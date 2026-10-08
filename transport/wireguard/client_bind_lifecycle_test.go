package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"

	"github.com/stretchr/testify/require"
)

// The bind's dial must be bounded, and a closed bind must end the receive loop.
//
// # The failure these pin
//
// The bind's socket is established lazily, on the first send or receive, while connAccess is
// held. That dial used to inherit only the bind context, which lives as long as the endpoint:
// a detour outbound whose path silently drops packets left the dial parked forever. Everything
// needing connAccess then queued behind it - sends, the bind's Close, every rebind - so one
// half-dead node froze the process's network machinery instead of failing one endpoint.
//
// The second half is what the frozen state did to shutdown. When the bind was closed while a
// dial was failing, receive returned a nil error, and wireguard-go's receive loop only exits on
// an error: it called straight back in, forever, at 100% of a core. The loop's deferred Done()
// is what a Close waits on, so the device could never finish stopping either.
func TestClientBindConnectDialIsBounded(t *testing.T) {
	restore := clientBindDialTimeout
	clientBindDialTimeout = 50 * time.Millisecond
	t.Cleanup(func() { clientBindDialTimeout = restore })

	dialer := newBlockingDialer()
	bind := newTestClientBind(t, dialer, true)
	_, _, err := bind.Open(0)
	require.NoError(t, err)

	start := time.Now()
	opened, err := bind.connect()
	require.Error(t, err, "a dial that never answers must fail, not park")
	require.Nil(t, opened)
	require.Less(t, time.Since(start), 2*time.Second,
		"the dial must be bounded by clientBindDialTimeout, not by the bind's lifetime")

	select {
	case <-dialer.entered:
	default:
		t.Fatal("the dialer was never asked to dial; the test proves nothing")
	}
}

// receive must report a closed bind as an error so wireguard-go's loop can exit.
func TestClientBindReceiveStopsOnClose(t *testing.T) {
	restore := clientBindDialTimeout
	clientBindDialTimeout = 20 * time.Millisecond
	t.Cleanup(func() { clientBindDialTimeout = restore })

	dialer := newBlockingDialer()
	bind := newTestClientBind(t, dialer, true)
	_, _, err := bind.Open(0)
	require.NoError(t, err)

	packets := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	endpoints := make([]conn.Endpoint, 1)

	// Close while the dial is in flight. The dial fails, and because the bind is closed the
	// receive must return an error rather than a nil that asks the caller to call back in.
	require.NoError(t, bind.Close())

	done := make(chan struct{})
	var receiveErr error
	go func() {
		defer close(done)
		_, receiveErr = bind.receive(packets, sizes, endpoints)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("receive did not return after the bind was closed; wireguard-go's receive loop " +
			"would call it again immediately and spin at 100% of a core")
	}
	require.ErrorIs(t, receiveErr, net.ErrClosed)
}

// The lock-free read of the bind conn must not race its writers.
//
// Open is wireguard-go's entry point and runs once, before any receive or send; what is
// concurrent is connect (which stores) against Close (which loads and closes) and against the
// fast-path load. This drives exactly that.
func TestClientBindConnAccessIsRaceFree(t *testing.T) {
	restore := clientBindDialTimeout
	clientBindDialTimeout = 20 * time.Millisecond
	t.Cleanup(func() { clientBindDialTimeout = restore })

	dialer := newBlockingDialer()
	bind := newTestClientBind(t, dialer, true)
	_, _, err := bind.Open(0)
	require.NoError(t, err)

	var waitGroup sync.WaitGroup
	waitGroup.Add(3)
	go func() {
		defer waitGroup.Done()
		for index := 0; index < 100; index++ {
			_, _ = bind.connect()
		}
	}()
	go func() {
		defer waitGroup.Done()
		for index := 0; index < 100; index++ {
			_ = bind.conn.Load()
		}
	}()
	go func() {
		defer waitGroup.Done()
		for index := 0; index < 100; index++ {
			_ = bind.Close()
		}
	}()
	waitGroup.Wait()
}

func newTestClientBind(t *testing.T, dialer N.Dialer, isConnect bool) *ClientBind {
	t.Helper()
	ctx := pause.WithDefaultManager(context.Background())
	return NewClientBind(ctx, log.NewNOPFactory().Logger(), dialer, isConnect, netip.MustParseAddrPort("192.0.2.1:51820"), [3]uint8{})
}

// blockingDialer never completes a dial on its own; it fails only when the dial context ends,
// which is the shape of a path that silently drops packets.
type blockingDialer struct {
	entered chan struct{}
	once    sync.Once
}

func newBlockingDialer() *blockingDialer {
	return &blockingDialer{entered: make(chan struct{})}
}

func (d *blockingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.once.Do(func() { close(d.entered) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (d *blockingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.once.Do(func() { close(d.entered) })
	<-ctx.Done()
	return nil, ctx.Err()
}
