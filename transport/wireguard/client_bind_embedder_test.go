package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"

	"github.com/stretchr/testify/require"
)

// The embedder contract of ClientBind: a construction error must fail an operation, never the
// process, and every lifecycle order must be answerable.
//
// # Why this is not defensive padding
//
// Every call below is reached from a goroutine the bind does not own. `connect()` is called by
// wireguard-go's receive loop and by its send path; wireguard-go's receive loop only exits on an
// error, and its deferred Done() is what a Close waits on. So a panic in either place is
// process-fatal rather than a failed call, and a nil error in the receive loop is a hot spin that
// also hangs Close. Both were real, and both are asserted here rather than assumed.

// A bind built without a dialer must fail closed, promptly, and without panicking.
func TestClientBindNilDialerFailsClosed(t *testing.T) {
	bind := NewClientBind(pauseContext(), log.NewNOPFactory().Logger(), nil, true,
		netip.MustParseAddrPort("192.0.2.1:51820"), [3]uint8{})

	// Open is the capability boundary: wireguard-go reaches it from its bind update, so an error
	// here fails the device's up transition and the endpoint's start.
	receiveFuncs, actualPort, err := bind.Open(0)
	require.ErrorIs(t, err, os.ErrInvalid,
		"a bind with no dialer must refuse to open rather than report a device that can never work")
	require.Nil(t, receiveFuncs)
	require.Zero(t, actualPort)

	opened, err := bind.connect()
	require.ErrorIs(t, err, os.ErrInvalid)
	require.Nil(t, opened)

	// Send must answer IMMEDIATELY. The retry path sleeps a second before reporting a failure, and a
	// permanent construction error must not add that second to every packet the device sends.
	start := time.Now()
	err = bind.Send([][]byte{make([]byte, 64)}, remoteEndpoint(netip.MustParseAddrPort("192.0.2.1:51820")), 0)
	require.ErrorIs(t, err, os.ErrInvalid)
	require.Less(t, time.Since(start), 500*time.Millisecond,
		"a permanent construction error must not be routed through the one-second retry")

	// The receive loop must not panic, and must not report success: a nil error asks wireguard-go to
	// call straight back in, which is the hot spin this bind was already fixed for.
	packets := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	endpoints := make([]conn.Endpoint, 1)
	require.NotPanics(t, func() {
		count, receiveErr := bind.receive(packets, sizes, endpoints)
		require.Zero(t, count)
		require.NoError(t, receiveErr,
			"the retry path reports nil to ask for another attempt; what must not happen is a panic")
	})

	// Once closed, the same path has to end the loop with an error.
	require.NoError(t, bind.Close())
	require.NotPanics(t, func() {
		_, receiveErr := bind.receive(packets, sizes, endpoints)
		require.ErrorIs(t, receiveErr, net.ErrClosed,
			"a closed bind must end the receive loop with an error, not a nil the caller acts on")
	})
}

// Send before Open must work rather than panic.
//
// The dial context used to be derived in Open, so a send that arrived first derived it from a nil
// parent - `context.WithTimeout(nil, ...)` panics, on the device's encryption goroutine.
func TestClientBindSendBeforeOpen(t *testing.T) {
	far, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer far.Close()

	dialer := newSocketDialer(t, far.LocalAddr().(*net.UDPAddr))
	bind := newSocketBind(t, dialer, true)
	destination := remoteEndpoint(netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 1}), 51820))

	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	require.NotPanics(t, func() {
		require.NoError(t, bind.Send([][]byte{payload}, destination, 0),
			"a send before Open must dial, not panic on a nil bind context")
	})
	require.Equal(t, 1, dialer.dialCount())

	received := make([]byte, 64)
	far.SetReadDeadline(time.Now().Add(2 * time.Second))
	count, _, err := far.ReadFromUDP(received)
	require.NoError(t, err)
	require.Equal(t, payload, received[:count])

	// And Open afterwards is not confused by the connection that already exists.
	_, _, err = bind.Open(0)
	require.NoError(t, err)
	require.NoError(t, bind.Send([][]byte{payload}, destination, 0))
	require.Equal(t, 1, dialer.dialCount(), "the established connection must be reused, not re-dialled")
	require.NoError(t, bind.Close())
}

// Every lifecycle order an embedder can reach must be answerable: close before open, open after
// close, close twice, open twice.
func TestClientBindLifecycleOrders(t *testing.T) {
	dialer := newSocketDialer(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820})
	bind := newSocketBind(t, dialer, true)
	destination := remoteEndpoint(netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 1}), 51820))
	payload := []byte{0x10, 0x11, 0x12, 0x13}

	// Close before Open: legal, and leaves the bind closed.
	require.NoError(t, bind.Close())
	require.NoError(t, bind.Close(), "Close must stay idempotent")
	_, err := bind.connect()
	require.ErrorIs(t, err, net.ErrClosed, "a closed bind that was never opened must refuse a dial")

	// Open after Close: this is what every rebind and every down/up transition does, so a closed
	// bind must be restartable rather than permanently spent.
	_, _, err = bind.Open(0)
	require.NoError(t, err)
	require.NoError(t, bind.Send([][]byte{payload}, destination, 0))

	// Open again without a Close: a further run on the same bind.
	_, _, err = bind.Open(0)
	require.NoError(t, err)
	require.NoError(t, bind.Send([][]byte{payload}, destination, 0))

	// Close, then Open, then Close.
	require.NoError(t, bind.Close())
	require.NoError(t, bind.Close())
	_, _, err = bind.Open(0)
	require.NoError(t, err)
	require.NoError(t, bind.Close())
	require.NoError(t, bind.Close())

	_, err = bind.connect()
	require.ErrorIs(t, err, net.ErrClosed, "the bind must end closed")
}

// A failed dial must not poison the bind: the next Open must be able to establish a socket.
func TestClientBindRestartsAfterAFailedDial(t *testing.T) {
	far, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer far.Close()

	dialer := newSocketDialer(t, far.LocalAddr().(*net.UDPAddr))
	dialer.failDials(1)
	bind := newSocketBind(t, dialer, true)
	destination := remoteEndpoint(netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 1}), 51820))

	_, _, err = bind.Open(0)
	require.NoError(t, err)
	_, err = bind.connect()
	require.Error(t, err, "the injected dial failure must reach the caller")
	require.ErrorIs(t, err, errDialRefused)

	// The bind is not spent: Open starts a new run and the next dial succeeds.
	_, _, err = bind.Open(0)
	require.NoError(t, err)
	require.NoError(t, bind.Send([][]byte{[]byte{0x20, 0x21, 0x22, 0x23}}, destination, 0))
	require.Equal(t, 2, dialer.dialCount())
	require.NoError(t, bind.Close())
}

// A context without a pause manager is a legal embedder configuration, not a nil dereference.
func TestClientBindWithoutAPauseManager(t *testing.T) {
	ctx := context.Background()
	require.Nil(t, pauseManagerOf(ctx), "this test is only meaningful without a pause manager installed")

	dialer := newSocketDialer(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820})
	dialer.failDials(1)
	bind := NewClientBind(ctx, log.NewNOPFactory().Logger(), dialer, true,
		netip.MustParseAddrPort("192.0.2.1:51820"), [3]uint8{})
	_, _, err := bind.Open(0)
	require.NoError(t, err)

	destination := remoteEndpoint(netip.MustParseAddrPort("192.0.2.1:51820"))
	require.NotPanics(t, func() {
		sendErr := bind.Send([][]byte{make([]byte, 64)}, destination, 0)
		require.ErrorIs(t, sendErr, errDialRefused,
			"the dial failure must be reported; a missing pause manager must not change it")
	})

	packets := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	endpoints := make([]conn.Endpoint, 1)
	require.NoError(t, bind.Close())
	require.NotPanics(t, func() {
		_, receiveErr := bind.receive(packets, sizes, endpoints)
		require.ErrorIs(t, receiveErr, net.ErrClosed)
	})
}

// A logger is optional in the same way: the error paths must not dereference a nil one.
func TestClientBindWithoutALogger(t *testing.T) {
	dialer := newSocketDialer(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820})
	dialer.failDials(1)
	bind := NewClientBind(pauseContext(), nil, dialer, true,
		netip.MustParseAddrPort("192.0.2.1:51820"), [3]uint8{})
	_, _, err := bind.Open(0)
	require.NoError(t, err)

	packets := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	endpoints := make([]conn.Endpoint, 1)
	require.NotPanics(t, func() {
		_, _ = bind.receive(packets, sizes, endpoints)
	})
	require.NoError(t, bind.Close())
}

// Send must honour the offset AND the per-endpoint reserved value, measured on the wire.
//
// # What is being pinned
//
// The buffer the device hands over has `offset` bytes of headroom in front of the packet, and the
// reserved bytes belong to positions 1..3 OF THE PACKET, not of the buffer. Writing them at the
// buffer's start would corrupt the headroom and leave the packet's reserved field untouched; slicing
// without the offset would send the headroom as payload.
func TestClientBindSendHonoursOffsetAndReserved(t *testing.T) {
	far, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer far.Close()

	dialer := newSocketDialer(t, far.LocalAddr().(*net.UDPAddr))
	bind := newSocketBind(t, dialer, true)
	_, _, err = bind.Open(0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = bind.Close() })

	const offset = 16
	registered := netip.MustParseAddrPort("198.51.100.7:51820")
	defaultReserved := [3]uint8{0xAA, 0xBB, 0xCC}
	perEndpointReserved := [3]uint8{0x0D, 0x0E, 0x0F}
	bind.reserved = defaultReserved
	bind.SetReservedForEndpoint(registered, perEndpointReserved)

	// The headroom is filled with a marker so its presence in the output is unambiguous.
	buffer := make([]byte, offset+8)
	for index := range buffer {
		buffer[index] = 0xF0
	}
	copy(buffer[offset:], []byte{0x01, 0x00, 0x00, 0x00, 0x05, 0x06, 0x07, 0x08})

	require.NoError(t, bind.Send([][]byte{buffer}, remoteEndpoint(registered), offset))

	received := make([]byte, 128)
	far.SetReadDeadline(time.Now().Add(2 * time.Second))
	count, _, err := far.ReadFromUDP(received)
	require.NoError(t, err)
	require.Equal(t, 8, count, "the headroom must not be sent as payload")

	sent := received[:count]
	require.Equal(t, buffer[offset:], sent, "exactly the packet, with no headroom")
	require.Equal(t, perEndpointReserved[:], sent[1:4],
		"the reserved value registered for this destination must be at packet positions 1..3")

	// A destination with no registration uses the bind-wide reserved value.
	bind.SetReservedForEndpoint(registered, [3]uint8{})
	other := netip.MustParseAddrPort("198.51.100.8:51820")
	require.NoError(t, bind.Send([][]byte{append([]byte{}, buffer...)}, remoteEndpoint(other), offset))
	far.SetReadDeadline(time.Now().Add(2 * time.Second))
	count, _, err = far.ReadFromUDP(received)
	require.NoError(t, err)
	require.Equal(t, defaultReserved[:], received[1:4],
		"an unregistered destination must fall back to the bind's own reserved value")
}

// A write failure must retire the connection, so the next send establishes a new one.
//
// The failure mode this prevents: a socket that failed once is reused for every subsequent packet,
// so every send fails on it and the tunnel never recovers even though the path came back.
func TestClientBindRecyclesConnectionAfterAWriteFailure(t *testing.T) {
	far, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer far.Close()

	dialer := newSocketDialer(t, far.LocalAddr().(*net.UDPAddr))
	bind := newSocketBind(t, dialer, true)
	_, _, err = bind.Open(0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = bind.Close() })

	destination := remoteEndpoint(netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 1}), 51820))
	require.NoError(t, bind.Send([][]byte{[]byte{0x30, 0x31, 0x32, 0x33}}, destination, 0))
	require.Equal(t, 1, dialer.dialCount())

	// Break the established socket underneath the bind.
	require.NoError(t, dialer.closeLastConn())
	sendErr := bind.Send([][]byte{[]byte{0x30, 0x31, 0x32, 0x33}}, destination, 0)
	require.Error(t, sendErr, "a write on a closed socket must be reported")

	// The next send must establish a new connection rather than write into the dead one.
	require.NoError(t, bind.Send([][]byte{[]byte{0x40, 0x41, 0x42, 0x43}}, destination, 0))
	require.Equal(t, 2, dialer.dialCount(),
		"a connection that failed a write must be retired, not reused for every later packet")
}

// errDialRefused is the injected failure of the fixture dialers.
var errDialRefused = errors.New("wireguard test: dial refused")

// pauseContext installs the default pause manager, which is what a box does.
func pauseContext() context.Context {
	return pause.WithDefaultManager(context.Background())
}

// pauseManagerOf reads the pause manager out of a context the way the bind does.
func pauseManagerOf(ctx context.Context) pause.Manager {
	return service.FromContext[pause.Manager](ctx)
}

// socketDialer hands out real UDP sockets pointed at one far end, and counts every dial so the
// bind's recycling behaviour is observable.
type socketDialer struct {
	far         *net.UDPAddr
	access      sync.Mutex
	dials       int
	failures    int
	lastConn    net.Conn
	lastPacket  net.PacketConn
	failureOnce error
}

func newSocketDialer(t *testing.T, far *net.UDPAddr) *socketDialer {
	t.Helper()
	return &socketDialer{far: far, failureOnce: errDialRefused}
}

func (d *socketDialer) failDials(count int) {
	d.access.Lock()
	d.failures = count
	d.access.Unlock()
}

func (d *socketDialer) dialCount() int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.dials
}

func (d *socketDialer) closeLastConn() error {
	d.access.Lock()
	defer d.access.Unlock()
	if d.lastConn == nil {
		return os.ErrInvalid
	}
	return d.lastConn.Close()
}

func (d *socketDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.dials++
	failing := d.failures > 0
	if failing {
		d.failures--
	}
	d.access.Unlock()
	if failing {
		return nil, d.failureOnce
	}
	var netDialer net.Dialer
	socket, err := netDialer.DialContext(ctx, N.NetworkUDP, d.far.String())
	if err != nil {
		return nil, err
	}
	d.access.Lock()
	d.lastConn = socket
	d.access.Unlock()
	return socket, nil
}

func (d *socketDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.access.Lock()
	d.dials++
	failing := d.failures > 0
	if failing {
		d.failures--
	}
	d.access.Unlock()
	if failing {
		return nil, d.failureOnce
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	d.access.Lock()
	d.lastPacket = socket
	d.access.Unlock()
	return socket, nil
}

func newSocketBind(t *testing.T, dialer N.Dialer, isConnect bool) *ClientBind {
	t.Helper()
	bind := NewClientBind(pauseContext(), log.NewNOPFactory().Logger(), dialer, isConnect,
		netip.MustParseAddrPort("192.0.2.1:51820"), [3]uint8{})
	t.Cleanup(func() { _ = bind.Close() })
	return bind
}
