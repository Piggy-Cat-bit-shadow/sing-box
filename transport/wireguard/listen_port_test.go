package wireguard

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// A configured `listen_port` must own a REAL UDP port, and a port that cannot be owned must fail the
// start.
//
// # Why every assertion here is a socket operation
//
// `listen_port` is written into the device's IPC configuration, and reading that text back proves
// nothing: the device records the port it was ASKED for whether or not a socket was ever opened for
// it. The only honest question is whether another process can bind the port, so that is what these
// tests ask, with their own independent socket. A test that asserted `options.ListenPort != 0`, or
// that the IPC text contains `listen_port=`, would pass on the broken code.
//
// # What the broken code did
//
// wireguard-go opens the bind from the UP transition, and the UP transition here arrives on the tun
// device's event channel - an asynchronous goroutine. `IpcSet` was reached first, so its
// `listen_port` handler called `BindUpdate` on a device that was not up yet, which returns without
// opening anything. Start then returned successfully while the socket did not exist yet, and when
// the port was already taken by another process the resulting bind failure was logged inside that
// goroutine and never reached the caller: the endpoint was published as ready, with no socket.

// The port is occupied the moment Start returns, and a second bind on it is refused.
func TestListenPortIsBoundAndRefusedToOthers(t *testing.T) {
	port := freeUDPPort(t)
	require.True(t, udpPortIsFree(t, port), "the port must start free; the test proves nothing otherwise")

	endpoint := newListenPortEndpoint(t, port)
	require.NoError(t, endpoint.Initialize(nil))
	require.NoError(t, endpoint.Start(false))
	t.Cleanup(func() { _ = endpoint.Close() })

	// No sleep, no retry: the bind is part of Start's contract, so it must already have happened.
	require.False(t, udpPortIsFree(t, port),
		"listen_port=%d was configured but the port is still free after Start: nothing bound it", port)

	// The refusal is asserted as a refusal, not merely as "not free": a real independent bind has to
	// come back with the same address-in-use error this machine produces for any other double bind.
	// The reference is MEASURED here rather than hard-coded, because the errno table is not portable
	// (Go's syscall.EADDRINUSE is not WSAEADDRINUSE on Windows).
	referenceErrno := udpBindConflictErrno(t)
	_, err := net.ListenPacket("udp4", "0.0.0.0:"+strconv.Itoa(int(port)))
	require.Error(t, err, "a second bind on the configured port must be refused")
	require.Equal(t, referenceErrno, socketErrno(t, err),
		"the refusal must be address-in-use, not an unrelated failure: %v", err)
}

// udpBindConflictErrno measures the errno this machine reports for a double bind, so the assertion
// above compares against a fact rather than against a platform guess.
func udpBindConflictErrno(t *testing.T) syscall.Errno {
	t.Helper()
	holder, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer holder.Close()
	_, conflictErr := net.ListenPacket("udp4", holder.LocalAddr().String())
	require.Error(t, conflictErr, "the reference double bind must conflict; without it this test proves nothing")
	return socketErrno(t, conflictErr)
}

// socketErrno extracts the errno a bind failure carries.
func socketErrno(t *testing.T, err error) syscall.Errno {
	t.Helper()
	var errno syscall.Errno
	require.ErrorAs(t, err, &errno, "a bind failure must carry a socket errno: %v", err)
	return errno
}

// The port is released by Close, so the endpoint does not hold it after teardown.
func TestListenPortIsReleasedByClose(t *testing.T) {
	port := freeUDPPort(t)

	endpoint := newListenPortEndpoint(t, port)
	require.NoError(t, endpoint.Initialize(nil))
	require.NoError(t, endpoint.Start(false))
	require.False(t, udpPortIsFree(t, port), "the endpoint must hold the port before Close")

	require.NoError(t, endpoint.Close())
	require.True(t, udpPortIsFree(t, port),
		"Close must release listen_port=%d: a stopped endpoint that keeps the port blocks its own restart", port)
}

// A port that is already taken fails the start; it is not swallowed.
func TestOccupiedListenPortFailsClosed(t *testing.T) {
	holder, err := net.ListenPacket("udp4", "0.0.0.0:0")
	require.NoError(t, err)
	port := uint16(holder.LocalAddr().(*net.UDPAddr).Port)

	endpoint := newListenPortEndpoint(t, port)
	require.NoError(t, endpoint.Initialize(nil))

	startErr := endpoint.Start(false)
	require.Error(t, startErr,
		"a listen_port that another process already holds must fail the start, not be reported as success")
	require.Nil(t, endpoint.device.Load(),
		"a failed start must not publish a device: the endpoint would be reachable but have no socket")
	t.Cleanup(func() { _ = endpoint.Close() })

	// No socket was left behind on the port by the failed attempt.
	require.NoError(t, holder.Close())
	require.True(t, udpPortIsFree(t, port),
		"the failed start must not leave a socket on the port it could not bind")
}

// Close then Start on the same endpoint refuses, and the port is left free for whoever starts next.
//
// The refusal is the point: the endpoint's tun device publishes the close of its event channel, so a
// second Start cannot resurrect a torn-down device. What must NOT happen is a Start that reports
// success while the port belongs to a device that was already closed.
func TestStartAfterCloseIsRefusedAndLeavesThePortFree(t *testing.T) {
	port := freeUDPPort(t)

	endpoint := newListenPortEndpoint(t, port)
	require.NoError(t, endpoint.Initialize(nil))
	require.NoError(t, endpoint.Start(false))
	require.NoError(t, endpoint.Close())

	startErr := endpoint.Start(false)
	require.Error(t, startErr, "a second Start after Close must be refused")
	require.True(t, udpPortIsFree(t, port),
		"the refused start must not have bound listen_port=%d", port)

	// The rule survives the restart: a fresh endpoint on the same pinned port binds it.
	restarted := newListenPortEndpoint(t, port)
	require.NoError(t, restarted.Initialize(nil))
	require.NoError(t, restarted.Start(false))
	t.Cleanup(func() { _ = restarted.Close() })
	require.False(t, udpPortIsFree(t, port),
		"a fresh endpoint on the same listen_port must bind it, and the refused start must not have poisoned it")
}

// listen_port = 0 asks the kernel for a port; the endpoint must report the one it actually got, and
// that port must be the one it holds.
func TestDynamicListenPortReportsTheRealPort(t *testing.T) {
	endpoint := newListenPortEndpoint(t, 0)
	require.NoError(t, endpoint.Initialize(nil))
	require.NoError(t, endpoint.Start(false))
	t.Cleanup(func() { _ = endpoint.Close() })

	wgDevice := endpoint.device.Load()
	require.NotNil(t, wgDevice)
	actualPort := endpoint.currentListenPort(wgDevice)
	require.NotZero(t, actualPort,
		"a dynamically allocated port must be reportable: 0 here would mean the device never bound anything")

	require.False(t, udpPortIsFree(t, actualPort),
		"the reported port %d must be the port the endpoint actually holds", actualPort)
}

// A pinned port is held on both families, because that is how the bind opens it.
//
// The standard bind opens udp4 and udp6 on the same port. Reporting the v6 half matters: an endpoint
// that bound only v4 would look healthy while every peer reaching it over IPv6 failed, and the
// asymmetry is invisible from the v4 probe alone.
func TestListenPortIsHeldOnBothFamilies(t *testing.T) {
	if !ipv6Available(t) {
		t.Fatal("this machine cannot bind a udp6 socket at all, so the dual-stack claim cannot be " +
			"tested here; the v4 half is covered by TestListenPortIsBoundAndRefusedToOthers")
	}
	port := freeUDPPort(t)

	endpoint := newListenPortEndpoint(t, port)
	require.NoError(t, endpoint.Initialize(nil))
	require.NoError(t, endpoint.Start(false))
	t.Cleanup(func() { _ = endpoint.Close() })

	v4Listener, v4Err := net.ListenPacket("udp4", "0.0.0.0:"+strconv.Itoa(int(port)))
	if v4Err == nil {
		_ = v4Listener.Close()
	}
	require.Error(t, v4Err, "the IPv4 half of listen_port=%d must be held", port)

	v6Listener, v6Err := net.ListenPacket("udp6", "[::]:"+strconv.Itoa(int(port)))
	if v6Err == nil {
		_ = v6Listener.Close()
	}
	require.Error(t, v6Err,
		"the IPv6 half of listen_port=%d must be held as well, or peers reaching this endpoint over "+
			"IPv6 are silently unable to connect", port)
}

// A dialer that cannot own a listening socket is refused when a listening port was asked for.
//
// # Why this is a refusal and not a fallback
//
// `listen_port` is a request for a socket other hosts can reach. The bind that a detour uses
// (ClientBind) has no local port of its own: it dials out and receives on the authenticated socket,
// and its Open deliberately reports 0 rather than pretending to bind a port the detour owns. Opening
// a listener anyway would put a socket on a path the operator did not choose, bypassing the detour,
// the bind_interface and the routing mark - so the honest answer is a failure.
//
// The in-tree route to this combination is already refused at construction (`listen_port` conflicts
// with `detour`, see protocol/wireguard), which is why this test drives the bind capability
// boundary directly: it is the case an EMBEDDER reaches by passing a non-listening dialer.
func TestListenPortWithoutAListeningDialerFailsClosed(t *testing.T) {
	port := freeUDPPort(t)
	ctx := pause.WithDefaultManager(context.Background())

	endpoint, err := NewEndpoint(EndpointOptions{
		Context:    ctx,
		Logger:     log.NewNOPFactory().Logger(),
		Dialer:     &plainDialer{},
		MTU:        1420,
		Address:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		PrivateKey: testPrivateKey,
		ListenPort: port,
		Peers: []PeerOptions{{
			Endpoint:   M.ParseSocksaddrHostPort("127.0.0.1", 51820),
			PublicKey:  testListenPeerPublicKey,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
	})
	require.NoError(t, err)
	require.NoError(t, endpoint.Initialize(nil))
	t.Cleanup(func() { _ = endpoint.Close() })

	startErr := endpoint.Start(false)
	require.Error(t, startErr,
		"a configured listen_port that the dialer cannot own must fail the start")
	require.ErrorContains(t, startErr, "listen_port")
	require.True(t, udpPortIsFree(t, port),
		"the refused endpoint must not hold the port it could not bind")
}

// The same dialer with NO configured port is the legitimate detour case, and must still start.
//
// This is the negative control for the test above: it separates "the dialer is unusable" from "a
// listening port was asked of a dialer that has none". It is also the check that the failure above
// was not implemented by opening a listener on a path that has no business owning one.
func TestNoListenPortWithANonListeningDialerStarts(t *testing.T) {
	ctx := pause.WithDefaultManager(context.Background())

	endpoint, err := NewEndpoint(EndpointOptions{
		Context:    ctx,
		Logger:     log.NewNOPFactory().Logger(),
		Dialer:     &plainDialer{},
		MTU:        1420,
		Address:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		PrivateKey: testPrivateKey,
		Peers: []PeerOptions{{
			Endpoint:   M.ParseSocksaddrHostPort("127.0.0.1", 51820),
			PublicKey:  testListenPeerPublicKey,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
	})
	require.NoError(t, err)
	require.NoError(t, endpoint.Initialize(nil))
	require.NoError(t, endpoint.Start(false),
		"a detour-shaped endpoint without listen_port must keep working exactly as before")
	t.Cleanup(func() { _ = endpoint.Close() })
	require.NotNil(t, endpoint.device.Load())
}

// A rebind must not move a pinned port: recovery may reopen the socket, but it may not silently
// change the port the operator configured.
func TestPinnedPortSurvivesARebind(t *testing.T) {
	port := freeUDPPort(t)

	endpoint := newListenPortEndpoint(t, port)
	require.NoError(t, endpoint.Initialize(nil))
	require.NoError(t, endpoint.Start(false))
	t.Cleanup(func() { _ = endpoint.Close() })

	wgDevice := endpoint.device.Load()
	require.NotNil(t, wgDevice)
	require.NoError(t, wgDevice.BindUpdate(), "a rebind on a pinned port must succeed")
	require.EqualValues(t, port, endpoint.currentListenPort(wgDevice),
		"a rebind must keep the configured port")
	require.False(t, udpPortIsFree(t, port), "the port must be held again after the rebind")

	// And the endpoint is still functional afterwards, not merely holding a port.
	require.NoError(t, endpoint.BindUpdate())
}

// A failed start must not leak a socket, so the port is immediately available to the next attempt.
func TestFailedStartLeavesNoSocket(t *testing.T) {
	holder, err := net.ListenPacket("udp4", "0.0.0.0:0")
	require.NoError(t, err)
	port := uint16(holder.LocalAddr().(*net.UDPAddr).Port)

	failed := newListenPortEndpoint(t, port)
	require.NoError(t, failed.Initialize(nil))
	require.Error(t, failed.Start(false))
	require.NoError(t, failed.Close())

	require.NoError(t, holder.Close())

	second := newListenPortEndpoint(t, port)
	require.NoError(t, second.Initialize(nil))
	require.NoError(t, second.Start(false), "the port must be free again after the failed start")
	t.Cleanup(func() { _ = second.Close() })
	require.False(t, udpPortIsFree(t, port))
}

// A start that loses the race with Close must not leave the port bound behind a closed endpoint.
//
// Box.Close is legal at any point of Box.Start, so this drives the two concurrently. The contract is
// not "Start always succeeds": it is that the endpoint never ends up closed while holding a socket.
func TestStartRacingCloseDoesNotStrandThePort(t *testing.T) {
	port := freeUDPPort(t)

	endpoint := newListenPortEndpoint(t, port)
	require.NoError(t, endpoint.Initialize(nil))

	startDone := make(chan error, 1)
	go func() {
		startDone <- endpoint.Start(false)
	}()
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- endpoint.Close()
	}()

	select {
	case <-startDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return")
	}
	select {
	case <-closeDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return")
	}
	require.True(t, udpPortIsFree(t, port),
		"after a start/close race the endpoint must not hold listen_port=%d", port)
}

// An endpoint built without a dialer fails its start instead of panicking later.
func TestEndpointWithoutADialerFailsClosed(t *testing.T) {
	ctx := pause.WithDefaultManager(context.Background())
	endpoint, err := NewEndpoint(EndpointOptions{
		Context:    ctx,
		Logger:     log.NewNOPFactory().Logger(),
		MTU:        1420,
		Address:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		PrivateKey: testPrivateKey,
		Peers: []PeerOptions{{
			Endpoint:   M.ParseSocksaddrHostPort("127.0.0.1", 51820),
			PublicKey:  testListenPeerPublicKey,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = endpoint.Close() })

	require.NotPanics(t, func() {
		require.NoError(t, endpoint.Initialize(nil))
		startErr := endpoint.Start(false)
		require.Error(t, startErr,
			"an endpoint with no dialer cannot reach the network; its start must fail, not succeed")
		require.ErrorContains(t, startErr, "dialer")
	})
}

// freeUDPPort asks the kernel for an unused port and releases it.
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(listener.LocalAddr().(*net.UDPAddr).Port)
	require.NoError(t, listener.Close())
	return port
}

// udpPortIsFree reports whether an independent bind on the wildcard succeeds.
//
// The wildcard is the address the standard WireGuard bind uses (":port"), so a successful bind here
// means the endpoint holds nothing on that port for any local address.
func udpPortIsFree(t *testing.T, port uint16) bool {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "0.0.0.0:"+strconv.Itoa(int(port)))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

// ipv6Available reports whether this machine can bind an IPv6 socket at all.
//
// It is asked by binding one, so the answer is evidence rather than a platform guess.
func ipv6Available(t *testing.T) bool {
	t.Helper()
	listener, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

// testListenPeerPublicKey is base64 of the bytes 0xc8..0xa9: a 32-byte WireGuard public key for the
// peer half of the fixtures below. Public test material, never used for a real tunnel.
const testListenPeerPublicKey = "yMfGxcTDwsHAv769vLu6ubi3trW0s7KxsK+urayrqqk="

// newListenPortEndpoint builds the endpoint the way a real configuration does: the dialer is the
// production DefaultDialer the outbound builds, the peer is an IP literal, and no detour is set.
func newListenPortEndpoint(t *testing.T, port uint16) *Endpoint {
	t.Helper()
	ctx := pause.WithDefaultManager(context.Background())
	outboundDialer, err := dialer.NewDefault(ctx, option.DialerOptions{})
	require.NoError(t, err)

	endpoint, err := NewEndpoint(EndpointOptions{
		Context:    ctx,
		Logger:     log.NewNOPFactory().Logger(),
		Dialer:     outboundDialer,
		MTU:        1420,
		Address:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		PrivateKey: testPrivateKey,
		ListenPort: port,
		Peers: []PeerOptions{{
			Endpoint:   M.ParseSocksaddrHostPort("127.0.0.1", 51820),
			PublicKey:  testListenPeerPublicKey,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
	})
	require.NoError(t, err)
	return endpoint
}

// plainDialer is a working dialer that is NOT a dialer.UDPListener: it can dial and it can open a
// socket, but it has no listener control to hand to the standard bind, which is exactly the
// capability shape a detour outbound has.
type plainDialer struct{}

func (d *plainDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var netDialer net.Dialer
	return netDialer.DialContext(ctx, network, destination.String())
}

func (d *plainDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	var listenConfig net.ListenConfig
	return listenConfig.ListenPacket(ctx, N.NetworkUDP, "0.0.0.0:0")
}
