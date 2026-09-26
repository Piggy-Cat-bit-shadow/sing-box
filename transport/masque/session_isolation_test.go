package masque

import (
	"context"
	"io"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

// Cross-session ownership.
//
// Two tunnels can be open at once, each with its own assigned addresses and its
// own advertised routes, and a packet's destination decides which one receives
// it. These tests pin the ownership rules directly, because the failure modes are
// silent: a packet delivered to the wrong tunnel is not an error anywhere, it is
// one client receiving another client's traffic.

// newTestServer builds a Server with the given tunnel prefix and advertised
// routes, without standing up a listener.
func newTestServer(t *testing.T, options ServerOptions) *Server {
	t.Helper()
	if options.Context == nil {
		options.Context = context.Background()
	}
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	server, err := NewServer(options)
	if err != nil {
		t.Fatalf("building the test server failed: %v", err)
	}
	return server
}

// discardStream satisfies io.ReadWriteCloser and swallows everything, so a
// test session can be built without a live tunnel.
type discardStream struct{}

func (discardStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (discardStream) Write(p []byte) (int, error) { return len(p), nil }
func (discardStream) Close() error                { return nil }

// noopSession builds a serverSession that owns the given addresses and routes
// and does nothing else, which is enough to exercise the ownership maps.
// noopSession builds a session through the REAL constructor.
//
// It must not assemble &session{} by hand: newSession is what installs the cancel
// function, and a hand-built session leaves it nil. That is not a theoretical
// concern - Server.Close calls cancel on every registered session, so a nil here
// panics inside Close. Going through the constructor keeps the test honest about
// the invariants production relies on.
func noopSession(server *Server, addresses []netip.Addr, peerRoutes []AddressRange) *serverSession {
	return &serverSession{
		session:    newSession(context.Background(), discardStream{}, &shutdownProbeHandler{}, func() int { return PacketHeadroom }),
		server:     server,
		ctx:        context.Background(),
		addresses:  addresses,
		peerRoutes: peerRoutes,
	}
}

// registerSession installs a session's ownership the same way a real tunnel
// establishment does, so the test exercises the real registration path and not
// a parallel one.
func registerSession(server *Server, current *serverSession) {
	server.access.Lock()
	for _, address := range current.addresses {
		server.addresses[address] = current
	}
	server.advertisements = append(server.advertisements, current)
	server.access.Unlock()
}

// TestLookupReturnsTheOwningSessionByAssignedAddress is the base ownership case.
//
// A packet addressed to an address the server ASSIGNED must go to the session
// that holds it, and to no other.
func TestLookupReturnsTheOwningSessionByAssignedAddress(t *testing.T) {
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")},
	})

	first := noopSession(server, []netip.Addr{netip.MustParseAddr("198.18.0.2")}, nil)
	second := noopSession(server, []netip.Addr{netip.MustParseAddr("198.18.0.3")}, nil)
	registerSession(server, first)
	registerSession(server, second)
	defer server.releaseSession(first)
	defer server.releaseSession(second)

	if got := server.lookup(netip.MustParseAddr("198.18.0.2"), 0); got != first {
		t.Fatalf("a packet for an address assigned to the first session was routed to "+
			"a different session (%p vs %p)", got, first)
	}
	if got := server.lookup(netip.MustParseAddr("198.18.0.3"), 0); got != second {
		t.Fatalf("a packet for an address assigned to the second session was routed to "+
			"a different session (%p vs %p)", got, second)
	}
}

// TestLookupNeverReturnsTheServersOwnAddress is the self-traffic guard.
//
// The server's own address inside the tunnel prefix is not owned by any session,
// and lookup() returns nil for it explicitly. If that guard were missing, the
// server's own address would fall through to the route-advertisement scan and be
// handed to whichever session advertised the covering route -- so a client could
// receive, and answer, traffic addressed to the server.
func TestLookupNeverReturnsTheServersOwnAddress(t *testing.T) {
	prefix := netip.MustParsePrefix("198.18.0.1/24")
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{prefix},
	})

	// A session that advertises the whole tunnel network, which is the widest a
	// client can legitimately be.
	current := noopSession(server, []netip.Addr{netip.MustParseAddr("198.18.0.2")}, []AddressRange{{
		Start:    netip.MustParseAddr("198.18.0.0"),
		End:      netip.MustParseAddr("198.18.0.255"),
		Protocol: 0,
	}})
	registerSession(server, current)
	defer server.releaseSession(current)

	ownAddress := prefix.Addr()
	if got := server.lookup(ownAddress, 0); got != nil {
		t.Fatalf("a packet addressed to the server's own address %s was routed to a "+
			"session; the server must keep its own address", ownAddress)
	}
	if server.Contains(ownAddress) {
		t.Fatalf("Contains must report the server's own address as not session-owned")
	}
}

// TestLookupPrefersTheAssignedAddressOverAnyAdvertisement pins precedence.
//
// An address the server actually ASSIGNED must win over a route another session
// merely ADVERTISED. Otherwise a session could claim a covering route and
// intercept traffic meant for an address the server handed to someone else,
// which is a straightforward cross-session traffic capture.
func TestLookupPrefersTheAssignedAddressOverAnyAdvertisement(t *testing.T) {
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")},
	})

	owner := noopSession(server, []netip.Addr{netip.MustParseAddr("198.18.0.5")}, nil)
	// The interloper advertises a route covering the owner's address.
	interloper := noopSession(server, []netip.Addr{netip.MustParseAddr("198.18.0.6")}, []AddressRange{{
		Start:    netip.MustParseAddr("198.18.0.0"),
		End:      netip.MustParseAddr("198.18.0.255"),
		Protocol: 0,
	}})
	registerSession(server, owner)
	// Registered SECOND, so a naive "last advertisement wins" ordering would
	// pick the interloper.
	registerSession(server, interloper)
	defer server.releaseSession(owner)
	defer server.releaseSession(interloper)

	if got := server.lookup(netip.MustParseAddr("198.18.0.5"), 0); got != owner {
		t.Fatalf("an address ASSIGNED to one session was claimed by another session's "+
			"route advertisement (%p vs %p): cross-session traffic capture", got, owner)
	}
}

// TestReleaseRemovesOnlyTheReleasingSessionsOwnership is the teardown case.
//
// A session that is closed must stop owning its addresses and must stop
// receiving routed traffic, while every other session is untouched.
func TestReleaseRemovesOnlyTheReleasingSessionsOwnership(t *testing.T) {
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")},
	})

	closing := noopSession(server, []netip.Addr{netip.MustParseAddr("198.18.0.2")}, []AddressRange{{
		Start: netip.MustParseAddr("198.18.0.0"), End: netip.MustParseAddr("198.18.0.255"),
	}})
	survivor := noopSession(server, []netip.Addr{netip.MustParseAddr("198.18.0.3")}, nil)
	registerSession(server, closing)
	registerSession(server, survivor)

	server.releaseSession(closing)

	if got := server.lookup(netip.MustParseAddr("198.18.0.2"), 0); got != nil {
		t.Fatalf("a released session still owns its address: %p", got)
	}
	if server.Contains(netip.MustParseAddr("198.18.0.2")) {
		t.Fatal("a released session still reports its address as owned")
	}
	// The survivor must be entirely unaffected, including its assignment.
	if got := server.lookup(netip.MustParseAddr("198.18.0.3"), 0); got != survivor {
		t.Fatalf("releasing one session disturbed another (%p vs %p)", got, survivor)
	}
	// The released session's advertisement must be gone too, so traffic for the
	// route it claimed is no longer delivered to a dead tunnel.
	server.access.RLock()
	remaining := len(server.advertisements)
	server.access.RUnlock()
	if remaining != 1 {
		t.Fatalf("expected 1 remaining advertisement after releasing one session, got %d", remaining)
	}
}

// TestReleaseCannotStealARecycledAddress is the address-reuse race.
//
// This is the subtle one. The pool hands a released address to the next client,
// so by the time a slow teardown runs, the address may already belong to a NEW
// session. releaseSession must therefore only delete an entry that still points
// at the session being released.
//
// Without that check, closing an old tunnel would delete the new tunnel's
// ownership entry, and the new client would silently stop receiving traffic on an
// address the server had just assigned it.
func TestReleaseCannotStealARecycledAddress(t *testing.T) {
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")},
	})

	address := netip.MustParseAddr("198.18.0.2")

	old := noopSession(server, []netip.Addr{address}, nil)
	registerSession(server, old)
	server.releaseSession(old)

	// The same address has now been recycled to a new session.
	replacement := noopSession(server, []netip.Addr{address}, nil)
	registerSession(server, replacement)

	// A late, repeated teardown of the OLD session must not remove the new
	// owner. This is reachable in practice: releaseSession is deferred, so it
	// runs after the address is already back in the pool.
	server.releaseSession(old)

	if got := server.lookup(address, 0); got != replacement {
		t.Fatalf("a late teardown of a closed session removed the ownership entry of the "+
			"session that now holds the recycled address %s (%p vs %p): the live client "+
			"stops receiving traffic with no error reported", address, got, replacement)
	}
	server.releaseSession(replacement)
}

// TestContainsTracksRouteAdvertisementsForUnownedAddresses covers the routing
// decision that does not go through an assigned address.
//
// A packet to a destination covered by a session's advertised route must be
// reported as owned, otherwise the packet is dropped as unroutable even though a
// tunnel offered to carry it.
func TestContainsTracksRouteAdvertisementsForUnownedAddresses(t *testing.T) {
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")},
	})

	current := noopSession(server, []netip.Addr{netip.MustParseAddr("198.18.0.2")}, []AddressRange{{
		Start:    netip.MustParseAddr("203.0.113.0"),
		End:      netip.MustParseAddr("203.0.113.255"),
		Protocol: 0,
	}})
	registerSession(server, current)
	defer server.releaseSession(current)

	if !server.Contains(netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("an address covered by a session's advertised route must be reported as owned")
	}
	if server.Contains(netip.MustParseAddr("203.0.114.9")) {
		t.Fatal("an address outside every advertised route must not be reported as owned")
	}
}

// TestRouteAdvertisementProtocolIsRespectedInLookup pins that the protocol
// number filters delivery.
//
// A session that advertised a route for TCP only (protocol 6) must not receive
// UDP traffic for that address, because it never offered to carry it.
func TestRouteAdvertisementProtocolIsRespectedInLookup(t *testing.T) {
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")},
	})

	tcpOnly := noopSession(server, []netip.Addr{netip.MustParseAddr("198.18.0.2")}, []AddressRange{{
		Start:    netip.MustParseAddr("203.0.113.0"),
		End:      netip.MustParseAddr("203.0.113.255"),
		Protocol: 6,
	}})
	registerSession(server, tcpOnly)
	defer server.releaseSession(tcpOnly)

	destination := netip.MustParseAddr("203.0.113.9")
	if got := server.lookup(destination, 6); got != tcpOnly {
		t.Fatalf("TCP traffic to an address advertised for protocol 6 must reach the "+
			"advertising session, got %p", got)
	}
	if got := server.lookup(destination, 17); got != nil {
		t.Fatalf("UDP traffic must not be delivered to a session that advertised the "+
			"address for TCP only, got %p", got)
	}
}
