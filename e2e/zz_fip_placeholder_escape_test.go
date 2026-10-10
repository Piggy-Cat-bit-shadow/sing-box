package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// ===========================================================================
// FIP-01: a synthetic address this Box issued must never escape to a peer
// ===========================================================================
//
// # The defect
//
// `Router.prepareMatchMetadata` (route/route.go:1051) unmaps a destination back to its domain only
// when the CURRENTLY configured range contains it:
//
//	if metadata.Destination.Addr.IsValid() && r.dnsTransport.FakeIP() != nil &&
//	        r.dnsTransport.FakeIP().Store().Contains(metadata.Destination.Addr) {
//	        domain, loaded := r.dnsTransport.FakeIP().Store().Lookup(metadata.Destination.Addr)
//	        if !loaded { return E.New("missing fakeip record, ...") }
//
// Both halves of that condition are statements about the CURRENT generation. An address the Box
// itself handed to a client does not stop being a placeholder when the range moves or the fakeip
// server is removed - it stops being RECOGNISED, which is a different thing. The client still holds
// it, still dials it, and the box forwards it as an ordinary literal.
//
// # Where the address comes from, and why a client really holds one
//
// A FakeIP address is not minted by the client. It is the answer the box's OWN dns server gives to an
// A query, with `C.DefaultDNSTTL` as its lifetime, so a client that resolved a name before the
// configuration changed can keep dialling the answer it was given. The stand below produces the
// address exactly the way a device does: through the product's own DNS hijack entry point.
//
// # Why every observation is taken at the peer
//
// The peer is a real SOCKS5 server that records the target of every CONNECT it is asked for - the
// value AND the ATYP byte it arrived with - so "the peer received the domain" and "the peer received
// the synthetic literal" are wire facts rather than log lines.
//
// # The positive control is load bearing
//
// On the host this was measured on, `198.18.0.0/15` is LIVE ROUTED ADDRESS SPACE: an active `tun0`
// interface answers every query - a real name and an NXDOMAIN alike - with an address in that range,
// and those addresses connect. So "refuse the whole range" would break real traffic on a real
// machine. `TestFIPLiteralWithoutIssuanceStaysReachable` is the row that fails if anyone tries it.
// Every hop below is TOLD what to dial, so no test depends on - or accidentally reaches - the
// machine's real routing.

// ---------------------------------------------------------------------------
// The ranges the stand uses
// ---------------------------------------------------------------------------

const (
	// fipRangeCurrent is the generation-1 range, and the default in most rows. It is a /16 so that the
	// moved range below can be genuinely DISJOINT from it: `/15` neighbours overlap, and an overlapping
	// fixture would make "the new range does not contain the issued address" unsatisfiable.
	fipRangeCurrent = "198.18.0.0/16"
	// fipRangeMoved is the generation-2 range: it contains none of generation 1's addresses.
	fipRangeMoved = "198.20.0.0/16"
	// fipRangeCustom is a range that contains none of the addresses above.
	fipRangeCustom = "10.7.0.0/16"
	// fipRangeV6 is the IPv6 range row.
	fipRangeV6 = "fdfe:dcba:9876::/64"
)

// ---------------------------------------------------------------------------
// The peer: a real SOCKS5 server that records what it was asked for
// ---------------------------------------------------------------------------

// fipPeerSink is a real SOCKS5 server that records the target of every CONNECT it is asked for, and
// never dials the address it was given.
//
// # Why it refuses to dial the requested target
//
// `198.18.0.0/15` is routed on the development host, so a hop that dialled a synthetic literal would
// leave the machine and reach something real - the test would then be producing the leak it is
// measuring. Every request is instead carried to a loopback echo server. That choice also makes the
// recording MORE useful: a flow that puts a placeholder on the wire COMPLETES, so the recording is
// read from a finished flow rather than from a connection error.
type fipPeerSink struct {
	listener net.Listener
	backend  string

	mu       sync.Mutex
	requests []socksRequest
	accepts  int
}

func startFIPPeerSink(t *testing.T, backend string) *fipPeerSink {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	sink := &fipPeerSink{listener: listener, backend: backend}
	go sink.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return sink
}

func (s *fipPeerSink) address() string { return s.listener.Addr().String() }

func (s *fipPeerSink) acceptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepts
}

func (s *fipPeerSink) seen() []socksRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]socksRequest(nil), s.requests...)
}

func (s *fipPeerSink) mark() int { return len(s.seen()) }

// since returns the requests recorded after a mark taken with mark(), so a row can assert on the
// request IT caused rather than on a position in a list shared with earlier rows.
func (s *fipPeerSink) since(mark int) []socksRequest {
	all := s.seen()
	if mark >= len(all) {
		return nil
	}
	return all[mark:]
}

// awaitSince gives an in-flight request a bounded window to arrive, so "the peer was never asked" is
// measured after the flow has had its chance rather than before.
func (s *fipPeerSink) awaitSince(mark int, window time.Duration) []socksRequest {
	deadline := time.Now().Add(window)
	for {
		added := s.since(mark)
		if len(added) > 0 || time.Now().After(deadline) {
			return added
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (s *fipPeerSink) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.accepts++
		s.mu.Unlock()
		go s.handle(conn)
	}
}

func (s *fipPeerSink) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, int(greeting[1]))); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	if head[1] != 0x01 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	target, err := readSocksTarget(conn, head[3])
	if err != nil {
		return
	}
	// Recorded BEFORE anything is dialled, so the request exists even if the carry fails. This is the
	// wire fact every assertion below reads.
	s.mu.Lock()
	s.requests = append(s.requests, socksRequest{AddressType: head[3], Host: target.host(), Port: target.port})
	s.mu.Unlock()

	upstream, err := net.DialTimeout("tcp", s.backend, 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := conn.Write(buildSOCKSReply(upstream.LocalAddr())); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
}

// host returns the CONNECT target in the form it arrived in: a name stays a name, an address stays an
// address, so a row can assert on the FORM and not only on the value.
func (t socksTarget) host() string {
	if t.isDomain {
		return t.domain
	}
	return t.address.String()
}

// ---------------------------------------------------------------------------
// The configuration
// ---------------------------------------------------------------------------

// fipConfig is the stand's box. `fakeIPRange` and `cacheFilePath` are the two axes the contract is
// written on: which generation's range is configured, and whether issuance survives a new Box.
type fipConfig struct {
	mixedPort   uint16
	peer        *fipPeerSink
	fakeIPRange string // "" means a box with no fakeip server at all
	v6Range     string
	// cacheFilePath enables `experimental.cache_file` + `store_fakeip`, the only path on which
	// issuance survives a new Box.
	cacheFilePath string
	// defaultDomainResolver names a resolver tag for `route.default_domain_resolver`.
	defaultDomainResolver string
	logLevel              string
}

const fipHostsTable = `"predefined": {"fip-owned.test": "127.0.0.1", "fip-second.test": "127.0.0.1", "fip-third.test": "127.0.0.1"}`

func (c fipConfig) json() string {
	level := c.logLevel
	if level == "" {
		level = chainLogLevel
	}
	servers := `{"tag": "static", "type": "hosts", ` + fipHostsTable + `}`
	rules := ""
	if c.fakeIPRange != "" {
		rangeOptions := fmt.Sprintf(`"inet4_range": %q`, c.fakeIPRange)
		if c.v6Range != "" {
			rangeOptions += fmt.Sprintf(`, "inet6_range": %q`, c.v6Range)
		}
		servers = fmt.Sprintf(`{"tag": "fakeip", "type": "fakeip", %s}, `, rangeOptions) + servers
		rules = `"rules": [{"domain": ["fip-owned.test", "fip-second.test", "fip-third.test"], "server": "fakeip"}],`
	}
	experimental := ""
	if c.cacheFilePath != "" {
		experimental = fmt.Sprintf(
			`, "experimental": {"cache_file": {"enabled": true, "path": %q, "store_fakeip": true}}`,
			c.cacheFilePath)
	}
	defaultResolver := ""
	if c.defaultDomainResolver != "" {
		defaultResolver = fmt.Sprintf(`, "default_domain_resolver": {"server": %q}`, c.defaultDomainResolver)
	}
	return fmt.Sprintf(`{
  "log": {"level": %q},
  "dns": {
    "servers": [%s],
    %s
    "final": "static"
  },
  "inbounds": [{"type": "mixed", "tag": "device-in", "listen": "127.0.0.1", "listen_port": %d}],
  "outbounds": [
    {"type": "socks", "tag": "exit", "server": %q, "server_port": %d, "version": "5",
     "domain_resolver": "static", "destination_dns_ownership": true}
  ],
  "route": {"final": "exit"%s}%s
}`, level, servers, rules, c.mixedPort, fipSplitHost(c.peer.address()), fipSplitPort(c.peer.address()),
		defaultResolver, experimental)
}

func fipSplitHost(address string) string {
	parsed, err := netip.ParseAddrPort(address)
	if err != nil {
		panic(err)
	}
	return parsed.Addr().String()
}

func fipSplitPort(address string) uint16 {
	parsed, err := netip.ParseAddrPort(address)
	if err != nil {
		panic(err)
	}
	return parsed.Port()
}

// ---------------------------------------------------------------------------
// Small probes
// ---------------------------------------------------------------------------

// fipAsk asks the box's own dns server for a name through the product's hijack entry point - the path
// a device's query takes - and returns the address it answered with.
func fipAsk(t *testing.T, running *chain, name string, queryType uint16) netip.Addr {
	t.Helper()
	response := queryThroughHijack(t, running, name, queryType)
	address := readDNSAddress(t, response)
	t.Logf("DNS %s/%d -> %s", name, queryType, address)
	return address
}

func fipProxyAddress(port uint16) string { return fmt.Sprintf("127.0.0.1:%d", port) }

// fipReloadRootContext builds the context a SEQUENCE of Boxes extends, with one issuance ledger in it.
//
// # Why this is the shape under test and not a convenience
//
// There is no in-process reload of a Box in this tree. `daemon/started_service.go:251
// StartOrReloadService` closes the old Box (:270 `_ = oldInstance.Close()`) and builds the next one
// (:280) from `service.ExtendContext(s.ctx)`; `sing/service.ExtendContext` is `registry.Clone()`, a
// shallow copy, so a service registered once in the long-lived context is the SAME object in every Box
// built from it. Registration happens once per application session (`NewStartedService`), not per
// reload.
//
// So the stand registers the ledger exactly where the daemon does - on the root context - and then
// builds two Boxes from it. A test that gave each Box its own root would be measuring a different
// program.
//
// `include.Context` is applied here because the Box needs its protocol registrations from the root,
// which is also what the daemon's context carries by the time `newInstance` extends it.
func fipReloadRootContext() (context.Context, *adapter.FakeIPIssuanceLedger) {
	root := include.Context(context.Background())
	ledger := adapter.NewFakeIPIssuanceLedger()
	service.MustRegisterPtr[adapter.FakeIPIssuanceLedger](root, ledger)
	return root, ledger
}

// fipFakeIPStoreIn reaches a Box's own FakeIP store through the live dns transport manager, which is
// the object the router itself consults. Nothing is substituted: this is the production store.
func fipFakeIPStoreIn(t *testing.T, running *chain) adapter.FakeIPStore {
	t.Helper()
	manager := service.FromContext[adapter.DNSTransportManager](running.ctx)
	require.NotNil(t, manager, "the running box must publish a dns transport manager")
	transport := manager.FakeIP()
	require.NotNil(t, transport, "this box must have a fakeip transport")
	return transport.Store()
}

// fipRouterLedger reads the ledger the same way the router does - from the ROUTER's context, not from
// the test's variable - so a key-derivation mistake in the registry pair shows up as a failure here
// rather than as a test that silently proves nothing.
func fipRouterLedger(t *testing.T, running *chain) *adapter.FakeIPIssuanceLedger {
	t.Helper()
	ledger := service.PtrFromContext[adapter.FakeIPIssuanceLedger](running.ctx)
	require.NotNil(t, ledger,
		"the router's own context does not resolve the issuance ledger: the registration pair "+
			"(`MustRegisterPtr[T]` written, `PtrFromContext[T]` read) does not agree, and the fix "+
			"would be inert")
	return ledger
}

// fipEgress renders the four facts every egress assertion in this file carries: the accept count, the
// recorded target(s), the ATYP, and the port.
func fipEgress(label string, code byte, acceptsBefore, acceptsAfter int, added []socksRequest) string {
	form := "none"
	if len(added) > 0 {
		form = ""
		for index, request := range added {
			if index > 0 {
				form += " "
			}
			form += fmt.Sprintf("{atyp=%d target=%s port=%d}", request.AddressType, request.Host, request.Port)
		}
	}
	return fmt.Sprintf("%s code=0x%02x accepts=%d->%d requests=%s",
		label, code, acceptsBefore, acceptsAfter, form)
}

// fipRequireRefused is the load-bearing assertion of this file: the flow must not have succeeded AND
// the peer must have received nothing. A refusal raised after the peer was asked is not a refusal.
func fipRequireRefused(t *testing.T, code byte, added []socksRequest, acceptsBefore, acceptsAfter int, what string) {
	t.Helper()
	require.NotEqual(t, byte(0x00), code,
		"%s: the client was told the connect SUCCEEDED, so the destination was dialled", what)
	require.Empty(t, added,
		"%s: the peer was asked for %v. A synthetic address reaching a peer is the placeholder "+
			"escaping to the real network", what, added)
	require.Equal(t, acceptsBefore, acceptsAfter,
		"%s: the peer accepted %d new connection(s); the load-bearing fact is that it received none",
		what, acceptsAfter-acceptsBefore)
}

// fipRequireOwnedAddress is the wire assertion for a destination the box recovered a NAME for.
//
// What must cross is the address the box's own policy answered with - never the synthetic one. With
// `destination_dns_ownership` on, the outbound resolves the recovered name LOCALLY and the peer is
// asked for the resulting address, which on this stand is fixed by the hosts table, so "the
// placeholder did not cross" is exact rather than approximate.
func fipRequireOwnedAddress(t *testing.T, added []socksRequest, synthetic netip.Addr, expected netip.Addr) {
	t.Helper()
	require.Len(t, added, 1, "the peer must have been asked exactly once")
	require.Equal(t, expected.String(), added[0].Host,
		"the peer must be asked for the address the box's policy answered with (%s); got %s",
		expected, added[0].Host)
	require.Equal(t, byte(0x01), added[0].AddressType, "the target must travel as an IPv4 literal (ATYP=1)")
	require.NotEqual(t, synthetic.String(), added[0].Host,
		"the SYNTHETIC address crossed to the peer: it is a placeholder that means nothing outside "+
			"this process")
}

// ---------------------------------------------------------------------------
// A1: the mapped path, unchanged, measured on the wire
// ---------------------------------------------------------------------------

// fipRequireMappedFlow asserts the route decision itself: the destination the rules matched on was the
// DOMAIN the address was issued for, the synthetic address is remembered as what the client asked for,
// and the flow is marked as a fakeip flow.
//
// This is the assertion that makes "the address was recognised" independent of what the outbound then
// does with the recovered name. With `destination_dns_ownership` on, the outbound resolves that name
// locally and the peer legitimately receives an address - so the wire recording alone cannot show
// whether the rewrite happened, and the router's own decision is where it is visible.
func fipRequireMappedFlow(t *testing.T, running *chain, synthetic netip.Addr, port uint16) flowRecord {
	t.Helper()
	flows := running.tracker.snapshot()
	require.NotEmpty(t, flows, "the router recorded no flow")
	flow := flows[len(flows)-1]
	suffix := fmt.Sprintf(":%d", port)
	t.Logf("FLOW destination=%s origin=%s domain=%q fakeip=%v routeRule=%q",
		flow.Destination, flow.OriginDestination, flow.Domain, flow.FakeIP, flow.RouteRule)
	require.True(t, flow.FakeIP, "the flow must be marked as a fakeip flow")
	require.Equal(t, "fip-owned.test"+suffix, flow.Destination,
		"the destination must be rewritten to the domain the address was issued for; a literal here "+
			"means the synthetic address was treated as an ordinary destination")
	require.Equal(t, synthetic.String()+suffix, flow.OriginDestination,
		"the address the client actually asked for must be remembered as the origin destination")
	return flow
}

// TestFIPMappedAddressIsForwardedAsItsDomain is the baseline row and the compatibility positive: an
// address the current generation maps is still recognised, the destination is rewritten to the name
// it was issued for, and NO synthetic literal reaches the peer.
//
// It is also what proves the stand can see the difference at all: the same client, peer and port
// produce `127.0.0.1` here and `198.18.0.2` in the rows below, so a recording of one is not an
// artefact of the harness.
func TestFIPMappedAddressIsForwardedAsItsDomain(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	mixedPort := freePort(t)
	running := startChain(t, fipConfig{mixedPort: mixedPort, peer: peer, fakeIPRange: fipRangeCurrent}.json())
	t.Cleanup(func() { _ = running.closeNow() })

	address := fipAsk(t, running, "fip-owned.test", 1)
	require.True(t, netip.MustParsePrefix(fipRangeCurrent).Contains(address),
		"the fakeip server must answer from its own range, got %s", address)

	conn, code := socks5Request(t, fipProxyAddress(mixedPort), 0x01, address.String(), 443)
	if conn != nil {
		defer conn.Close()
	}
	require.Equal(t, byte(0x00), code, "a currently mapped fakeip address must connect")
	requireEcho(t, conn, "fip-a1")

	requests := peer.awaitSince(0, 500*time.Millisecond)
	t.Logf("EGRESS-A1 %s", fipEgress("domain=fip-owned.test", code, 0, peer.acceptCount(), requests))
	fipRequireOwnedAddress(t, requests, address, netip.MustParseAddr("127.0.0.1"))
	fipRequireMappedFlow(t, running, address, 443)
}

// TestFIPInRangeUnissuedIsRefusedBothSpellings covers C2.
//
// `198.18.0.5` is inside the configured range and this Box never issued it: the store's first
// issuance is `range.Addr().Next()` == `198.18.0.2`. The row asserts the refusal at the peer rather
// than on the error text, for BOTH spellings, because a 4-in-6 destination is an IPv4 address in
// sixteen bytes and `netip.Prefix.Contains` answers `false` for an IPv4 prefix against one
// (BitLen 32 vs 128) - so a code path that compared them without normalising would miss the branch
// entirely and dial the literal.
func TestFIPInRangeUnissuedIsRefusedBothSpellings(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	mixedPort := freePort(t)
	running := startChain(t, fipConfig{mixedPort: mixedPort, peer: peer, fakeIPRange: fipRangeCurrent}.json())
	t.Cleanup(func() { _ = running.closeNow() })

	unissued := netip.MustParseAddr("198.18.0.5")
	require.True(t, netip.MustParsePrefix(fipRangeCurrent).Contains(unissued))

	for _, spelling := range []struct {
		name        string
		addressType byte
		host        string
	}{
		{"plain", 0x01, unissued.String()},
		{"4in6", 0x04, netip.AddrFrom16(unissued.As16()).String()},
	} {
		t.Run(spelling.name, func(t *testing.T) {
			mark := peer.mark()
			acceptsBefore := peer.acceptCount()
			conn, code := socks5Request(t, fipProxyAddress(mixedPort), spelling.addressType, spelling.host, 443)
			if conn != nil {
				defer conn.Close()
			}
			added := peer.awaitSince(mark, 400*time.Millisecond)
			t.Logf("EGRESS-A2-%s %s", spelling.name,
				fipEgress("host="+spelling.host, code, acceptsBefore, peer.acceptCount(), added))
			fipRequireRefused(t, code, added, acceptsBefore, peer.acceptCount(),
				fmt.Sprintf("in-range unissued address %s (%s spelling)", unissued, spelling.name))
		})
	}
}

// TestFIPMappedAddressInFourInSixSpellingIsForwardedAsItsDomain is the other half of the 4-in-6
// question: when a mapped address IS delivered in its 4-in-6 spelling, it must still map to its
// domain. `netip.Addr` equality is spelling-sensitive, so a branch that normalises for `Contains` and
// not for `Lookup` would land on `missing fakeip record` - failing closed, but failing C1.
//
// The row is driven through a real SOCKS5 client that sends ATYP=0x04 with the mapped bytes.
func TestFIPMappedAddressInFourInSixSpellingIsForwardedAsItsDomain(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	mixedPort := freePort(t)
	running := startChain(t, fipConfig{mixedPort: mixedPort, peer: peer, fakeIPRange: fipRangeCurrent}.json())
	t.Cleanup(func() { _ = running.closeNow() })

	address := fipAsk(t, running, "fip-owned.test", 1)
	mapped := netip.AddrFrom16(address.As16())
	require.True(t, mapped.Is4In6(), "the fixture must produce a 4-in-6 address, got %s", mapped)

	mark := peer.mark()
	acceptsBefore := peer.acceptCount()
	conn, code := socks5Request(t, fipProxyAddress(mixedPort), 0x04, mapped.String(), 443)
	if conn != nil {
		defer conn.Close()
	}
	added := peer.awaitSince(mark, 500*time.Millisecond)
	t.Logf("EGRESS-A8-4in6 %s", fipEgress("mapped="+mapped.String(), code, acceptsBefore, peer.acceptCount(), added))
	flows := running.tracker.snapshot()
	for _, flow := range flows {
		t.Logf("FLOW-A8-4in6 destination=%s origin=%s fakeip=%v", flow.Destination, flow.OriginDestination, flow.FakeIP)
	}
	require.Equal(t, byte(0x00), code,
		"the 4-in-6 spelling of a mapped address must connect: it denotes an address this Box issued")
	fipRequireOwnedAddress(t, added, address, netip.MustParseAddr("127.0.0.1"))

	require.NotEmpty(t, flows)
	flow := flows[len(flows)-1]
	require.Equal(t, "fip-owned.test:443", flow.Destination,
		"the 4-in-6 spelling must be recognised as mapped and rewritten to its domain; a literal "+
			"destination here means the branch did not recognise the address")
	require.True(t, flow.FakeIP, "and the flow must be marked as a fakeip flow")
}

// ---------------------------------------------------------------------------
// A3 / A4 / A6: an address a PREVIOUS generation issued
// ---------------------------------------------------------------------------

// TestFIPAddressFromThePreviousGenerationDoesNotEscape is C4, and it is the reason this task exists.
//
// # The configuration-replacement shape, proved rather than assumed
//
// There is no in-process reload of a Box in this tree. The real path is
// `daemon/started_service.go:251 StartOrReloadService`:
//
//	:260  oldInstance := s.instance
//	:270  _ = oldInstance.Close()
//	:280  instance, err := s.newInstance(ctx, profileContent, options, oldInstance != nil)
//	         -> a brand-new box.New from service.ExtendContext(s.ctx)
//
// So a reload IS "old Box closed, new Box built in the same process". `closeNow()` + `startChain()`
// below is that exact shape; the only difference from the daemon is which object holds the
// configuration string.
//
// # Why an address from the previous generation is an ESCAPE and not an edge case
//
// The client resolved `fip-owned.test` and was handed `198.18.0.2`. The range then moved to
// `198.19.0.0/15`. The client keeps dialling the address it holds - it has no way to know anything
// changed - and the box no longer recognises it, because `Contains` answers about the CURRENT range.
// The mapping is still on disk, which is exactly what makes the address ATTRIBUTABLE; reading that
// evidence is what the fix has to do, and it has to do it before `Store.Start` resets it.
func TestFIPAddressFromThePreviousGenerationDoesNotEscape(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	cachePath := tempDir(t) + "\\fip-a3.db"

	// The two Boxes below extend ONE root context that carries the issuance ledger, which is the shape
	// `daemon.StartedService` builds across a reload. See fipReloadRootContext for the call chain.
	root, wantLedger := fipReloadRootContext()

	first := startChainInContext(t, root, fipConfig{
		mixedPort: freePort(t), peer: peer, fakeIPRange: fipRangeCurrent, cacheFilePath: cachePath,
	}.json(), nil)
	issued := fipAsk(t, first, "fip-owned.test", 1)
	t.Logf("A3 generation 1 range=%s issued=%s", fipRangeCurrent, issued)
	require.True(t, netip.MustParsePrefix(fipRangeCurrent).Contains(issued),
		"generation 1 must issue from its own range, got %s", issued)
	// The fixture must really have a ledger, or every assertion below would pass vacuously.
	require.Same(t, wantLedger, fipRouterLedger(t, first),
		"the Box the router is running in must resolve the SAME ledger the root context carries")
	require.True(t, wantLedger.Issued(issued),
		"generation 1 must have RECORDED the address it issued: the ledger is the proof source the "+
			"refusal is built on, and a recording gap would make the refusal unreachable")
	require.NoError(t, first.closeNow())

	secondPort := freePort(t)
	second := startChainInContext(t, root, fipConfig{
		mixedPort: secondPort, peer: peer, fakeIPRange: fipRangeMoved, cacheFilePath: cachePath,
	}.json(), nil)
	t.Cleanup(func() { _ = second.closeNow() })
	require.Same(t, wantLedger, fipRouterLedger(t, second),
		"a Box built after a reload must share the SAME ledger: that is the whole mechanism")

	require.False(t, netip.MustParsePrefix(fipRangeMoved).Contains(issued),
		"the fixture must actually move the range away from the issued address")

	mark := peer.mark()
	acceptsBefore := peer.acceptCount()
	conn, code := socks5Request(t, fipProxyAddress(secondPort), 0x01, issued.String(), 443)
	if conn != nil {
		defer conn.Close()
	}
	added := peer.awaitSince(mark, 600*time.Millisecond)
	t.Logf("EGRESS-A3 %s", fipEgress("issued="+issued.String()+" oldRange="+fipRangeCurrent+" newRange="+fipRangeMoved,
		code, acceptsBefore, peer.acceptCount(), added))
	fipRequireRefused(t, code, added, acceptsBefore, peer.acceptCount(),
		"an address this Box issued under the previous configuration, dialled after the range moved")

	// The control for the same Box: an address in its OWN new range that it never issued is refused
	// too, so the refusal above is not "the new generation refuses everything".
	own := netip.MustParsePrefix(fipRangeMoved).Addr().Next().Next()
	require.True(t, netip.MustParsePrefix(fipRangeMoved).Contains(own))
	ownMark := peer.mark()
	ownAccepts := peer.acceptCount()
	conn2, code2 := socks5Request(t, fipProxyAddress(secondPort), 0x01, own.String(), 443)
	if conn2 != nil {
		defer conn2.Close()
	}
	ownAdded := peer.awaitSince(ownMark, 400*time.Millisecond)
	t.Logf("CONTROL-A3 %s", fipEgress("own-range-unissued="+own.String(), code2, ownAccepts, peer.acceptCount(), ownAdded))
	fipRequireRefused(t, code2, ownAdded, ownAccepts, peer.acceptCount(),
		"an unissued address inside the NEW range (the control that keeps the row honest)")
}

// TestFIPRangeMoveNewGenerationStillIssuesCorrectly is the compatibility half of A3: after the range
// moves, the box must still be a working fakeip resolver. Without this row, "refuse the old address"
// could be satisfied by a box that refuses everything.
func TestFIPRangeMoveNewGenerationStillIssuesCorrectly(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))

	first := startChain(t, fipConfig{
		mixedPort: freePort(t), peer: peer, fakeIPRange: fipRangeCurrent,
	}.json())
	firstIssued := fipAsk(t, first, "fip-owned.test", 1)
	require.NoError(t, first.closeNow())

	secondPort := freePort(t)
	second := startChain(t, fipConfig{mixedPort: secondPort, peer: peer, fakeIPRange: fipRangeMoved}.json())
	t.Cleanup(func() { _ = second.closeNow() })

	secondIssued := fipAsk(t, second, "fip-owned.test", 1)
	t.Logf("A3-control firstIssued=%s firstRange=%s secondIssued=%s secondRange=%s",
		firstIssued, fipRangeCurrent, secondIssued, fipRangeMoved)
	require.True(t, netip.MustParsePrefix(fipRangeMoved).Contains(secondIssued),
		"the new generation must issue from its own range, got %s", secondIssued)
	require.False(t, netip.MustParsePrefix(fipRangeCurrent).Contains(secondIssued),
		"and it must not issue from the previous generation's range")

	mark := peer.mark()
	conn, code := socks5Request(t, fipProxyAddress(secondPort), 0x01, secondIssued.String(), 443)
	added := peer.awaitSince(mark, 500*time.Millisecond)
	t.Logf("EGRESS-A3-control %s", fipEgress("newIssued="+secondIssued.String(), code, 0, peer.acceptCount(), added))
	require.Equal(t, byte(0x00), code, "the new generation's own mapping must work")
	if conn != nil {
		defer conn.Close()
	}
	fipRequireOwnedAddress(t, added, secondIssued, netip.MustParseAddr("127.0.0.1"))
	fipRequireMappedFlow(t, second, secondIssued, 443)
}

// TestFIPAddressIssuedBeforeTheFakeIPServerWasRemovedDoesNotEscape is A4: the fakeip server is gone
// from the new generation's configuration entirely, so there is no range to be inside of. The client
// still holds the address.
func TestFIPAddressIssuedBeforeTheFakeIPServerWasRemovedDoesNotEscape(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	cachePath := tempDir(t) + "\\fip-a4.db"

	root, wantLedger := fipReloadRootContext()

	first := startChainInContext(t, root, fipConfig{
		mixedPort: freePort(t), peer: peer, fakeIPRange: fipRangeCurrent, cacheFilePath: cachePath,
	}.json(), nil)
	issued := fipAsk(t, first, "fip-owned.test", 1)
	t.Logf("A4 generation 1 range=%s issued=%s", fipRangeCurrent, issued)
	require.Same(t, wantLedger, fipRouterLedger(t, first))
	require.NoError(t, first.closeNow())

	secondPort := freePort(t)
	second := startChainInContext(t, root, fipConfig{
		mixedPort: secondPort, peer: peer,
		// The fakeip SERVER is gone, so this generation has no store at all. The durable file is still
		// configured, and the ledger is the only thing left that can attribute the address.
		fakeIPRange:   "",
		cacheFilePath: cachePath,
	}.json(), nil)
	t.Cleanup(func() { _ = second.closeNow() })
	require.Same(t, wantLedger, fipRouterLedger(t, second),
		"the ledger must be reachable even though this Box has NO fakeip server: that is exactly the "+
			"case where `dnsTransport.FakeIP()` is nil and the store cannot be asked")
	// The ledger's own record is the discriminator here, so assert it positively: the address is
	// attributable, and a nil ledger would have made the refusal below unreachable.
	require.True(t, wantLedger.Issued(issued),
		"the retired generation's issuance must still be recorded after its Box is gone")

	mark := peer.mark()
	acceptsBefore := peer.acceptCount()
	conn, code := socks5Request(t, fipProxyAddress(secondPort), 0x01, issued.String(), 443)
	if conn != nil {
		defer conn.Close()
	}
	added := peer.awaitSince(mark, 600*time.Millisecond)
	t.Logf("EGRESS-A4 %s", fipEgress("issued="+issued.String()+" fakeipRemoved", code, acceptsBefore, peer.acceptCount(), added))
	fipRequireRefused(t, code, added, acceptsBefore, peer.acceptCount(),
		"an address whose fakeip server was removed from the configuration")

	// The control: ordinary literal traffic through the same Box must still work, so the refusal is
	// about the issued address and not about the new configuration being broken.
	controlMark := peer.mark()
	conn2, code2 := socks5Request(t, fipProxyAddress(secondPort), 0x01, "127.0.0.1", 443)
	controlAdded := peer.awaitSince(controlMark, 500*time.Millisecond)
	t.Logf("CONTROL-A4 %s", fipEgress("literal=127.0.0.1", code2, 0, peer.acceptCount(), controlAdded))
	require.Equal(t, byte(0x00), code2, "a box with no fakeip server must still carry literal traffic")
	if conn2 != nil {
		requireEcho(t, conn2, "fip-a4-control")
		conn2.Close()
	}
	require.Len(t, controlAdded, 1)
	require.Equal(t, "127.0.0.1", controlAdded[0].Host)
}

// TestFIPClearedMappingIsNotReused is A6: the mapping is destroyed while the range stays the same.
//
// `Store.Reset()` is what the cache-clearing paths reach, and the range is unchanged, so the address
// is STILL inside the current range. The store's own record of having issued it is then the only
// remaining evidence, and it is what decides whether the address may be dialled. No DNS query happens
// between the reset and the dial, so nothing can re-learn the mapping.
func TestFIPClearedMappingIsNotReused(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	mixedPort := freePort(t)
	running := startChain(t, fipConfig{mixedPort: mixedPort, peer: peer, fakeIPRange: fipRangeCurrent}.json())
	t.Cleanup(func() { _ = running.closeNow() })

	issued := fipAsk(t, running, "fip-owned.test", 1)
	preconditionMark := peer.mark()
	conn0, code0 := socks5Request(t, fipProxyAddress(mixedPort), 0x01, issued.String(), 443)
	precondition := peer.awaitSince(preconditionMark, 500*time.Millisecond)
	t.Logf("PRECONDITION-A6 %s", fipEgress("issued="+issued.String(), code0, 0, peer.acceptCount(), precondition))
	require.Equal(t, byte(0x00), code0, "precondition: the mapping must work before it is cleared")
	if conn0 != nil {
		conn0.Close()
	}
	require.Len(t, precondition, 1, "precondition: the peer must have been asked")
	fipRequireOwnedAddress(t, precondition, issued, netip.MustParseAddr("127.0.0.1"))
	fipRequireMappedFlow(t, running, issued, 443)

	// Clear the mapping through the box's own store - the object the router consults.
	require.NoError(t, fipFakeIPStoreIn(t, running).Reset(), "resetting the fakeip store must succeed")

	mark := peer.mark()
	acceptsBefore := peer.acceptCount()
	conn, code := socks5Request(t, fipProxyAddress(mixedPort), 0x01, issued.String(), 443)
	if conn != nil {
		defer conn.Close()
	}
	added := peer.awaitSince(mark, 600*time.Millisecond)
	t.Logf("EGRESS-A6 %s", fipEgress("issued="+issued.String()+" mappingCleared", code, acceptsBefore, peer.acceptCount(), added))
	fipRequireRefused(t, code, added, acceptsBefore, peer.acceptCount(),
		"an address whose mapping was cleared, with its range unchanged")
}

// ---------------------------------------------------------------------------
// A7: the positive control that forbids a blanket guard
// ---------------------------------------------------------------------------

// TestFIPLiteralWithoutIssuanceStaysReachable is A7 and the reason C3 exists.
//
// # This is not a hypothetical row
//
// On the host this was measured on, `198.18.0.0/15` is LIVE ROUTED SPACE: an active `tun0` interface
// answers every query - a real name and an NXDOMAIN alike - with an address in that range, and those
// addresses connect. A guard written as "refuse anything in the fakeip range" would therefore break
// real traffic on a real machine, silently.
//
// Three literals are exercised, each with zero issuance evidence in the box under test:
//
//   - `127.0.0.1`, the ordinary loopback literal, which must keep working as it always has;
//   - `198.18.0.9`, inside the range another generation used but this Box never did;
//   - `198.20.0.9`, inside no range at all.
//
// The box's own range is `10.7.0.0/16`, so "inside the configured range" is false for all three and
// the row measures exactly the boundary C3 draws.
func TestFIPLiteralWithoutIssuanceStaysReachable(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	mixedPort := freePort(t)
	// No cache file: this Box has no durable memory of anything, so it cannot have issued these.
	running := startChain(t, fipConfig{mixedPort: mixedPort, peer: peer, fakeIPRange: fipRangeCustom}.json())
	t.Cleanup(func() { _ = running.closeNow() })

	for _, literal := range []string{"127.0.0.1", "198.18.0.9", "198.20.0.9"} {
		t.Run(literal, func(t *testing.T) {
			mark := peer.mark()
			conn, code := socks5Request(t, fipProxyAddress(mixedPort), 0x01, literal, 443)
			added := peer.awaitSince(mark, 500*time.Millisecond)
			t.Logf("EGRESS-A7 %s", fipEgress("literal="+literal, code, 0, peer.acceptCount(), added))
			require.Equal(t, byte(0x00), code,
				"a literal address with zero issuance evidence must stay reachable: %s was refused, "+
					"which is a compatibility regression for every address that merely LOOKS like a "+
					"placeholder", literal)
			require.Len(t, added, 1, "the peer must have been asked for the literal")
			require.Equal(t, literal, added[0].Host,
				"the literal must cross unchanged, not rewritten to something else")
			require.Equal(t, byte(0x01), added[0].AddressType, "an IPv4 literal must travel as ATYP=1")
			require.Equal(t, uint16(443), added[0].Port)
			if conn != nil {
				requireEcho(t, conn, "fip-a7-literal")
				conn.Close()
			}
		})
	}
}

// TestFIPLiteralIsReachableWithNoFakeIPServerAtAll is the same positive control at its strongest:
// the box has no fakeip server, so `r.dnsTransport.FakeIP()` is nil and there is no store to consult.
// No part of the new refusal may depend on the address being outside a range that does not exist.
func TestFIPLiteralIsReachableWithNoFakeIPServerAtAll(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	mixedPort := freePort(t)
	running := startChain(t, fipConfig{mixedPort: mixedPort, peer: peer, fakeIPRange: ""}.json())
	t.Cleanup(func() { _ = running.closeNow() })

	for _, literal := range []string{"127.0.0.1", "198.18.0.2"} {
		mark := peer.mark()
		conn, code := socks5Request(t, fipProxyAddress(mixedPort), 0x01, literal, 443)
		added := peer.awaitSince(mark, 500*time.Millisecond)
		t.Logf("EGRESS-A7-nofakeip %s", fipEgress("literal="+literal, code, 0, peer.acceptCount(), added))
		require.Equal(t, byte(0x00), code,
			"with no fakeip server there is no store and no issuance, so %s is an ordinary literal", literal)
		require.Len(t, added, 1)
		require.Equal(t, literal, added[0].Host)
		if conn != nil {
			conn.Close()
		}
	}
}

// TestFIPCustomRangeOwnAddressesAreIndependentOfTheDefaultRange is the other half of A7: a Box whose
// range is custom must not treat the DEFAULT range as its own, in either direction.
func TestFIPCustomRangeOwnAddressesAreIndependentOfTheDefaultRange(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	mixedPort := freePort(t)
	running := startChain(t, fipConfig{mixedPort: mixedPort, peer: peer, fakeIPRange: fipRangeCustom}.json())
	t.Cleanup(func() { _ = running.closeNow() })

	issued := fipAsk(t, running, "fip-owned.test", 1)
	require.True(t, netip.MustParsePrefix(fipRangeCustom).Contains(issued),
		"a custom range must be the one that answers, got %s", issued)

	mark := peer.mark()
	conn, code := socks5Request(t, fipProxyAddress(mixedPort), 0x01, issued.String(), 443)
	added := peer.awaitSince(mark, 500*time.Millisecond)
	t.Logf("EGRESS-A7-custom %s", fipEgress("customIssued="+issued.String(), code, 0, peer.acceptCount(), added))
	require.Equal(t, byte(0x00), code, "the custom range's own mapping must work")
	if conn != nil {
		conn.Close()
	}
	fipRequireOwnedAddress(t, added, issued, netip.MustParseAddr("127.0.0.1"))
	fipRequireMappedFlow(t, running, issued, 443)
}

// ---------------------------------------------------------------------------
// A8: IPv6 and the v6 spelling
// ---------------------------------------------------------------------------

// TestFIPIPv6RangeIsConfiguredAndDoesNotDisturbIPv4 covers the v6 half of A8: an IPv6 range is
// accepted, IPv4 issuance still works from the IPv4 range, and a v6 literal with no issuance evidence
// is untouched.
func TestFIPIPv6RangeIsConfiguredAndDoesNotDisturbIPv4(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	mixedPort := freePort(t)
	running := startChain(t, fipConfig{
		mixedPort: mixedPort, peer: peer, fakeIPRange: fipRangeCurrent, v6Range: fipRangeV6,
	}.json())
	t.Cleanup(func() { _ = running.closeNow() })

	v4 := fipAsk(t, running, "fip-owned.test", 1)
	require.True(t, netip.MustParsePrefix(fipRangeCurrent).Contains(v4),
		"with both ranges configured, an A query must still answer from the IPv4 range, got %s", v4)

	mark := peer.mark()
	conn, code := socks5Request(t, fipProxyAddress(mixedPort), 0x01, v4.String(), 443)
	added := peer.awaitSince(mark, 500*time.Millisecond)
	t.Logf("EGRESS-A8-v6range %s", fipEgress("v4issued="+v4.String(), code, 0, peer.acceptCount(), added))
	require.Equal(t, byte(0x00), code)
	if conn != nil {
		conn.Close()
	}
	fipRequireOwnedAddress(t, added, v4, netip.MustParseAddr("127.0.0.1"))
	fipRequireMappedFlow(t, running, v4, 443)

	// A v6 destination with zero issuance evidence, inside the configured v6 range: this is the C2
	// case in the second family, and it must be refused rather than dialled as a literal.
	unissuedV6 := netip.MustParsePrefix(fipRangeV6).Addr().Next().Next().Next()
	require.True(t, netip.MustParsePrefix(fipRangeV6).Contains(unissuedV6))
	v6Mark := peer.mark()
	v6Accepts := peer.acceptCount()
	conn6, code6 := socks5Request(t, fipProxyAddress(mixedPort), 0x04, unissuedV6.String(), 443)
	if conn6 != nil {
		defer conn6.Close()
	}
	v6Added := peer.awaitSince(v6Mark, 400*time.Millisecond)
	t.Logf("EGRESS-A8-v6unissued %s", fipEgress("v6="+unissuedV6.String(), code6, v6Accepts, peer.acceptCount(), v6Added))
	fipRequireRefused(t, code6, v6Added, v6Accepts, peer.acceptCount(),
		"an unissued address inside the configured IPv6 range")
}

// ---------------------------------------------------------------------------
// A9: a fakeip server named as a destination resolver
// ---------------------------------------------------------------------------

// TestFIPDefaultDomainResolverNamingAFakeIPServerIsRefusedBeforeAnyExchange is the
// `route.default_domain_resolver` spelling of A9.
//
// `common/dialer/dialer.go:122-131` takes the DEFAULT resolver from
// `networkManager.DefaultOptions()`, which `route/network.go:166` fills from
// `route.default_domain_resolver`. A fakeip server placed there answers a destination lookup with an
// address only this process can interpret, and the caller dials what it is given.
//
// The exchange count is the load-bearing half: a refusal raised AFTER the query would still have
// created the mapping, which is the state the refusal exists to prevent. So a real DNS responder
// stands behind the fakeip server's rule and must receive zero questions.
func TestFIPDefaultDomainResolverNamingAFakeIPServerIsRefusedBeforeAnyExchange(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	// A real DNS server behind an ordinary transport, so "the fakeip server was not asked" is
	// measured against a server that WOULD have recorded the question.
	recorder := startDNSResponder(t, "static", map[string]netip.Addr{"fip-owned.test": netip.MustParseAddr("127.0.0.1")})
	mixedPort := freePort(t)

	config := fmt.Sprintf(`{
  "log": {"disabled": true},
  "dns": {
    "servers": [
      {"tag": "fakeip", "type": "fakeip", "inet4_range": %q},
      {"tag": "static", "type": "udp", "server": "127.0.0.1", "server_port": %d}
    ],
    "rules": [{"domain": ["fip-owned.test"], "server": "fakeip"}],
    "final": "static"
  },
  "inbounds": [{"type": "mixed", "tag": "device-in", "listen": "127.0.0.1", "listen_port": %d}],
  "outbounds": [
    {"type": "socks", "tag": "exit", "server": %q, "server_port": %d, "version": "5",
     "destination_dns_ownership": true}
  ],
  "route": {"final": "exit", "default_domain_resolver": {"server": "fakeip"}}
}`, fipRangeCurrent, recorder.port(), mixedPort, fipSplitHost(peer.address()), fipSplitPort(peer.address()))
	running := startChain(t, config)
	t.Cleanup(func() { _ = running.closeNow() })

	mark := peer.mark()
	acceptsBefore := peer.acceptCount()
	questionsBefore := len(recorder.asked())
	// The client asks the box for a NAME. Destination DNS ownership means the box must resolve it
	// locally, and the local policy for this name is the fakeip server.
	conn, code := socks5Request(t, fipProxyAddress(mixedPort), 0x03, "fip-owned.test", 443)
	if conn != nil {
		defer conn.Close()
	}
	added := peer.awaitSince(mark, 600*time.Millisecond)
	questions := recorder.asked()
	t.Logf("EGRESS-A9-default %s questionsBefore=%d questionsAfter=%d questions=%v",
		fipEgress("name=fip-owned.test", code, acceptsBefore, peer.acceptCount(), added),
		questionsBefore, len(questions), questions)
	fipRequireRefused(t, code, added, acceptsBefore, peer.acceptCount(),
		"route.default_domain_resolver naming a fakeip server")
	require.Equal(t, questionsBefore, len(questions),
		"the resolver was asked %v: a refusal raised after the query would still have created the "+
			"mapping, which is the state the refusal exists to prevent", questions[questionsBefore:])
}

// TestFIPOutboundDomainResolverNamingAFakeIPServerIsRefusedBeforeAnyExchange is the `domain_resolver`
// spelling, which commit 8fad3e9bc claims to have fixed. It is re-measured here on THIS stand so the
// two spellings are covered by one instrument: the difference between them is
// `common/dialer/dialer.go:106-113` versus `:122-131`, and a guard placed at one of them would leave
// the other open.
func TestFIPOutboundDomainResolverNamingAFakeIPServerIsRefusedBeforeAnyExchange(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	recorder := startDNSResponder(t, "static", map[string]netip.Addr{"fip-owned.test": netip.MustParseAddr("127.0.0.1")})
	mixedPort := freePort(t)

	config := fmt.Sprintf(`{
  "log": {"disabled": true},
  "dns": {
    "servers": [
      {"tag": "fakeip", "type": "fakeip", "inet4_range": %q},
      {"tag": "static", "type": "udp", "server": "127.0.0.1", "server_port": %d}
    ],
    "rules": [{"domain": ["fip-owned.test"], "server": "fakeip"}],
    "final": "static"
  },
  "inbounds": [{"type": "mixed", "tag": "device-in", "listen": "127.0.0.1", "listen_port": %d}],
  "outbounds": [
    {"type": "socks", "tag": "exit", "server": %q, "server_port": %d, "version": "5",
     "domain_resolver": "fakeip", "destination_dns_ownership": true}
  ],
  "route": {"final": "exit"}
}`, fipRangeCurrent, recorder.port(), mixedPort, fipSplitHost(peer.address()), fipSplitPort(peer.address()))
	running := startChain(t, config)
	t.Cleanup(func() { _ = running.closeNow() })

	mark := peer.mark()
	acceptsBefore := peer.acceptCount()
	questionsBefore := len(recorder.asked())
	conn, code := socks5Request(t, fipProxyAddress(mixedPort), 0x03, "fip-owned.test", 443)
	if conn != nil {
		defer conn.Close()
	}
	added := peer.awaitSince(mark, 600*time.Millisecond)
	questions := recorder.asked()
	t.Logf("EGRESS-A9-outbound %s questionsBefore=%d questionsAfter=%d questions=%v",
		fipEgress("name=fip-owned.test", code, acceptsBefore, peer.acceptCount(), added),
		questionsBefore, len(questions), questions)
	fipRequireRefused(t, code, added, acceptsBefore, peer.acceptCount(),
		"outbound domain_resolver naming a fakeip server")
	require.Equal(t, questionsBefore, len(questions),
		"the resolver was asked %v: the refusal must happen before the synthetic server is consulted",
		questions[questionsBefore:])
}

// ---------------------------------------------------------------------------
// A10: the second client protocol
// ---------------------------------------------------------------------------

// TestFIPRefusalIsTheSameOverHTTPConnect is A10 at the minimum: the same refusal and the same
// zero-connection peer fact measured through an HTTP CONNECT client rather than a SOCKS5 one, so the
// guard is not an artefact of one inbound protocol's error path.
//
// # Why the response head is NOT the assertion
//
// MEASURED while writing this row: `transport/http/server_conn.go:105-116` `serveConnect` writes
// `HTTP/1.1 200 Connection established` at :110 and only THEN hands the connection to the router at
// :114. The 200 is therefore written before any routing decision exists, so it says nothing about
// whether the destination was accepted - and an assertion on it would have been a red herring in both
// directions. The load-bearing fact is the peer recording, which is written by the hop before it
// dials anything.
func TestFIPRefusalIsTheSameOverHTTPConnect(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	cachePath := tempDir(t) + "\\fip-a10.db"

	// The same shared-root shape as A3: two Boxes, one ledger, which is what a real reload is.
	root, wantLedger := fipReloadRootContext()

	first := startChainInContext(t, root, fipConfig{
		mixedPort: freePort(t), peer: peer, fakeIPRange: fipRangeCurrent, cacheFilePath: cachePath,
	}.json(), nil)
	issued := fipAsk(t, first, "fip-owned.test", 1)
	t.Logf("A10 issued=%s", issued)
	require.Same(t, wantLedger, fipRouterLedger(t, first))
	require.NoError(t, first.closeNow())

	secondPort := freePort(t)
	second := startChainInContext(t, root, fipConfig{
		mixedPort: secondPort, peer: peer, fakeIPRange: fipRangeMoved, cacheFilePath: cachePath,
	}.json(), nil)
	t.Cleanup(func() { _ = second.closeNow() })
	require.Same(t, wantLedger, fipRouterLedger(t, second))

	mark := peer.mark()
	acceptsBefore := peer.acceptCount()
	flowsBefore := second.tracker.count()

	target := issued.String() + ":443"
	conn, err := net.DialTimeout("tcp", fipProxyAddress(secondPort), 5*time.Second)
	require.NoError(t, err)
	_, writeErr := conn.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
	require.NoError(t, writeErr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	head, readErr := readHTTPHead(conn)
	// The tunnel must not carry bytes: a CONNECT that was refused cannot have become a live tunnel.
	echoed := make([]byte, 0)
	if readErr == nil {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 16)
		read, _ := conn.Read(buffer)
		echoed = buffer[:read]
	}
	conn.Close()
	t.Logf("HTTP-CONNECT-A10 target=%s head=%q readErr=%v payloadAfterHead=%q", target, head, readErr, echoed)

	added := peer.awaitSince(mark, 600*time.Millisecond)
	flowsAfter := second.tracker.count()
	t.Logf("EGRESS-A10 %s flowsBefore=%d flowsAfter=%d",
		fipEgress("http-connect target="+target, 0x00, acceptsBefore, peer.acceptCount(), added),
		flowsBefore, flowsAfter)

	// The two load-bearing facts, and NEITHER of them is the status line. `serveConnect` writes 200
	// before the router sees the request (:110 writes, :114 hands off), so a 200 here is expected and
	// says nothing; what a refusal must produce is no peer request, no accepted connection, and no
	// routed flow - the connection must die before the route decision is even made.
	require.Empty(t, added,
		"the peer was asked for %v over HTTP CONNECT: the placeholder escaped on the second protocol "+
			"as well", added)
	require.Equal(t, acceptsBefore, peer.acceptCount(),
		"the peer accepted %d new connection(s) for a synthetic address", peer.acceptCount()-acceptsBefore)
	require.Equal(t, flowsBefore, flowsAfter,
		"the router recorded %d flow(s) for a CONNECT that must be refused before any dial: a "+
			"recorded flow means the destination was accepted as a route target", flowsAfter-flowsBefore)
	require.Empty(t, echoed,
		"the CONNECT tunnel carried %q: a tunnel that transfers bytes is a destination that was "+
			"reached, whatever the status line said", echoed)
}

// ---------------------------------------------------------------------------
// A11: generations must not pollute one another
// ---------------------------------------------------------------------------

// TestFIPConcurrentLookupsAfterARangeMoveNeverReturnTheOldRange is A11.
//
// The dangerous shape is not a wrong refusal - it is a STALE ANSWER: a store or cache that outlives
// the box that owned it would let a client receive an address from a generation that no longer
// exists, and that address is then dialled under a configuration that cannot map it. The row drives
// concurrent lookups through the NEW box and requires every answer to belong to the new range, with
// the old range appearing in none of them.
func TestFIPConcurrentLookupsAfterARangeMoveNeverReturnTheOldRange(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	cachePath := tempDir(t) + "\\fip-a11.db"

	root, wantLedger := fipReloadRootContext()

	first := startChainInContext(t, root, fipConfig{
		mixedPort: freePort(t), peer: peer, fakeIPRange: fipRangeCurrent, cacheFilePath: cachePath,
	}.json(), nil)
	firstIssued := fipAsk(t, first, "fip-owned.test", 1)
	t.Logf("A11 generation 1 issued=%s", firstIssued)
	require.Same(t, wantLedger, fipRouterLedger(t, first))
	require.NoError(t, first.closeNow())

	secondPort := freePort(t)
	second := startChainInContext(t, root, fipConfig{
		mixedPort: secondPort, peer: peer, fakeIPRange: fipRangeMoved, cacheFilePath: cachePath,
	}.json(), nil)
	t.Cleanup(func() { _ = second.closeNow() })

	// One query per goroutine through the box's own dns entry point, and every answer is kept so the
	// assertion is on the SET of answers rather than on one of them. `readDNSAddress` is called from
	// the goroutine on purpose: it fails the test itself if an answer is unusable.
	const lookups = 24
	names := []string{"fip-owned.test", "fip-second.test", "fip-third.test"}
	answers := make([]netip.Addr, lookups)
	var waitGroup sync.WaitGroup
	for index := 0; index < lookups; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			answers[index] = fipAsk(t, second, names[index%len(names)], 1)
		}(index)
	}
	waitGroup.Wait()

	movedPrefix := netip.MustParsePrefix(fipRangeMoved)
	currentPrefix := netip.MustParsePrefix(fipRangeCurrent)
	var fromNew, fromOld, other int
	for _, address := range answers {
		switch {
		case movedPrefix.Contains(address):
			fromNew++
		case currentPrefix.Contains(address):
			fromOld++
		default:
			other++
		}
	}
	t.Logf("A11 answers=%v newRange=%d oldRange=%d other=%d", answers, fromNew, fromOld, other)
	require.Zero(t, fromOld,
		"%d of %d answers came from the PREVIOUS generation's range: a stale issuance survived the "+
			"range move and would be dialled under a configuration that cannot map it", fromOld, lookups)
	require.Zero(t, other, "%d answers were not addresses from either range: %v", other, answers)
	require.Equal(t, lookups, fromNew, "every lookup must be answered from the new range")
}

// ---------------------------------------------------------------------------
// A12: repetition must not accumulate
// ---------------------------------------------------------------------------

// TestFIPRepeatedGenerationCyclesDoNotAccumulate is A12.
//
// The same Box shape is built and closed repeatedly, alternating the range between set and removed,
// which is the shape a device sees when a profile is switched back and forth. Two things are
// measured:
//
//  1. BOUNDEDNESS: heap objects after the first cycle versus after the last, read after a GC so the
//     number is live objects rather than pending collection. A per-cycle leak shows up as a multiple
//     of the cycle count.
//  2. OWNERSHIP: after the churn, a fresh Box on the same durable file must not treat a previous
//     Box's issuance as its own when the file is gone, and must not lose the ability to answer.
func TestFIPRepeatedGenerationCyclesDoNotAccumulate(t *testing.T) {
	backend := startEchoServer(t, "tcp", "127.0.0.1:0")
	peer := startFIPPeerSink(t, echoAddress(backend))
	cachePath := tempDir(t) + "\\fip-a12.db"

	cycle := func(index int, fakeIPRange string) {
		running := startChain(t, fipConfig{
			mixedPort: freePort(t), peer: peer, fakeIPRange: fakeIPRange, cacheFilePath: cachePath,
		}.json())
		if fakeIPRange != "" {
			issued := fipAsk(t, running, "fip-owned.test", 1)
			require.True(t, netip.MustParsePrefix(fakeIPRange).Contains(issued),
				"cycle %d must issue from its own range, got %s", index, issued)
		}
		require.NoError(t, running.closeNow(), "cycle %d must close cleanly", index)
	}

	const cycles = 12
	cycle(0, fipRangeCurrent)
	runtime.GC()
	var first runtime.MemStats
	runtime.ReadMemStats(&first)

	for index := 1; index <= cycles; index++ {
		if index%2 == 0 {
			cycle(index, "")
		} else {
			cycle(index, fipRangeMoved)
		}
	}
	runtime.GC()
	var last runtime.MemStats
	runtime.ReadMemStats(&last)

	objectsFirst := int64(first.HeapObjects)
	objectsLast := int64(last.HeapObjects)
	delta := objectsLast - objectsFirst
	perCycle := float64(delta) / float64(cycles)
	t.Logf("A12 cycles=%d heapObjects first=%d last=%d delta=%d perCycle=%.1f heapAlloc=%d->%d",
		cycles, objectsFirst, objectsLast, delta, perCycle, first.HeapAlloc, last.HeapAlloc)
	// The bound is stated rather than measured-as-zero: each cycle legitimately holds a Box's worth of
	// live objects until its GC sweep, and `startChain`'s retry loop can leave a discarded Box behind.
	// What a leak looks like here is tens of objects PER CYCLE, so one order of magnitude above that
	// is the line.
	require.Less(t, perCycle, 4096.0,
		"live heap objects grew by %.1f per cycle over %d build/close cycles (%d -> %d): state that "+
			"grows with the number of generations is state that never had an owner",
		perCycle, cycles, objectsFirst, objectsLast)

	// OWNERSHIP after the churn: a fresh Box with a range of its own must answer for that range, and
	// must not be confused by anything the previous generations left behind.
	finalPort := freePort(t)
	final := startChain(t, fipConfig{
		mixedPort: finalPort, peer: peer, fakeIPRange: fipRangeCurrent, cacheFilePath: cachePath,
	}.json())
	t.Cleanup(func() { _ = final.closeNow() })
	finalIssued := fipAsk(t, final, "fip-owned.test", 1)
	require.True(t, netip.MustParsePrefix(fipRangeCurrent).Contains(finalIssued),
		"after %d cycles the Box must still issue from its configured range, got %s", cycles, finalIssued)

	mark := peer.mark()
	conn, code := socks5Request(t, fipProxyAddress(finalPort), 0x01, finalIssued.String(), 443)
	added := peer.awaitSince(mark, 500*time.Millisecond)
	t.Logf("EGRESS-A12 %s", fipEgress("finalIssued="+finalIssued.String(), code, 0, peer.acceptCount(), added))
	require.Equal(t, byte(0x00), code, "and must still map its own address to the domain")
	if conn != nil {
		conn.Close()
	}
	fipRequireOwnedAddress(t, added, finalIssued, netip.MustParseAddr("127.0.0.1"))
	fipRequireMappedFlow(t, final, finalIssued, 443)
}
