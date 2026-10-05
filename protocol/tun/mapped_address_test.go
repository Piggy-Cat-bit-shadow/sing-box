package tun

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

// A v4-mapped IPv6 destination is an IPv4 address written in sixteen bytes, and every policy
// comparison in this file is written against the four-byte form.
//
// # Why this needs its own tests rather than one
//
// The bug reported a different symptom in each layer, and all three symptoms are "policy silently did
// not apply":
//
//	DNS address hijack   the query was not hijacked, so it left the DNS policy path entirely
//	FakeIP L0 guard      the guard did not fire, so a placeholder was handed to the platform
//	route address sets   a route set did not contain its own address, so the wrong verdict was reached
//
// They share one cause - the address was never canonicalised at the boundary - so they are fixed in
// one place, and each is asserted separately because a fix that covered only one of them would look
// correct from the other two.
//
// # Reachability
//
// These are wire forms, not constructed ones: the packets below are built with the sixteen-byte
// destination in the IPv6 header and pushed through the real stack harness in
// native_bypass_trace_test.go, which parses them exactly as sing-tun does. A dual-stack application
// reaching 10.0.0.53 as ::ffff:10.0.0.53 is the ordinary case this protects.

func mappedAddr(address netip.Addr) netip.Addr { return netip.AddrFrom16(address.As16()) }

func mappedAddrPort(address netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(mappedAddr(address.Addr()), address.Port())
}

// hijackTestInboundFor returns an inbound wired to a router that records what it is asked and that
// never bypasses, so "the router was consulted" and "the flow was bypassed" cannot be confused.
func hijackTestInboundFor(t *testing.T, dnsAddress []netip.Addr, byPort bool) (*Inbound, *bypassPreferringRouter) {
	t.Helper()
	router := newBypassPreferringRouter()
	router.bypassable.Store(false)
	return &Inbound{
		tag:              "tun-in",
		ctx:              context.Background(),
		router:           router,
		logger:           log.NewNOPFactory().Logger(),
		dnsHijackAddress: dnsAddress,
		dnsHijackByPort:  byPort,
	}, router
}

// TestMappedDnsAddressIsHijacked pins the DNS half.
func TestMappedDnsAddressIsHijacked(t *testing.T) {
	dnsAddress := netip.MustParseAddr("10.0.0.53")
	inbound, _ := hijackTestInboundFor(t, []netip.Addr{dnsAddress}, false)

	for _, testCase := range []struct {
		name        string
		destination netip.AddrPort
		packet      []byte
	}{
		{
			name:        "four-byte",
			destination: netip.AddrPortFrom(dnsAddress, 53),
			packet: func() []byte {
				return udpDatagram(netip.MustParseAddrPort("198.18.0.2:40000"),
					netip.AddrPortFrom(dnsAddress, 53), []byte("query"))
			}(),
		},
		{
			name:        "v4-mapped",
			destination: mappedAddrPort(netip.AddrPortFrom(dnsAddress, 53)),
			packet: func() []byte {
				return udpDatagramV6(netip.MustParseAddrPort("[fd73:ab91:1::2]:40000"),
					mappedAddrPort(netip.AddrPortFrom(dnsAddress, 53)), []byte("query"))
			}(),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			// Through the real parser and the real stack: the packet's own header decides the
			// destination, so the test cannot pass by constructing the address it wants to see.
			handler := handlerFor(inbound)
			harness := newMemoryTunHarness(t, handler)
			harness.inject(t, testCase.packet)

			verdicts := awaitVerdicts(t, handler, 1)
			require.Equal(t, tun.ActionHijackDNS, verdicts[0].Action,
				"a query to the configured DNS address must be hijacked in every form it can arrive "+
					"in, and this is the verdict the stack received for the packet that was injected")

			// The same input judged directly, so a failure says whether the decision or the delivery
			// is at fault.
			verdict := inbound.JudgeFlow(uint8(header.UDPProtocolNumber), netip.MustParseAddrPort("198.18.0.2:40000"), testCase.destination, nil)
			require.Equal(t, tun.ActionHijackDNS, verdict.Action)
		})
	}

	// And the TCP half, which is ACCEPTED at the flow level so the stream DNS path takes over. The
	// same comparison decides it, so the same input must not be bypassed there either.
	tcpInbound, _ := hijackTestInboundFor(t, []netip.Addr{dnsAddress}, false)
	for _, destination := range []netip.AddrPort{
		netip.AddrPortFrom(dnsAddress, 53),
		mappedAddrPort(netip.AddrPortFrom(dnsAddress, 53)),
	} {
		verdict := tcpInbound.JudgeFlow(uint8(header.TCPProtocolNumber), netip.MustParseAddrPort("198.18.0.2:40000"), destination, nil)
		require.Equal(t, tun.ActionAccept, verdict.Action,
			"TCP to a configured DNS address is accepted so the stream path can hijack it, never bypassed")
	}

	// The userspace entry point makes the same decision, and it is the one that actually carries a
	// real connection.
	for _, destination := range []netip.AddrPort{
		netip.AddrPortFrom(dnsAddress, 53),
		mappedAddrPort(netip.AddrPortFrom(dnsAddress, 53)),
	} {
		require.True(t, tcpInbound.isDNSHijackDestination(M.SocksaddrFromNetIP(destination)),
			"the connection path must recognise the DNS address in both forms")
	}
}

// TestMappedFakeIPIsStillGuardedFromTheRouteSets pins the FakeIP half.
//
// The include-set configuration is the one where the missing canonicalisation fails OPEN: an address
// outside an include set is bypassed, and a mapped address is outside every set written in four-byte
// form - so without the fix a FakeIP placeholder reaches the platform's routing table.
func TestMappedFakeIPIsStillGuardedFromTheRouteSets(t *testing.T) {
	fakeIP := netip.MustParseAddr("198.18.0.5")
	mapped := mappedAddr(fakeIP)

	for _, testCase := range []struct {
		name        string
		destination netip.Addr
		packet      []byte
	}{
		{
			name:        "four-byte",
			destination: fakeIP,
			packet: udpDatagram(netip.MustParseAddrPort("198.18.0.2:40000"),
				netip.AddrPortFrom(fakeIP, 443), []byte("x")),
		},
		{
			name:        "v4-mapped",
			destination: mapped,
			packet: udpDatagramV6(netip.MustParseAddrPort("[fd73:ab91:1::2]:40000"),
				netip.AddrPortFrom(mapped, 443), []byte("x")),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			inbound, router := hijackTestInboundFor(t, nil, false)
			inbound.fakeIPStore = &fakeIPStoreStub{inet4: netip.MustParsePrefix("198.18.0.0/15")}
			// An include set that cannot contain the placeholder in either spelling: without the
			// guard, "outside the set" means bypass.
			inbound.routeAddressSet = []*netipx.IPSet{ipSetFrom(t, "10.0.0.0/8")}

			harness := newTraceHandler(func(network uint8, source, destination netip.AddrPort) tun.FlowVerdict {
				return inbound.JudgeFlow(network, source, destination, nil)
			})
			memoryHarness := newMemoryTunHarness(t, harness)
			memoryHarness.inject(t, testCase.packet)
			verdicts := awaitVerdicts(t, harness, 1)
			require.NotEqual(t, tun.ActionBypass, verdicts[0].Action,
				"a FakeIP placeholder must reach the router so the domain can be recovered, in every "+
					"form it can arrive in")
			require.EqualValues(t, 1, router.preMatchCalls.Load(),
				"and the router is where the FakeIP policy lives")
		})
	}
}

// TestMappedDestinationReachesTheRouteSets pins the third symptom, which is the widest one: a route
// set that does not contain its own address makes every address-based decision wrong in whichever
// direction the set was written.
func TestMappedDestinationReachesTheRouteSets(t *testing.T) {
	inbound, router := hijackTestInboundFor(t, nil, false)
	inbound.routeExcludeAddressSet = []*netipx.IPSet{ipSetFrom(t, "198.16.0.0/12")}

	excluded := netip.MustParseAddr("198.20.0.5")
	for _, testCase := range []struct {
		name        string
		destination netip.AddrPort
	}{
		{"four-byte", netip.AddrPortFrom(excluded, 443)},
		{"v4-mapped", netip.AddrPortFrom(mappedAddr(excluded), 443)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			router.preMatchCalls.Store(0)
			verdict := inbound.JudgeFlow(uint8(header.TCPProtocolNumber),
				netip.MustParseAddrPort("198.18.0.2:40000"), testCase.destination, nil)
			require.Equal(t, tun.ActionBypass, verdict.Action,
				"an address in the exclude set is bypassed by the route sets in every form")
			require.EqualValues(t, 0, router.preMatchCalls.Load(),
				"without consulting the router, which is the point of the layer")
		})
	}
}

// TestMappedDestinationReachesTheRouterCanonical is the fourth symptom, and the one no single
// comparison owns: the metadata the ROUTER sees must be canonical, or every rule matching an
// address against a CIDR set fails silently.
func TestMappedDestinationReachesTheRouterCanonical(t *testing.T) {
	inbound, router := hijackTestInboundFor(t, nil, false)
	unmapped := netip.MustParseAddrPort("93.184.216.34:443")
	mapped := netip.AddrPortFrom(mappedAddr(unmapped.Addr()), unmapped.Port())

	// Two paths reach the router and both are asserted, because they are separate call sites: the
	// flow-level verdict and the userspace connection the TUN stack creates for a direct flow.
	verdict := inbound.JudgeFlow(uint8(header.UDPProtocolNumber),
		netip.MustParseAddrPort("198.18.0.2:40000"), mapped, nil)
	require.NotEqual(t, tun.ActionBypass, verdict.Action)
	recorded := router.lastDestination.Load()
	require.NotNil(t, recorded)
	require.Equal(t, unmapped, *recorded,
		"the flow path must hand the router the four-byte form, or a route rule written as a CIDR set "+
			"matches nothing")

	router.lastDestination.Store(nil)
	harness := newMemoryTunHarness(t, handlerFor(inbound))
	harness.inject(t, udpDatagramV6(netip.MustParseAddrPort("[fd73:ab91:1::2]:40000"), mapped, []byte("x")))
	harness.waitForAccepted(t)
	recorded = router.lastDestination.Load()
	require.NotNil(t, recorded)
	require.Equal(t, unmapped, *recorded,
		"and so must the userspace connection path, which is the one that actually carries a real flow")
}

// awaitVerdicts waits until the handler has produced at least `count` verdicts.
//
// A hijacked or rejected packet is CONSUMED by the dispatcher, so "a userspace connection appeared"
// is not a signal that can be waited on for those verdicts; the verdict itself is.
func awaitVerdicts(t *testing.T, handler *traceHandler, count int) []tun.FlowVerdict {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if verdicts := handler.verdictsSeen(); len(verdicts) >= count {
			return verdicts
		}
		time.Sleep(5 * time.Millisecond)
	}
	verdicts := handler.verdictsSeen()
	t.Fatalf("the packet never reached a verdict: got %d, want %d", len(verdicts), count)
	return nil
}

// handlerFor runs the real TUN inbound behind the stack, so the packet's own bytes decide what the
// inbound is asked about.
func handlerFor(inbound *Inbound) *traceHandler {
	return newTraceHandler(func(network uint8, source, destination netip.AddrPort) tun.FlowVerdict {
		return inbound.JudgeFlow(network, source, destination, nil)
	})
}

// TestOnlyV4MappedAddressesAreCanonicalised is the negative control for the boundary.
//
// Canonicalising at ingress is only safe because it is restricted to one wire form. Inet4-in-6
// (::ffff:a.b.c.d) denotes the IPv4 address; nothing else does, and two other families look like
// candidates to a broader predicate:
//
//	NAT64 (64:ff9b::/96)          a routable IPv6 prefix that CARRIES an IPv4 address
//	IPv4-compatible (::a.b.c.d)   the deprecated form, and not the mapped one
//
// Unmapping a NAT64 destination would turn a routable IPv6 address into an IPv4 address that is not
// where the packet was going, so the connection would be dialed somewhere else entirely - and the
// route rules, FakeIP ranges and DNS policies written against 64:ff9b::/96 would stop matching. A
// predicate that asked "does this address embed an IPv4 address" instead of "is this the mapped
// form" would do exactly that, which is what this test exists to prevent.
func TestOnlyV4MappedAddressesAreCanonicalised(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		destination netip.AddrPort
		want        netip.Addr
		wantMapped  bool
	}{
		{
			name:        "mapped v4 is unmapped",
			destination: netip.MustParseAddrPort("[::ffff:192.0.2.1]:443"),
			want:        netip.MustParseAddr("192.0.2.1"),
		},
		{
			name:        "a plain v4 address is already canonical",
			destination: netip.MustParseAddrPort("192.0.2.1:443"),
			want:        netip.MustParseAddr("192.0.2.1"),
		},
		{
			name:        "NAT64 stays IPv6",
			destination: netip.MustParseAddrPort("[64:ff9b::c000:201]:443"),
			want:        netip.MustParseAddr("64:ff9b::c000:201"),
			wantMapped:  true,
		},
		{
			name:        "the well-known NAT64 prefix itself stays IPv6",
			destination: netip.MustParseAddrPort("[64:ff9b::1]:53"),
			want:        netip.MustParseAddr("64:ff9b::1"),
			wantMapped:  true,
		},
		{
			name:        "IPv4-compatible is not the mapped form",
			destination: netip.MustParseAddrPort("[::192.0.2.1]:443"),
			want:        netip.MustParseAddr("::192.0.2.1"),
			wantMapped:  true,
		},
		{
			name:        "an ordinary global IPv6 address is untouched",
			destination: netip.MustParseAddrPort("[2001:db8::1]:443"),
			want:        netip.MustParseAddr("2001:db8::1"),
			wantMapped:  true,
		},
		{
			name:        "the port is never touched",
			destination: netip.MustParseAddrPort("[64:ff9b::c000:201]:8443"),
			want:        netip.MustParseAddr("64:ff9b::c000:201"),
			wantMapped:  true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := canonicalAddrPort(testCase.destination)
			require.Equal(t, testCase.want, got.Addr(), "canonicalAddrPort")
			require.Equal(t, testCase.destination.Port(), got.Port(), "the port must survive")

			// The same predicate has to answer the same way for the userspace entry points, which
			// take a Socksaddr rather than an AddrPort. Two implementations of one rule is how a
			// boundary stops being one boundary.
			canonical := canonicalSocksaddr(M.SocksaddrFrom(testCase.destination.Addr(), testCase.destination.Port()))
			require.Equal(t, got.Addr(), canonical.Addr, "canonicalSocksaddr must agree with canonicalAddrPort")
			require.Equal(t, testCase.destination.Port(), canonical.Port)

			// No mapped form may survive canonicalisation, and no non-mapped form may lose its
			// family: the two assertions together are the whole rule.
			require.False(t, canonical.Addr.Is4In6(),
				"nothing that is still mapped may pass the boundary")
			for _, address := range []netip.Addr{got.Addr()} {
				if testCase.wantMapped {
					require.True(t, address.Is6() && !address.Is4(),
						"%s denotes an IPv6 destination and must stay one", address)
				}
			}
		})
	}
}

// TestNAT64DestinationReachesTheRouterUnchanged is the same boundary through the real packet path.
//
// The unit test above pins the predicate; this one proves the packet path actually uses it and that
// a NAT64 destination arrives at the router as the IPv6 address the application dialed - the failure
// the unit test cannot see, because a caller could canonicalise with a different predicate.
func TestNAT64DestinationReachesTheRouterUnchanged(t *testing.T) {
	inbound, router := hijackTestInboundFor(t, nil, false)
	harness := newMemoryTunHarness(t, handlerFor(inbound))

	nat64 := netip.MustParseAddr("64:ff9b::c000:201")
	harness.inject(t, udpDatagramV6(netip.MustParseAddrPort("[fd73:ab91:1::2]:40000"), netip.AddrPortFrom(nat64, 443), []byte("x")))
	harness.waitForAccepted(t)

	recorded := router.lastDestination.Load()
	require.NotNil(t, recorded, "the connection must reach the router")
	require.Equal(t, nat64, recorded.Addr(),
		"a NAT64 destination is not a v4-mapped one: unmapping it would dial 192.0.2.1 instead")
	require.True(t, recorded.Addr().Is6(), "and it must still be an IPv6 address")
	require.False(t, recorded.Addr().Is4In6())
}
