package adapter

import (
	"net/netip"
	"sync"
	"testing"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// JudgeFlow is the boundary every flow decision passes through, including the Linux nfqueue one whose
// packets are parsed from the wire exactly like a TUN's. This pins what it hands the router.
//
// # Why the boundary owns this
//
// A v4-mapped IPv6 address is an IPv4 address written in sixteen bytes, and every comparison the router
// makes is written against the four-byte form: route rules match addresses against CIDR sets, FakeIP
// ranges are four-byte prefixes, DNS addresses are four-byte literals. `netip.Prefix.Contains` and
// `netipx.IPSet.Contains` both return false for the mapped spelling of an address they contain, so an
// address that arrives mapped matches nothing and fails every one of those comparisons silently.
//
// The test asserts on the metadata the ROUTER received rather than on the return value, because the
// return value would be the same either way.

type recordingMetadataRouter struct {
	Router
	access sync.Mutex
	seen   []InboundContext
}

func (r *recordingMetadataRouter) PreMatch(metadata InboundContext, firstPacket []byte) PreMatchResult {
	r.access.Lock()
	r.seen = append(r.seen, metadata)
	r.access.Unlock()
	return PreMatchResult{Action: PreMatchContinue}
}

func (r *recordingMetadataRouter) destinations() []M.Socksaddr {
	r.access.Lock()
	defer r.access.Unlock()
	destinations := make([]M.Socksaddr, 0, len(r.seen))
	for _, metadata := range r.seen {
		destinations = append(destinations, metadata.Destination)
	}
	return destinations
}

func TestJudgeFlowHandsTheRouterACanonicalDestination(t *testing.T) {
	four := netip.MustParseAddr("10.0.0.53")
	mapped := netip.AddrFrom16(four.As16())
	source := netip.MustParseAddrPort("198.18.0.2:40000")

	require.True(t, mapped.Is4In6(), "the fixture must actually be the mapped form")

	router := &recordingMetadataRouter{}
	verdict := JudgeFlow(router, InboundContext{}, uint8(header.TCPProtocolNumber), source,
		netip.AddrPortFrom(mapped, 53), nil)

	require.Equal(t, tun.ActionAccept, verdict.Action, "a continuing verdict is what a stub router produces")
	require.Len(t, router.destinations(), 1, "the router must have been consulted at all")
	require.Equal(t, M.SocksaddrFromNetIP(netip.AddrPortFrom(four, 53)), router.destinations()[0],
		"the router must see the four-byte form, or every CIDR-set comparison it makes fails silently")

	// The control: the four-byte form arrives unchanged, so the assertion above is about
	// canonicalisation rather than about the metadata being rewritten in general.
	router = &recordingMetadataRouter{}
	JudgeFlow(router, InboundContext{}, uint8(header.TCPProtocolNumber), source,
		netip.AddrPortFrom(four, 53), nil)
	require.Equal(t, M.SocksaddrFromNetIP(netip.AddrPortFrom(four, 53)), router.destinations()[0])

	// An IPv6 flow is untouched, so the canonicalisation cannot be mistaken for a family rewrite.
	router = &recordingMetadataRouter{}
	global6 := netip.MustParseAddrPort("[2606:2800:220:1:248:1893:25c8:1946]:443")
	JudgeFlow(router, InboundContext{}, uint8(header.TCPProtocolNumber),
		netip.MustParseAddrPort("[fd73:ab91:1::2]:40000"), global6, nil)
	require.Equal(t, M.SocksaddrFromNetIP(global6), router.destinations()[0])
}
