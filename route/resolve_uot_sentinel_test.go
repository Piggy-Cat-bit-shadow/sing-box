package route

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// UoT protocol sentinels must never be resolved as sniffed domains.
//
// # How a sentinel reaches the resolver
//
// The Native Naive inbound wraps its router in common/uot.Router, which recognises the UoT magic
// address, reads the session header, and then rewrites the metadata:
//
//	metadata.Domain      = metadata.Destination.Fqdn   // the magic sentinel
//	metadata.Destination = request.Destination         // the real target
//
// Keeping the sentinel in Domain is deliberate - it records the provenance of the flow - but the
// destination is now an IP, and the `resolve` route action recovers a destination from
// metadata.Domain for exactly that shape. The sentinel is a well-formed FQDN, so nothing about it
// looks wrong to validSniffedDomain, and the resolver is asked for it.
//
// The lookup cannot succeed. sp.v2.udp-over-tcp.arpa is not a real name, so the query runs to its
// timeout, and the flow is abandoned before the target ACL it exists to exercise is ever consulted.

// sentinelResolveMetadata builds the metadata shape that exists immediately after a UoT unwrap.
func sentinelResolveMetadata(sentinel string, destination M.Socksaddr) adapter.InboundContext {
	metadata := adapter.InboundContext{}
	metadata.Domain = sentinel
	metadata.Destination = destination
	return metadata
}

// TestResolveLookupNameExcludesUoTSentinels is the focused regression.
func TestResolveLookupNameExcludesUoTSentinels(t *testing.T) {
	sentinels := map[string]string{
		"v2 magic address":  uot.MagicAddress,
		"v1 legacy address": uot.LegacyMagicAddress,
	}

	for name, sentinel := range sentinels {
		t.Run(name, func(t *testing.T) {
			// An IP destination is what a UoT unwrap produces, and it is the shape that makes the
			// resolver reach for metadata.Domain.
			metadata := sentinelResolveMetadata(sentinel, M.ParseSocksaddr("93.184.216.34:443"))

			require.Empty(t, resolveLookupName(&metadata),
				"the UoT sentinel %q was returned as a name to resolve. It is a protocol marker, "+
					"not an application domain: the lookup cannot succeed, and the flow is abandoned "+
					"on a DNS timeout before the target policy is ever consulted", sentinel)
		})
	}
}

// TestResolveLookupNameStillRecoversGenuineSniffedDomains guards the fix 4ca74d69f made.
//
// That change lets an IP destination reuse a sniffed domain so dual-stack recovery can plan against
// the real name. Excluding the sentinels must not disable it: a genuine application domain is not a
// protocol marker, and dropping it would reintroduce the recovery bug that fix removed.
func TestResolveLookupNameStillRecoversGenuineSniffedDomains(t *testing.T) {
	// The literal-IP-with-sniffed-domain shape that 4ca74d69f introduced this for.
	metadata := sentinelResolveMetadata("example.com", M.ParseSocksaddr("2001:db8::1:443"))

	require.Equal(t, "example.com", resolveLookupName(&metadata),
		"a genuine sniffed domain must still be recovered for an IP destination. Disabling that "+
			"would revert 4ca74d69f and bring back the dual-stack recovery failure it fixed")

	// And the other two shapes are unaffected.
	domainDestination := adapter.InboundContext{}
	domainDestination.Destination = M.ParseSocksaddr("example.com:443")
	require.Equal(t, "example.com", resolveLookupName(&domainDestination),
		"a domain destination is resolved as itself")

	plainIP := adapter.InboundContext{}
	plainIP.Destination = M.ParseSocksaddr("93.184.216.34:443")
	require.Empty(t, resolveLookupName(&plainIP),
		"an IP destination with no sniffed domain has nothing to resolve")
}

// TestResolveLookupNameExcludesSentinelsForIPv6Too covers the unspecified-IP shape legacy UoT uses.
//
// A legacy UoT session has no request destination at all, so common/uot leaves an unspecified IPv4
// address behind. That is still an IP destination, so the same recovery path is taken.
func TestResolveLookupNameExcludesSentinelsForIPv6Too(t *testing.T) {
	unspecified := adapter.InboundContext{}
	unspecified.Domain = uot.LegacyMagicAddress
	unspecified.Destination = M.Socksaddr{Addr: netip.IPv4Unspecified()}

	require.Empty(t, resolveLookupName(&unspecified),
		"the legacy UoT sentinel must not be resolved either. The legacy session leaves an "+
			"unspecified address as its destination, which is exactly the IP shape that triggers "+
			"sniffed-domain recovery")
}
