package route

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for dual-stack candidate recovery in actionResolve (§76, §77).
//
// The failure being fixed: a TUN client has usually already resolved the name and connects
// to an address, so Destination is a literal. The action used to resolve only when
// Destination was a domain, so it did nothing - even when sniffing had recovered the domain.
// The connection then had exactly one candidate, and a broken path for that family had
// nothing to fall back to.

func TestResolveLookupNameUsesSniffedDomainForLiteralDestination(t *testing.T) {
	metadata := &adapter.InboundContext{
		Destination: M.ParseSocksaddr("[240e:1::1]:443"),
		Domain:      "example.test",
	}
	require.Equal(t, "example.test", resolveLookupName(metadata),
		"a literal destination with a sniffed domain must be resolvable")
}

func TestResolveLookupNamePrefersAnActualDomainDestination(t *testing.T) {
	metadata := &adapter.InboundContext{
		Destination: M.ParseSocksaddr("example.test:443"),
		Domain:      "other.test",
	}
	require.Equal(t, "example.test", resolveLookupName(metadata),
		"a domain destination resolves directly; the sniffed value is only a fallback source")
}

func TestResolveLookupNameWithoutUsableDomain(t *testing.T) {
	cases := []struct {
		name     string
		metadata *adapter.InboundContext
	}{
		{"IP destination, no sniffed domain", &adapter.InboundContext{
			Destination: M.ParseSocksaddr("[240e:1::1]:443"),
		}},
		{"IP destination, empty domain", &adapter.InboundContext{
			Destination: M.ParseSocksaddr("[240e:1::1]:443"),
			Domain:      "",
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Empty(t, resolveLookupName(testCase.metadata),
				"with no usable name there is nothing to resolve")
		})
	}
}

func TestValidSniffedDomainRejectsUnusableValues(t *testing.T) {
	// A sniffed domain is attacker-influenced: it is derived from bytes the remote peer
	// chose, and it is about to be handed to a resolver. Anything malformed is refused
	// rather than resolved.
	rejected := []struct {
		name   string
		domain string
	}{
		{"empty", ""},
		{"IP literal", "192.0.2.1"},
		{"IPv6 literal", "240e:1::1"},
		{"NUL byte", "exa\x00mple.test"},
		{"space", "exa mple.test"},
		{"newline", "example.test\n"},
		{"path separator", "example.test/path"},
		{"over-long", string(make([]byte, 300))},
		{"leading dot", ".example.test"},
		{"trailing dot only", "."},
		{"double dot", "example..test"},
		{"bare hostname", "localhost"},
		{"label too long", string(make([]byte, 64)) + ".test"},
	}
	for _, testCase := range rejected {
		t.Run(testCase.name, func(t *testing.T) {
			require.Empty(t, validSniffedDomain(testCase.domain),
				"a malformed sniffed domain must be refused")
		})
	}

	accepted := map[string]string{
		"example.test":     "example.test",
		"www.example.test": "www.example.test",
		"example.test.":    "example.test",
		"a-b.example.test": "a-b.example.test",
		"1.2.example.test": "1.2.example.test",
	}
	for input, expected := range accepted {
		t.Run("accept "+input, func(t *testing.T) {
			require.Equal(t, expected, validSniffedDomain(input))
		})
	}
}

func TestMergeOriginalDestinationKeepsTheOriginal(t *testing.T) {
	// The resolved set may not contain the address the client chose - a CDN answering
	// differently per query, a split-horizon resolver, or a cached mapping. Dropping it
	// would discard a destination the client can demonstrably reach.
	original := M.ParseSocksaddr("[240e:1::1]:443")
	resolved := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	}
	merged := mergeOriginalDestination(original, resolved, C.DomainStrategyAsIS)

	require.Contains(t, merged, netip.MustParseAddr("240e:1::1"),
		"the original destination must remain a candidate")
}

func TestMergeOriginalDestinationDoesNotDuplicate(t *testing.T) {
	original := M.ParseSocksaddr("[2001:db8::1]:443")
	resolved := []netip.Addr{netip.MustParseAddr("2001:db8::1")}
	merged := mergeOriginalDestination(original, resolved, C.DomainStrategyPreferIPv6)

	count := 0
	for _, address := range merged {
		if address == netip.MustParseAddr("2001:db8::1") {
			count++
		}
	}
	require.Equal(t, 1, count, "an already-resolved original must not be added twice")
}

func TestMergeOriginalDestinationPreservesFamilyPreference(t *testing.T) {
	// The rule that keeps a recovery from overruling the configuration: an IPv6 original
	// must not drag the plan to IPv6 when the strategy prefers IPv4.
	original := M.ParseSocksaddr("[240e:1::1]:443")
	resolved := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	}

	merged := mergeOriginalDestination(original, resolved, C.DomainStrategyPreferIPv4)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), merged[0],
		"prefer_ipv4 must still lead with IPv4 even when the original is IPv6")

	merged6 := mergeOriginalDestination(original, resolved, C.DomainStrategyPreferIPv6)
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), merged6[0],
		"prefer_ipv6 must lead with IPv6")
}

func TestMergeOriginalDestinationHonoursHardStrategies(t *testing.T) {
	// "only" means only. A strict strategy must not admit the other family even as the
	// address the client actually chose.
	original6 := M.ParseSocksaddr("[240e:1::1]:443")
	resolved := []netip.Addr{netip.MustParseAddr("192.0.2.1")}

	merged := mergeOriginalDestination(original6, resolved, C.DomainStrategyIPv4Only)
	for _, address := range merged {
		require.False(t, address.Is6() && !address.Is4In6(),
			"ipv4_only must not emit an IPv6 candidate, not even the original: %v", address)
	}

	original4 := M.ParseSocksaddr("192.0.2.9:443")
	resolved6 := []netip.Addr{netip.MustParseAddr("2001:db8::1")}
	merged6 := mergeOriginalDestination(original4, resolved6, C.DomainStrategyIPv6Only)
	for _, address := range merged6 {
		require.False(t, address.Is4(),
			"ipv6_only must not emit an IPv4 candidate, not even the original: %v", address)
	}
}

func TestMergeOriginalDestinationLeavesDomainDestinationsAlone(t *testing.T) {
	// A domain destination has no address to merge; the resolved list is the whole answer.
	resolved := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	merged := mergeOriginalDestination(M.ParseSocksaddr("example.test:443"), resolved, C.DomainStrategyAsIS)
	require.Equal(t, resolved, merged)
}
