package dialer

import (
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// Tests for dual-stack candidate planning (§68, §69, §70, §8, §94).
//
// These are pure ordering tests: no network, no timing. They pin the shape of a plan so the
// scheduler built on top cannot quietly change which address is attempted first.

func mustAddr(t *testing.T, value string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(value)
	require.NoError(t, err, "test fixture address %q", value)
	return address
}

func planStrings(plan candidatePlan) []string {
	values := make([]string, len(plan.candidates))
	for i, candidate := range plan.candidates {
		values[i] = candidate.address.String()
	}
	return values
}

func TestPlanCandidatesInterleavesFamilies(t *testing.T) {
	// The ordering requirement from RFC 8305 style racing: the first candidate of the
	// non-preferred family is attempted early, not after every preferred-family address.
	// Family blocks would make one unreachable address cost the whole family's timeout.
	v6a := mustAddr(t, "2001:db8::1")
	v6b := mustAddr(t, "2001:db8::2")
	v6c := mustAddr(t, "2001:db8::3")
	v4a := mustAddr(t, "192.0.2.1")
	v4b := mustAddr(t, "192.0.2.2")

	cases := []struct {
		name     string
		strategy C.DomainStrategy
		want     []string
	}{
		{
			name:     "prefer IPv6",
			strategy: C.DomainStrategyPreferIPv6,
			want:     []string{v6a.String(), v4a.String(), v6b.String(), v4b.String(), v6c.String()},
		},
		{
			name:     "prefer IPv4",
			strategy: C.DomainStrategyPreferIPv4,
			want:     []string{v4a.String(), v6a.String(), v4b.String(), v6b.String(), v6c.String()},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// The input is deliberately grouped by family, as sortAddresses produces it.
			var input []netip.Addr
			if testCase.strategy == C.DomainStrategyPreferIPv6 {
				input = []netip.Addr{v6a, v6b, v6c, v4a, v4b}
			} else {
				input = []netip.Addr{v4a, v4b, v6a, v6b, v6c}
			}
			plan := planCandidates(input, netip.Addr{}, testCase.strategy)
			require.Equal(t, testCase.want, planStrings(plan))
		})
	}
}

func TestPlanCandidatesDeduplicates(t *testing.T) {
	// Every address appears exactly once, however many times the input repeats it.
	v6a := mustAddr(t, "2001:db8::1")
	v4a := mustAddr(t, "192.0.2.1")
	plan := planCandidates(
		[]netip.Addr{v6a, v4a, v6a, v4a, v6a},
		netip.Addr{},
		C.DomainStrategyPreferIPv6,
	)
	require.Equal(t, []string{v6a.String(), v4a.String()}, planStrings(plan))
}

func TestPlanCandidatesTreatsMappedIPv4AsIPv4(t *testing.T) {
	// ::ffff:192.0.2.1 is an IPv4 address in IPv6 notation. Classifying it as IPv6 would
	// attempt an IPv4 destination over the IPv6 stack, which cannot work - and the failure
	// would be misread as an IPv6 problem.
	mapped := mustAddr(t, "::ffff:192.0.2.1")
	plain := mustAddr(t, "192.0.2.1")

	plan := planCandidates([]netip.Addr{mapped}, netip.Addr{}, C.DomainStrategyPreferIPv6)
	require.Equal(t, []string{plain.String()}, planStrings(plan), "the mapped form must be canonicalised")

	// And a mapped address must deduplicate against its plain form.
	plan = planCandidates([]netip.Addr{mapped, plain}, netip.Addr{}, C.DomainStrategyPreferIPv6)
	require.Len(t, plan.candidates, 1, "the mapped and plain forms are one destination")
}

func TestPlanCandidatesDropsInvalidAddresses(t *testing.T) {
	// An invalid address cannot be dialled; attempting it produces a confusing error rather
	// than a fallback.
	v4a := mustAddr(t, "192.0.2.1")
	plan := planCandidates([]netip.Addr{{}, v4a}, netip.Addr{}, C.DomainStrategyPreferIPv4)
	require.Equal(t, []string{v4a.String()}, planStrings(plan))
}

func TestPlanCandidatesHardStrategiesStaySingleFamily(t *testing.T) {
	// "only" means only. A strict strategy must not admit the other family even when the
	// original destination was in it, or a preference would silently become a policy.
	v6a := mustAddr(t, "2001:db8::1")
	v4a := mustAddr(t, "192.0.2.1")

	ipv4Only := planCandidates([]netip.Addr{v6a, v4a}, v6a, C.DomainStrategyIPv4Only)
	require.Equal(t, []string{v4a.String()}, planStrings(ipv4Only),
		"ipv4_only must not admit IPv6 candidates, not even the original destination")

	ipv6Only := planCandidates([]netip.Addr{v6a, v4a}, v4a, C.DomainStrategyIPv6Only)
	require.Equal(t, []string{v6a.String()}, planStrings(ipv6Only),
		"ipv6_only must not admit IPv4 candidates")
}

func TestPlanCandidatesIncludesOriginalDestinationInItsFamily(t *testing.T) {
	// The recovery case: the application chose an IPv6 literal, DNS returned both families.
	// The original must remain a candidate, placed in its own family at that family's end
	// so the resolver's ordering stays authoritative.
	original := mustAddr(t, "240e:1::1")
	v6a := mustAddr(t, "2001:db8::1")
	v4a := mustAddr(t, "192.0.2.1")

	// IPv6 leads (the original's family), and the original sits at the END of its family
	// rather than ahead of the resolved addresses: the resolver's ordering is authoritative
	// within a family, and the original is a recovery candidate, not a preferred one.
	plan := planCandidates([]netip.Addr{v4a, v6a}, original, C.DomainStrategyAsIS)
	require.Equal(t,
		[]string{v6a.String(), v4a.String(), original.String()},
		planStrings(plan),
		"AsIS keeps the original's family first, with the original appended within it")
}

func TestPlanCandidatesDoesNotDuplicateTheOriginal(t *testing.T) {
	// When DNS already returns the original address, it must not be added a second time as
	// a recovery candidate.
	original := mustAddr(t, "2001:db8::1")
	plan := planCandidates([]netip.Addr{original, mustAddr(t, "192.0.2.1")}, original, C.DomainStrategyPreferIPv6)

	count := 0
	for _, candidate := range plan.candidates {
		if candidate.address == original {
			count++
		}
	}
	require.Equal(t, 1, count, "the original must appear exactly once")
}

func TestPlanCandidatesAsISPrefersTheOriginalFamily(t *testing.T) {
	// With no explicit preference, a recovery must not overrule the application's own
	// choice. The IPv6 original means IPv6 leads.
	original := mustAddr(t, "240e:1::1")
	v4a := mustAddr(t, "192.0.2.1")
	v6a := mustAddr(t, "2001:db8::1")

	plan := planCandidates([]netip.Addr{v4a, v6a}, original, C.DomainStrategyAsIS)
	require.True(t, plan.preferIPv6, "an IPv6 original must lead under AsIS")
	require.Equal(t, familyIPv6, plan.candidates[0].family,
		"the first candidate must be from the original's family")

	// The mirror: an IPv4 original leads.
	original4 := mustAddr(t, "192.0.2.9")
	plan4 := planCandidates([]netip.Addr{v6a, v4a}, original4, C.DomainStrategyAsIS)
	require.False(t, plan4.preferIPv6, "an IPv4 original must lead under AsIS")
	require.Equal(t, familyIPv4, plan4.candidates[0].family,
		"the first candidate must be from the original's family")
}

func TestPlanCandidatesSingleFamilyIsNotInterleaved(t *testing.T) {
	// With only one family present, the resolver's order is preserved exactly. Interleaving
	// with an empty slice would be a no-op, but this pins that it stays one.
	v4a := mustAddr(t, "192.0.2.1")
	v4b := mustAddr(t, "192.0.2.2")
	v4c := mustAddr(t, "192.0.2.3")

	plan := planCandidates([]netip.Addr{v4a, v4b, v4c}, netip.Addr{}, C.DomainStrategyPreferIPv6)
	require.Equal(t, []string{v4a.String(), v4b.String(), v4c.String()}, planStrings(plan))
}

func TestPlanCandidatesEmptyInput(t *testing.T) {
	plan := planCandidates(nil, netip.Addr{}, C.DomainStrategyPreferIPv6)
	require.Empty(t, plan.candidates)
}

func TestPlanCandidatesMarksOriginalProvenance(t *testing.T) {
	// Provenance is carried so diagnostics and tests can tell a recovered candidate from a
	// resolved one without a second lookup.
	original := mustAddr(t, "240e:1::1")
	plan := planCandidates([]netip.Addr{mustAddr(t, "192.0.2.1")}, original, C.DomainStrategyAsIS)

	var foundOriginal bool
	for _, candidate := range plan.candidates {
		if candidate.address == original {
			foundOriginal = true
			require.True(t, candidate.original, "the recovered candidate must be marked as the original")
		} else {
			require.False(t, candidate.original, "resolved candidates must not be marked original")
		}
	}
	require.True(t, foundOriginal, "the original destination must be present")
}
