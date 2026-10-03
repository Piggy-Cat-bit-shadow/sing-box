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
	//
	// The original must remain a candidate AND lead its own family. It is the endpoint the
	// application selected, and it outranks addresses obtained by re-resolving a sniffed name -
	// which can legitimately differ from what the application resolved. Placing it after them,
	// as an earlier version did, let a recovery lookup push the application's own endpoint
	// behind addresses it never asked for.
	original := mustAddr(t, "240e:1::1")
	v6a := mustAddr(t, "2001:db8::1")
	v4a := mustAddr(t, "192.0.2.1")

	// IPv6 leads because AsIS follows the original's family, and the original leads WITHIN
	// that family. The two families then interleave, so IPv4 takes the second slot - which is
	// the RFC 8305 behaviour, not a demotion of the original.
	//
	// The property that matters is the FIRST candidate: it must be the application's own
	// address, not one recovered by re-resolving the sniffed name.
	plan := planCandidates([]netip.Addr{v4a, v6a}, original, C.DomainStrategyAsIS)
	require.Equal(t,
		[]string{original.String(), v4a.String(), v6a.String()},
		planStrings(plan),
		"the original must lead, with the families interleaved behind it")
	require.Equal(t, original, plan.candidates[0].address,
		"the application's own endpoint must be dialled first")
	require.True(t, plan.candidates[0].original,
		"the leading candidate must be marked as the application's own address")
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

// --- original-literal precedence (A-H) -----------------------------------------------
//
// Every case asserts the EXACT candidate order, not merely that the original is present.
// The defect these pin was precisely a present-but-misplaced address: when the resolver
// returned the application's own address, the old presence check left it where the resolver
// put it, so a re-resolved address could sit in front of the endpoint the application chose.

func TestOriginalLiteralLeadsItsFamilyEvenWhenAlreadyResolved(t *testing.T) {
	original := mustAddr(t, "192.0.2.4")
	resolved := []netip.Addr{
		mustAddr(t, "192.0.2.8"),
		mustAddr(t, "192.0.2.4"), // the original, in the middle
		mustAddr(t, "192.0.2.9"),
	}

	plan := planCandidates(resolved, original, C.DomainStrategyAsIS)
	require.Equal(t,
		[]string{"192.0.2.4", "192.0.2.8", "192.0.2.9"},
		planStrings(plan),
		"an original already present in the resolved list must be MOVED to the front of its "+
			"family, not left where the resolver put it")
}

func TestOriginalLiteralPrecedenceMatrix(t *testing.T) {
	cases := []struct {
		name     string
		resolved []string
		original string
		strategy C.DomainStrategy
		want     []string
	}{
		{
			// A. absent: must be ADDED to its family.
			name:     "A absent IPv4 original is added to the IPv4 family",
			resolved: []string{"192.0.2.8", "192.0.2.9"},
			original: "192.0.2.4",
			strategy: C.DomainStrategyAsIS,
			want:     []string{"192.0.2.4", "192.0.2.8", "192.0.2.9"},
		},
		{
			// B. present in the middle: must be MOVED, with no duplicate.
			name:     "B IPv4 original present mid-list is promoted without duplication",
			resolved: []string{"192.0.2.8", "192.0.2.4", "192.0.2.9"},
			original: "192.0.2.4",
			strategy: C.DomainStrategyAsIS,
			want:     []string{"192.0.2.4", "192.0.2.8", "192.0.2.9"},
		},
		{
			// C. the IPv6 mirror.
			name:     "C IPv6 original present mid-list is promoted",
			resolved: []string{"240e:1::8", "240e:1::4", "240e:1::9"},
			original: "240e:1::4",
			strategy: C.DomainStrategyPreferIPv6,
			want:     []string{"240e:1::4", "240e:1::8", "240e:1::9"},
		},
		{
			// D. the resolver returned the IPv4-mapped form of the original.
			name:     "D IPv4-mapped duplicate is deduplicated canonically",
			resolved: []string{"::ffff:192.0.2.4", "192.0.2.8"},
			original: "192.0.2.4",
			strategy: C.DomainStrategyAsIS,
			want:     []string{"192.0.2.4", "192.0.2.8"},
		},
		{
			// E. preference governs the FAMILY order; the original leads WITHIN its family.
			name:     "E PreferIPv6 with an IPv4 original keeps IPv6 leading overall",
			resolved: []string{"2001:db8::1", "192.0.2.8", "192.0.2.4"},
			original: "192.0.2.4",
			strategy: C.DomainStrategyPreferIPv6,
			want:     []string{"2001:db8::1", "192.0.2.4", "192.0.2.8"},
		},
		{
			// F. the symmetric case.
			name:     "F PreferIPv4 with an IPv6 original keeps IPv4 leading overall",
			resolved: []string{"192.0.2.1", "240e:1::8", "240e:1::4"},
			original: "240e:1::4",
			strategy: C.DomainStrategyPreferIPv4,
			want:     []string{"192.0.2.1", "240e:1::4", "240e:1::8"},
		},
		{
			// G. strict: no IPv6 may appear, and the original still leads its own family.
			name:     "G IPv4Only admits no IPv6 and still promotes the IPv4 original",
			resolved: []string{"192.0.2.8", "192.0.2.4", "2001:db8::1"},
			original: "192.0.2.4",
			strategy: C.DomainStrategyIPv4Only,
			want:     []string{"192.0.2.4", "192.0.2.8"},
		},
		{
			// H. the mirror.
			name:     "H IPv6Only admits no IPv4 and still promotes the IPv6 original",
			resolved: []string{"240e:1::8", "240e:1::4", "192.0.2.1"},
			original: "240e:1::4",
			strategy: C.DomainStrategyIPv6Only,
			want:     []string{"240e:1::4", "240e:1::8"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			resolved := make([]netip.Addr, 0, len(testCase.resolved))
			for _, address := range testCase.resolved {
				resolved = append(resolved, mustAddr(t, address))
			}

			plan := planCandidates(resolved, mustAddr(t, testCase.original), testCase.strategy)
			require.Equal(t, testCase.want, planStrings(plan),
				"the candidate order must match exactly; an original that is present but "+
					"misplaced is the failure this pins")

			// No candidate may appear twice. A promotion implemented as an append rather than a
			// move would duplicate the original, which addresses the ordering symptom while
			// creating a second connection to the same host.
			seen := make(map[string]struct{}, len(plan.candidates))
			for _, candidate := range plan.candidates {
				_, duplicate := seen[candidate.address.String()]
				require.False(t, duplicate, "candidate %v appears more than once", candidate.address)
				seen[candidate.address.String()] = struct{}{}
			}

			// Strict strategies must remain strict regardless of the original's family.
			for _, candidate := range plan.candidates {
				isV6 := candidate.address.Is6() && !candidate.address.Is4In6()
				switch testCase.strategy {
				case C.DomainStrategyIPv4Only:
					require.False(t, isV6, "ipv4_only must not admit %v", candidate.address)
				case C.DomainStrategyIPv6Only:
					require.False(t, candidate.address.Is4() || candidate.address.Is4In6(),
						"ipv6_only must not admit %v", candidate.address)
				}
			}
		})
	}
}

func TestOriginalLiteralPromotionPreservesResolvedOrderOtherwise(t *testing.T) {
	// Only the original may move. Every other address must keep its relative resolver order,
	// which is what makes this a promotion rather than a re-sort.
	original := mustAddr(t, "192.0.2.5")
	resolved := []netip.Addr{
		mustAddr(t, "192.0.2.1"),
		mustAddr(t, "192.0.2.2"),
		mustAddr(t, "192.0.2.5"),
		mustAddr(t, "192.0.2.3"),
		mustAddr(t, "192.0.2.4"),
	}

	plan := planCandidates(resolved, original, C.DomainStrategyIPv4Only)
	require.Equal(t,
		[]string{"192.0.2.5", "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"},
		planStrings(plan),
		"the original moves; the resolver's ordering of everything else is preserved")
}

func TestOriginalLiteralKeptWhenAbsentFromResolved(t *testing.T) {
	// The recovery case, which must not regress: the resolved set may not contain the
	// application's address at all (a CDN answering differently, split-horizon DNS, a cached
	// mapping), and the address must still appear in its family.
	original := mustAddr(t, "240e:1::1")
	resolved := []netip.Addr{mustAddr(t, "192.0.2.1")}

	plan := planCandidates(resolved, original, C.DomainStrategyAsIS)
	require.Equal(t, []string{"240e:1::1", "192.0.2.1"}, planStrings(plan),
		"an absent original must be ADDED to its own family")

	var found bool
	for _, candidate := range plan.candidates {
		if candidate.address == original {
			found = true
			require.True(t, candidate.original, "the added candidate must carry original provenance")
		}
	}
	require.True(t, found)
}
