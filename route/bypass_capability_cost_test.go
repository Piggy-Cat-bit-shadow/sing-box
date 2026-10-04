package route

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Whether the Direct Fast Path's eligibility decision should be gated on the CALLER being able to
// honour a bypass verdict.
//
// # Why the question comes up
//
// tun.ActionBypass is honoured by Linux auto_redirect (nfqueue maps it to NfRepeat with the output
// mark) and by no TUN stack: there, a bypass verdict installs an accept entry and the packet
// continues into the userspace stack, exactly as an accept verdict does. So for an ordinary TUN
// inbound the whole eligibility decision is inert, and the obvious follow-up is to stop computing
// it.
//
// # What is measured here
//
// Two configurations of the same production-shaped direct outbound:
//
//	eligible  the shipped profile, so canFastBypass allows and the verdict is a bypass
//	ordinary  the same outbound with one dial option that refuses, so the decision is computed and
//	          DECLINES, and preMatchFlow runs its ordinary tail
//
// The second is not identical to gating - gating would skip the predicate rather than run it and
// refuse - so it bounds the answer from the pessimistic side: gating can save at most the difference
// between refusing at the last check and skipping the check entirely, and that difference is smaller
// than what this compares.
//
// # Why it matters that both paths end in the same place
//
// Both verdicts reach the same data path (see protocol/tun/native_bypass_trace_test.go), and neither
// one produces a NewTracker for a direct TCP flow, because the direct outbound answers
// PreMatchContinue for TCP and UDP. So the two configurations differ in nothing a user can observe -
// no accounting, no lifecycle, no packet path - which is what makes a tens-of-nanoseconds difference
// the entire question.

// ordinaryDirectOutbound is the production profile with one option that refuses the fast path, so the
// decision runs and declines.
func ordinaryDirectOutbound() *productionDirectOutbound {
	return &productionDirectOutbound{
		semantics: dialer.NativeBypassSemantics(option.DialerOptions{
			AbstractDialerOptions: option.AbstractDialerOptions{
				DomainResolver: &option.DomainResolveOptions{Server: "local-agh"},
				BindInterface:  "en0",
			},
		}),
	}
}

func preMatchRouter(outbound adapter.Outbound) *Router {
	return &Router{
		ctx:      context.Background(),
		logger:   log.NewNOPFactory().Logger(),
		outbound: &stubOutboundManager{def: outbound},
	}
}

// TestBothConfigurationsReachTheSameVerdictAndTheSameWork is the behavioural half.
//
// It is the control for the benchmarks below: if the two configurations differed in what the router
// produced, comparing their costs would be comparing two different decisions.
func TestBothConfigurationsReachTheSameVerdictAndTheSameWork(t *testing.T) {
	destination := M.ParseSocksaddr("93.184.216.34:443")

	eligible := preMatchRouter(newProductionDirectOutbound())
	ordinary := preMatchRouter(ordinaryDirectOutbound())

	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		t.Run(network, func(t *testing.T) {
			eligibleMetadata := fastBypassMetadata(network, destination)
			ordinaryMetadata := fastBypassMetadata(network, destination)

			eligibleVerdict := eligible.canFastBypass(&eligibleMetadata, destination,
				[]adapter.Outbound{eligible.outbound.Default()}, eligible.outbound.Default())
			ordinaryVerdict := ordinary.canFastBypass(&ordinaryMetadata, destination,
				[]adapter.Outbound{ordinary.outbound.Default()}, ordinary.outbound.Default())

			require.True(t, eligibleVerdict.BypassAllowed(),
				"the shipped profile is eligible, which is what makes it the fast path")
			require.Equal(t, BypassRefusedOutboundSemantics, ordinaryVerdict,
				"and the ordinary one declines at the outbound's own check")

			// Both then produce a result the TUN stack treats identically, which is the whole reason
			// the cost question is the only question.
			eligibleResult := eligible.preMatchFlow(context.Background(), &eligibleMetadata,
				destination, nil, "")
			ordinaryResult := ordinary.preMatchFlow(context.Background(), &ordinaryMetadata,
				destination, nil, "")
			require.Equal(t, adapter.PreMatchBypass, eligibleResult.Action)
			require.Equal(t, adapter.PreMatchContinue, ordinaryResult.Action)
			require.Nil(t, eligibleResult.NewTracker,
				"neither carries a tracker: the direct outbound answers PreMatchContinue for %s, so "+
					"the flow path is never taken and no NewTracker is built", network)
			require.Nil(t, ordinaryResult.NewTracker)
		})
	}
}

// BenchmarkPreMatchDirectFlow measures the whole pre-match for the two configurations.
//
// The comparison is the answer to "how much work would capability gating save": the eligible row is
// what the router does today for these flows, and the ordinary row is what it does when the decision
// declines and the ordinary tail runs. Gating would land between them, closer to the ordinary row,
// because it replaces the predicate with that same tail.
func BenchmarkPreMatchDirectFlow(b *testing.B) {
	destination := M.ParseSocksaddr("93.184.216.34:443")

	for _, configuration := range []struct {
		name     string
		outbound adapter.Outbound
	}{
		{"eligible", newProductionDirectOutbound()},
		{"ordinary", ordinaryDirectOutbound()},
	} {
		for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
			b.Run(configuration.name+"/"+network, func(b *testing.B) {
				router := preMatchRouter(configuration.outbound)
				chain := []adapter.Outbound{configuration.outbound}
				metadata := fastBypassMetadata(network, destination)

				b.ReportAllocs()
				for b.Loop() {
					router.canFastBypass(&metadata, destination, chain, configuration.outbound)
				}
			})
		}
	}
}

// BenchmarkPreMatchDirectFlowEndToEnd measures the same two configurations through the public
// entry point, so the benchmark includes everything preMatchFlow does rather than only the
// predicate.
func BenchmarkPreMatchDirectFlowEndToEnd(b *testing.B) {
	destination := M.ParseSocksaddr("93.184.216.34:443")

	for _, configuration := range []struct {
		name     string
		outbound adapter.Outbound
	}{
		{"eligible", newProductionDirectOutbound()},
		{"ordinary", ordinaryDirectOutbound()},
	} {
		b.Run(configuration.name, func(b *testing.B) {
			router := preMatchRouter(configuration.outbound)
			b.ReportAllocs()
			for b.Loop() {
				metadata := fastBypassMetadata(N.NetworkTCP, destination)
				router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
			}
		})
	}
}
