package route

import (
	"net/netip"

	"github.com/sagernet/sing-box/common/dialer"
)

// BypassVerdict is the router's answer to "may this flow skip the userspace data path?".
//
// # Why a verdict rather than a boolean
//
// The Direct Fast Path is an allow-list of a dozen independent conditions, and a boolean collapses
// all of them into one bit. That is fine for the decision and useless for everything else: a
// deployment asking "why is my direct traffic not bypassed?" gets the same answer whether the cause
// is a FakeIP destination, a tracker, or one dial option, and those have three different remedies.
//
// The zero value is the permissive one, which is why it is named as the success case rather than as
// a negation.
type BypassVerdict uint8

const (
	// BypassAllowed: every condition held and the flow may take the platform's own path.
	BypassAllowed BypassVerdict = iota
	BypassRefusedInboundType
	BypassRefusedNetwork
	BypassRefusedDomainDestination
	BypassRefusedFakeIP
	BypassRefusedSniffedDomain
	BypassRefusedResolvedCandidates
	BypassRefusedDestinationRewritten
	BypassRefusedRouteOriginalDestination
	BypassRefusedUoTDatagramDestinations
	BypassRefusedUDPConnect
	BypassRefusedUDPDomainUnmapping
	BypassRefusedCustomUDPTimeout
	BypassRefusedNetworkOptions
	BypassRefusedTLSOptions
	BypassRefusedTracker
	BypassRefusedProcessMetadataUnproven
	BypassRefusedOutboundChain
	BypassRefusedOutboundNotBypassable
	BypassRefusedOutboundSemantics
)

// bypassVerdictNames is the diagnostic spelling of each verdict. It is a slice rather than a map so
// that looking one up is an index and cannot allocate.
var bypassVerdictNames = [...]string{
	BypassAllowed:                         "allowed",
	BypassRefusedInboundType:              "inbound is not TUN",
	BypassRefusedNetwork:                  "network is not TCP or UDP",
	BypassRefusedDomainDestination:        "destination is a domain",
	BypassRefusedFakeIP:                   "destination is FakeIP",
	BypassRefusedSniffedDomain:            "a domain was sniffed for this flow",
	BypassRefusedResolvedCandidates:       "the flow carries a resolved candidate list",
	BypassRefusedDestinationRewritten:     "a rule rewrote the destination",
	BypassRefusedRouteOriginalDestination: "a rule recorded an original destination",
	BypassRefusedUoTDatagramDestinations:  "UoT session carries per-datagram destinations",
	BypassRefusedUDPConnect:               "UDPConnect has its own socket semantics",
	BypassRefusedUDPDomainUnmapping:       "udp_disable_domain_unmapping is set",
	BypassRefusedCustomUDPTimeout:         "a UDP timeout is configured",
	BypassRefusedNetworkOptions:           "network strategy, type or fallback is configured",
	BypassRefusedTLSOptions:               "TLS fragmentation or spoofing is configured",
	BypassRefusedTracker:                  "a connection tracker is attached",
	BypassRefusedProcessMetadataUnproven:  "process metadata could not be proven",
	BypassRefusedOutboundChain:            "the outbound chain is not a single leaf",
	BypassRefusedOutboundNotBypassable:    "the selected outbound is not bypassable",
	BypassRefusedOutboundSemantics:        "the selected outbound's dial semantics are not equivalent",
}

// String names the verdict, for diagnostics and test failures.
func (v BypassVerdict) String() string {
	if int(v) >= len(bypassVerdictNames) {
		return "unknown bypass verdict"
	}
	return bypassVerdictNames[v]
}

// BypassAllowed reports whether this verdict permits the fast path.
func (v BypassVerdict) BypassAllowed() bool { return v == BypassAllowed }

// bypassBlockerReporter is the optional richer half of adapter.BypassableOutbound.
//
// It is asserted structurally rather than declared in adapter because the blocker type lives in
// common/dialer, which imports adapter - declaring it in adapter would close the cycle. An outbound
// that does not implement it is not penalised: the verdict is then BypassRefusedOutboundSemantics
// with no detail, which is exactly what a plain boolean answer can express.
type bypassBlockerReporter interface {
	BypassBlockers(network string, destination netip.Addr) dialer.NativeBypassBlocker
}

// bypassBlockerDetail attributes an outbound-level refusal, or reports BlockerNone when the
// outbound cannot say. It is called only after the fast path has already been refused, so it is off
// every successful decision and off the packet path entirely.
func bypassBlockerDetail(outbound any, network string, destination netip.Addr) dialer.NativeBypassBlocker {
	reporter, isReporter := outbound.(bypassBlockerReporter)
	if !isReporter {
		return dialer.BlockerNone
	}
	return reporter.BypassBlockers(network, destination)
}
