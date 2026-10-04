package route

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing-box/option"
)

// TrafficClassPolicies maps an outbound tag to the traffic class its configuration states
// explicitly.
//
// # Why a tag map rather than a field on the outbound
//
// TrafficClass is declared on the configuration envelope, so it exists for every outbound type
// without any of them knowing about it. Attaching it to the outbound OBJECT would mean editing
// every constructor, or wrapping the outbound - and wrapping breaks the type assertions that
// resolveOutbound depends on (`outbound.(adapter.OutboundGroup)` is how a selector is followed to
// its leaf). A tag-keyed lookup leaves every outbound type untouched and cannot interfere with
// group resolution.
//
// The lookup runs at flow setup only. Nothing on the per-read or per-write path consults it.
type TrafficClassPolicies map[string]option.TrafficClassPolicy

// resolveTrafficClass determines a flow's traffic class from its complete logical outbound chain.
//
// # Precedence
//
//  1. The FIRST explicit traffic_class, scanning outermost to leaf. This includes an explicit
//     "default", which is how an operator stops automatic classification for a group.
//  2. If NO element of the chain carries an explicit policy, automatic tag classification,
//     again outermost to leaf.
//  3. Otherwise default.
//
// # Why the outermost element wins
//
// The business meaning belongs to the logical entry group, not to the node that happens to serve
// it. One residential node is reachable through the AI selector and through a general selector at
// the same time, so a class inferred from the leaf would mark that node as AI for every flow that
// ever uses it. Resolving per flow from the chain is what keeps the two paths independent, and it
// is why nothing here is memoised onto the chain elements.
//
// An explicit policy anywhere in the chain suppresses automatic detection for the whole chain,
// including at inner levels: the chain is one policy decision, not a set of independent ones.
func resolveTrafficClass(chain []adapter.Outbound, policies TrafficClassPolicies) trafficclass.Class {
	for _, outbound := range chain {
		if policy, loaded := policies[outbound.Tag()]; loaded {
			return policy.Class
		}
	}
	for _, outbound := range chain {
		if trafficclass.MatchTag(outbound.Tag()) {
			return trafficclass.AutoTagClass
		}
	}
	return trafficclass.ClassDefault
}
