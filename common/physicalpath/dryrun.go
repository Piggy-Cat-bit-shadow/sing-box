package physicalpath

import (
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

// EndpointRegistry is the half of the endpoint namespace a dry run has to see.
//
// It exists as an interface rather than as a concrete manager so a caller - and a test - can
// supply the object set directly, and so this package does not depend on a manager's internals.
// adapter.EndpointManager satisfies it.
type EndpointRegistry interface {
	Get(tag string) (adapter.Endpoint, bool)
	Endpoints() []adapter.Endpoint
}

// Declarations carries the facts a dry run needs that are NOT readable from the objects
// themselves.
//
// # Why a declaration has to be supplied rather than read from the leaf
//
// `dialer_options.destination_dns_ownership` is a CONFIGURATION declaration, and the object it
// produced does not necessarily remember it: only the outbound types that implement the behaviour
// parse the field. Comparing the declaration against the object's own capability report is
// therefore the coherent check - it catches "the configuration promised this and the object cannot
// do it", which is a silent remote resolution at run time rather than a startup error.
type Declarations struct {
	// DestinationDNSOwnership is the set of tags whose configuration declared
	// destination_dns_ownership.
	DestinationDNSOwnership map[string]bool
}

// HopCheck is one node the dry run examined, at the position it occupies on the route.
type HopCheck struct {
	// Root is the tag of the walk's root.
	Root string
	// Hop is the node's own tag.
	Hop string
	// Route is the control descent that reaches the node: root, then each group entered, then the
	// node.
	Route string
	// Path is the packet-order physical chain that reaches it.
	Path string
	// Position is its packet-order index.
	Position int
	// Exit is true when this node is where the route ends - the leaf proper.
	Exit bool
	// Current is true when this node is on the path the root resolves to RIGHT NOW, rather than
	// one of the other reachable members.
	Current bool
	// Requirement is the network set this node was ACTUALLY checked against, which is the fact the
	// report has to state: a node that was not required to carry anything was not failed for
	// carrying nothing, and a reader who cannot tell those apart cannot tell a verified leaf from
	// an undecided one.
	//
	// A nil slice means no network requirement applied at this node, for one of three reasons:
	//
	//   - the node is a DEPENDENCY (Position > 0). A dependency carries the consumer's own
	//     transport, not the business flow, and which network that transport is - TCP for every
	//     proxy protocol in this tree, UDP for the QUIC-based ones - is a fact about the consumer
	//     that no object publishes before Start. Comparing the business network against it is the
	//     mistake that refused a TCP-only hop under a UDP-over-TCP outbound.
	//   - the node is below a group whose selection filters members by network before choosing one,
	//     so an incapable member is never handed the flow.
	//   - nothing proved which networks reach this root, and the root advertises none this package
	//     can decide (see advertisedNetworks).
	Requirement []string
	// Unknowns are the problems found at this node. A node with unknowns was NOT verified, and it
	// is never reported as reachable.
	Unknowns []Unknown
}

// Failure is one reason a reachable node is not usable.
//
// The fields are the whole point: "unsupported" is not a report. The root says which entry the
// failure arrived through, the route says which selection steps led to it, the path says where in
// the packet order it sits, the hop says the index, the leaf says what object it is, and the
// reason says what is wrong with it.
type Failure struct {
	Root   string
	Leaf   string
	Route  string
	Path   string
	Hop    int
	Reason string
}

func (f Failure) String() string {
	var builder strings.Builder
	builder.WriteString("outbound/")
	builder.WriteString(f.Root)
	builder.WriteString(" -> ")
	if f.Route != "" && f.Route != f.Root {
		builder.WriteString(f.Route)
		builder.WriteString(" -> ")
	}
	builder.WriteString("hop #")
	builder.WriteString(itoa(f.Hop))
	builder.WriteString(" ")
	builder.WriteString(f.Leaf)
	if f.Path != "" && f.Path != f.Leaf {
		builder.WriteString(" (path ")
		builder.WriteString(f.Path)
		builder.WriteString(")")
	}
	builder.WriteString(": ")
	builder.WriteString(f.Reason)
	return builder.String()
}

// Report is the result of a dry run over a set of roots.
type Report struct {
	// Roots is every root the dry run started from, in the order it examined them.
	Roots []string
	// Nodes is every node it examined, one entry per reachable node per route.
	Nodes []HopCheck
	// Failures is every node that is not usable. A report with no failures is the only one that
	// means "every reachable leaf was validated".
	Failures []Failure
}

// Reachable reports whether every reachable node under every root was validated and usable.
//
// A node the dry run could not determine - an unknown hop - does NOT count as reachable: the
// question this answers is "was every leaf PROVEN usable", and an unproven leaf is not.
func (r Report) Reachable() bool {
	return len(r.Failures) == 0
}

// Leaves returns the checks for the nodes where each route ends.
func (r Report) Leaves() []HopCheck {
	leaves := make([]HopCheck, 0, len(r.Nodes))
	for _, node := range r.Nodes {
		if node.Exit {
			leaves = append(leaves, node)
		}
	}
	return leaves
}

// Err renders the report as a start error naming every offending route, or nil.
//
// Every failure is reported rather than only the first: an operator fixing one broken member at a
// time, one start at a time, is the experience this exists to remove.
func (r Report) Err() error {
	if r.Reachable() {
		return nil
	}
	lines := make([]string, 0, len(r.Failures))
	for _, failure := range r.Failures {
		lines = append(lines, failure.String())
	}
	return E.New("unusable outbound path member(s):\n  ", strings.Join(lines, "\n  "))
}

// ValidateRoots runs the reachable-leaf dry run over an explicit set of roots.
//
// delivered is what the caller has PROVEN can reach these roots: the networks a routing rule with
// an explicit network condition delivers, unioned over the rules that name the root. Each node is
// checked against the part of that set that is a requirement FOR IT - see nodeRequirementFor.
//
// An empty or nil delivered means exactly that nothing was proven, and it is NOT read as "both
// networks" or as "TCP". The requirement then falls back to what the root itself advertises,
// computed from the reachable objects rather than from a group's own Network() - a selector
// reports both networks while nothing is selected (protocol/group/selector.go), so its pre-Start
// answer is a blanket rather than a capability, and treating it as a hard requirement refused
// every selector whose members were all TCP-only.
//
// It dials nothing, resolves nothing, starts nothing, changes no selection and consumes no
// rotation, and it takes NO selection preview either: whether a node is on the path the root
// resolves to right now is decided by which members the groups DECLARED as their selection, so no
// group's Selected() is called. See Hops and the package documentation.
func ValidateRoots(resolver *Resolver, roots []adapter.Outbound, endpoints EndpointRegistry, delivered []string, declarations Declarations) (Report, error) {
	report := Report{}
	proven := decidedNetworks(delivered)
	seenRoot := make(map[adapter.Outbound]bool)
	for _, root := range roots {
		if root == nil || seenRoot[root] {
			continue
		}
		seenRoot[root] = true
		report.Roots = append(report.Roots, root.Tag())
		nodes, err := resolver.Hops(root)
		if err != nil {
			return Report{}, E.Cause(err, "enumerate reachable leaves of outbound/", root.Tag())
		}
		requirement := proven
		if requirement == nil {
			// Nothing was proven about delivery, so the requirement is what the root's own
			// reachable objects say they can carry. Reading it from the NODES rather than from
			// root.Network() is what keeps a group's pre-Start answer, which is a blanket, out of
			// the decision.
			requirement = advertisedNetworks(nodes)
		}
		// A group that picks its member BY NETWORK never hands a flow to a member that cannot carry
		// it, so a network delivered to such a group is served by whichever member can carry it -
		// and the group is unusable only when NO member can. Refusing every member that could not
		// carry it would refuse a configuration protocol/group/loadbalance.go documents as the
		// reason the union is advertised at all.
		//
		// # Why the question is asked per EDGE rather than of the whole tree
		//
		// It used to be `if hasNetworkFilteringGroup(resolver, nodes)`, a single boolean that is
		// true when ANY group anywhere on ANY node's control path filters, followed by
		// `anyNodeCarries(nodes, network)` over the WHOLE node set. That is a pass for the whole
		// tree: one filtering group was taken as protecting every node, including nodes it never
		// chooses, and the "is this network served at all" question was asked of nodes that are not
		// below it.
		//
		// MEASURED, with `outer(loadbalance) -> inner(selector) -> [tcp-only, udp-only]` and both
		// networks delivered, the walk reported NO failures at all: `outer` filters, so every node
		// below `outer` was treated as exempt - while `inner` does not filter and hands a UDP flow
		// straight to `tcp-only`.
		//
		// The responsibility belongs to the group that does the filtering, so the question is asked
		// once per filtering group that was actually reached, of the exits THAT group can reach.
		// The failure is attributed to that group rather than to the root, because that group is
		// what refuses the flow at run time.
		for _, group := range filteringGroups(resolver, nodes) {
			reachable := nodesUnder(nodes, group.Tag())
			for _, network := range requirement {
				if anyNodeCarries(reachable, network) {
					continue
				}
				report.Failures = append(report.Failures, Failure{
					Root:  root.Tag(),
					Leaf:  group.Tag(),
					Route: routeUnder(reachable, root.Tag()),
					Path:  routeUnder(reachable, root.Tag()),
					Hop:   0,
					Reason: "no reachable member carries " + network + ", and this group selects its " +
						"member by network, so every " + network + " flow delivered here would be " +
						"refused at run time",
				})
			}
		}
		for _, node := range nodes {
			check := HopCheck{
				Root:        node.Root,
				Hop:         node.Tag,
				Route:       node.Route(),
				Path:        node.Path(),
				Position:    node.Position,
				Exit:        node.Exit,
				Current:     node.IsCurrent,
				Requirement: nodeRequirementFor(resolver, node, requirement),
			}
			for _, failure := range validateNode(resolver, node, endpoints, check.Requirement, declarations) {
				check.Unknowns = append(check.Unknowns, Unknown{
					Node:     failure.Leaf,
					Position: failure.Hop,
					Reason:   failure.Reason,
				})
				report.Failures = append(report.Failures, failure)
			}
			report.Nodes = append(report.Nodes, check)
		}
	}
	return report, nil
}

// nodeRequirementFor reports the networks THIS node has to be able to carry, and nil when nothing
// is decided for it.
//
// # Why the requirement is not the same for every node of a route
//
// The flow the routing selected reaches the FIRST physical node. Every node after it is a
// dependency of the node above, and a dependency is dialled to carry that consumer's own
// connection - not the business flow - so its network requirement is a TRANSPORT requirement, and
// the consumer's transport is not published by any object before Start. A dependency that carries
// the business network is therefore accepted, and one that does not is left UNVERIFIED rather than
// refused: UDP-over-TCP is a legal conversion and this is exactly the case it covers.
//
// # Why the exemption reads the PARENT EDGE and not the whole control path
//
// A node is exempt when the group that HANDS IT THE FLOW refuses to hand it a flow it cannot carry.
// That group is the innermost one on the node's control path, because the path is recorded from the
// root down (leaves.go's `groupTags`), so it is the LAST element and not "any element".
//
// Reading the whole path made an ANCESTOR's filter a pass for every node below it. MEASURED, with
// `outer(loadbalance) -> inner(selector) -> [tcp-only, udp-only]` and both networks delivered, the
// walk reported no failures: `outer` filters and is on both nodes' control paths, so both were
// exempt - while `inner` does not filter and hands a UDP flow to `tcp-only` and a TCP flow to
// `udp-only`. The presence of a filtering group anywhere must not be a pass for a whole subtree.
func nodeRequirementFor(resolver *Resolver, hop PathNode, delivered []string) []string {
	if !businessEntry(hop) {
		return nil
	}
	if parentGroup(resolver, hop) != nil && networkFilteringGroup(parentGroup(resolver, hop)) {
		return nil
	}
	return delivered
}

// parentGroup recovers the group that handed this node the flow.
//
// The control path is recorded from the root DOWN - the root first, then each group entered
// (leaves.go's `enumerateHops` appends as it descends) - so the group that chose this node is the
// last element. A group is never emitted as a hop itself, so the last element is always the
// immediate parent rather than the node.
//
// The object is recovered by tag through the resolver's lookup, which is the same read-only
// registry lookup the enumeration used, so what is returned is the object that declared this
// membership.
func parentGroup(resolver *Resolver, hop PathNode) adapter.OutboundGroup {
	if len(hop.ControlPath) == 0 {
		return nil
	}
	object, loaded := resolver.Lookup(hop.ControlPath[len(hop.ControlPath)-1])
	if !loaded {
		return nil
	}
	group, isGroup := object.(adapter.OutboundGroup)
	if !isGroup {
		return nil
	}
	return group
}

// filteringGroups reports every group that filters its members by network and that this walk
// actually reached, de-duplicated by identity.
//
// Identity rather than tag is what de-duplicates: a tag is configuration and two objects may share
// one, and asking the question of the wrong object would answer for a group that is not on this
// route.
func filteringGroups(resolver *Resolver, nodes []PathNode) []adapter.OutboundGroup {
	var groups []adapter.OutboundGroup
	for _, node := range nodes {
		for _, tag := range node.ControlPath {
			object, loaded := resolver.Lookup(tag)
			if !loaded {
				continue
			}
			group, isGroup := object.(adapter.OutboundGroup)
			if !isGroup || !networkFilteringGroup(group) {
				continue
			}
			if !slices.Contains(groups, group) {
				groups = append(groups, group)
			}
		}
	}
	return groups
}

// nodesUnder reports the nodes whose control path passes through this group, which is every exit it
// can reach: its own members, and everything below them.
//
// # Why the members are not read from the group instead
//
// A group's declared members include nested GROUPS, and a group is never emitted as a hop
// (leaves.go: "a group is a control node: it never terminates a physical route by itself"). Asking a
// nested member what it can carry would therefore ask a group for its own pre-Start `Network()`,
// which is the blanket this package exists to keep out of the decision. The nodes below the group
// are the PHYSICAL exits it can reach, which is the question being asked.
func nodesUnder(nodes []PathNode, tag string) []PathNode {
	var under []PathNode
	for _, node := range nodes {
		if slices.Contains(node.ControlPath, tag) {
			under = append(under, node)
		}
	}
	return under
}

// routeUnder renders the control descent that reaches the first of these nodes, so a failure
// attributed to a group still says which route arrives at it. It falls back to the root.
func routeUnder(nodes []PathNode, rootTag string) string {
	if len(nodes) == 0 {
		return rootTag
	}
	return nodes[0].Route()
}

// businessEntry reports whether the flow the routing selected ARRIVES at this node.
//
// # Why this is not Position == 0
//
// `Position` is an index into PACKET order, whose origin is the hop nearest THIS DEVICE. For a route
// with a detour the device-nearest hop is a DEPENDENCY, so reading position 0 as "the flow arrives
// here" demands the BUSINESS network of an underlay hop and refuses a legal TCP-only middle hop under
// a UDP-carrying outbound.
//
// The business entry is the far end of packet order: the hop the routing selected. A node therefore
// is the entry exactly when nothing was dialled THROUGH it, which is when its own physical chain does
// not continue past it. `Position` is the node's index in `PhysicalPath`, so that is
// `len(PhysicalPath)-1 == Position`.
//
// It is stated in terms of the node's OWN CHAIN rather than in terms of an index, so it stays correct
// whichever end the ordering convention counts from.
func businessEntry(hop PathNode) bool {
	if len(hop.PhysicalPath) == 0 {
		// No physical chain at all: the root itself, which is where the flow is delivered.
		return true
	}
	return hop.Position == len(hop.PhysicalPath)-1
}

// hasNetworkFilteringGroup used to report whether any group on these nodes' control paths filters
// its members by network, and it is deliberately GONE rather than kept as a helper.
//
// # Why it must not come back
//
// It answered a question about the whole tree - "is there a filtering group anywhere below this
// root" - and both of its callers used that answer as though it were about ONE edge: the root-level
// pass above, and `nodeRequirementFor`, which called it with a single node and then read "any group
// on the whole path" as "the group that chose this node". A filtering group one or more levels up
// therefore exempted every node below it, including nodes it never chooses.
//
// MEASURED, with `outer(loadbalance) -> inner(selector) -> [tcp-only, udp-only]`: every node was
// exempt and the walk reported no failures, while `inner` does not filter and would hand UDP to
// `tcp-only` and TCP to `udp-only`.
//
// The two questions it conflated are now asked separately and per edge: `parentGroup` for "does the
// group that chose this node filter", and `filteringGroups` for "which filtering groups did this
// walk reach, and what can each of them reach". A boolean over the whole tree cannot express either
// one, so there is nothing here to preserve.

// networkFilteringGroup reports whether a group refuses a member that cannot carry the flow's
// network, which is what makes a member with a narrower network set legal below it.
//
// # Why these two capabilities, and what is not detectable
//
// The property is per-network SELECTION, and the only observable statements of it in this tree are
// the two interfaces whose implementations filter before choosing: a flow-aware group answers
// SelectForFlow(.., network, ..), and a urltest group's Select skips a member whose Network() does
// not contain the network. Both were checked against their implementations rather than assumed:
// protocol/group/loadbalance.go filters in candidateCount/isCandidate, and protocol/group/urltest.go
// filters at URLTestGroup.Select.
//
// A group that implements neither is treated as NOT filtering, which is the conservative direction
// and the one that matches the contract every group already implements: Selected(network) may
// return any member, and Selector.Selected does exactly that for every network
// (protocol/group/selector_edge_test.go pins it). A third-party group that filters per network
// without either interface is therefore checked as if it did not, which can refuse a member that
// would in fact never be handed the flow - the same answer this package gave before the distinction
// existed, so it adds no refusal.
func networkFilteringGroup(group adapter.OutboundGroup) bool {
	if _, flowAware := group.(adapter.FlowAwareOutboundGroup); flowAware {
		return true
	}
	if _, measured := group.(adapter.URLTestGroup); measured {
		return true
	}
	return false
}

// advertisedNetworks is what the reachable objects under one root say they can carry between them.
//
// It is the fallback requirement when nothing is proven about delivery, and it is deliberately
// derived from the NODES rather than from root.Network(): a group's Network() before Start is the
// group's own answer about a selection it has not made, and for a selector that answer is a
// blanket covering both networks regardless of its members.
//
// Only the nodes the business flow can actually arrive at are counted - the ones at position 0.
// A node further down the chain is a dependency, so its network set describes what it can serve as
// a PROXY, not what the flow entering this root can be: a TCP-only middle hop under a UDP-carrying
// outbound is the ordinary shape of UDP-over-TCP, and unioning its answer in would make the root
// responsible for a network no flow reaches it with.
func advertisedNetworks(nodes []PathNode) []string {
	var advertised []string
	for _, node := range nodes {
		if !businessEntry(node) {
			// A dependency. Its network set describes what it can serve as a PROXY for the hop that
			// dials through it, not what the flow entering this root can be, so unioning its answer
			// in would make the root responsible for a network no flow reaches it with.
			continue
		}
		for _, network := range decidedNetworks(networksOf(node.Outbound)) {
			if !slices.Contains(advertised, network) {
				advertised = append(advertised, network)
			}
		}
	}
	return advertised
}

// anyNodeCarries reports whether any reachable node under a root can carry the network.
func anyNodeCarries(nodes []PathNode, network string) bool {
	for _, node := range nodes {
		if !businessEntry(node) {
			// A dependency carries the transport of the hop that dials through it, so its Network()
			// answers a different question. Counting it here answers the wrong question in the PASS
			// direction: a udp-carrying underlay would bless a group whose exit is tcp-only.
			continue
		}
		if slices.Contains(networksOf(node.Outbound), network) {
			return true
		}
	}
	return false
}

// decidedNetworks keeps the networks this dry run can decide about, in first-seen order.
//
// ICMP and any future network are carried by a flow port rather than dialled, so they are outside
// what this dry run can decide. Ignoring them is the honest answer: inventing a requirement for
// them would reject a legal configuration.
func decidedNetworks(networks []string) []string {
	var decided []string
	for _, network := range networks {
		if network != NetworkTCP && network != NetworkUDP {
			continue
		}
		if slices.Contains(decided, network) {
			continue
		}
		decided = append(decided, network)
	}
	return decided
}

// validateNode is the per-node contract. Every check below is decidable without the network, which
// is what makes it legal to run before any traffic exists.
//
// requirement is the set THIS node must be able to carry, as nodeRequirementFor decided it; an
// empty set means no network requirement applies here and step 2 is skipped rather than passed
// with a default.
func validateNode(resolver *Resolver, hop PathNode, endpoints EndpointRegistry, requirement []string, declarations Declarations) []Failure {
	failure := func(reason string) []Failure {
		return []Failure{{
			Root:   hop.Root,
			Leaf:   hop.Tag,
			Route:  hop.Route(),
			Path:   hop.Path(),
			Hop:    hop.Position,
			Reason: reason,
		}}
	}
	// 1. The node exists, and the reference is legal. The reason is worded for the case that
	//    matters: a group declared this member, so the failure would otherwise arrive at the first
	//    switch to it rather than at start.
	if hop.Outbound == nil {
		return failure("the group declares this member but no outbound or endpoint with this tag " +
			"exists; the group would fail on the first switch to it")
	}
	// 2. The node can serve the networks required at its position.
	//
	//    The requirement is the node's OWN - what the routes proved reaches this entry point, or,
	//    when nothing was proven, what this root's reachable objects advertise between them. It is
	//    never the union of every outbound in the configuration: an unrelated outbound that carries
	//    UDP says nothing about what reaches this one, and treating it as if it did refused
	//    configurations that had always started.
	if len(requirement) > 0 {
		networksCarried := networksOf(hop.Outbound)
		if len(networksCarried) == 0 {
			return failure("this outbound reports no network it can carry, so it cannot serve the " +
				strings.Join(requirement, ",") + " flow routed through it")
		}
		// EVERY network in the requirement is checked before a verdict is reached, and the report
		// names the ones this hop CANNOT carry.
		//
		// # Why the loop does not return on the first unsupported network
		//
		// It used to, and the consequence was a wrong message rather than a missing check. A hop
		// required to carry both networks while carrying only TCP reported "this outbound carries
		// tcp and cannot serve the udp flow" - which reads as "it carries tcp and therefore cannot
		// serve udp", i.e. as though carrying tcp were the CAUSE of the udp failure. The cause is
		// that it does not carry udp, and the sentence said the opposite.
		//
		// A caller that is told the wrong cause looks in the wrong place, so the failure now names
		// exactly the missing set and separately what the hop does carry.
		var missing []string
		for _, network := range requirement {
			if !slices.Contains(networksCarried, network) {
				missing = append(missing, network)
			}
		}
		if len(missing) > 0 {
			return failure("this outbound does not carry " + strings.Join(missing, ",") +
				" (it carries " + strings.Join(networksCarried, ",") + ") and cannot serve the " +
				strings.Join(missing, ",") + " flow routed through it (the entry point routes " +
				strings.Join(requirement, ",") + " to it)")
		}
	}
	// 3. Endpoint participation and lifecycle ownership are coherent.
	//
	//    # What "is an endpoint" means here
	//
	//    Not "the object has Start and Close": adapter.Endpoint embeds adapter.Outbound, so a
	//    Lifecycle on an outbound is the ordinary shape of several outbound types and asserting the
	//    interface would misreport every one of them. What the endpoint manager OWNS is its own
	//    registry, so the question is whether the object this hop resolved to is the object that
	//    registry holds under this tag.
	//
	//    An object the endpoint manager holds and that does not match is a collision, and a
	//    collision is worse than a missing registration: the lookup resolves the outbound first, so
	//    the endpoint exists, is listed, and can never be reached.
	if endpoints != nil {
		registered, present := endpoints.Get(hop.Tag)
		if present && registered != hop.Outbound {
			return failure("this tag is claimed by BOTH an outbound and an endpoint in the endpoint " +
				"manager, and they are different objects; the lookup resolves the outbound first, so " +
				"the endpoint can never be reached and would never be started or closed")
		}
	}
	// 4. Destination DNS ownership: a declared owner must be able to resolve the destination
	//    before it writes the request to its peer, and the object must implement the behaviour the
	//    configuration declared.
	if declarations.DestinationDNSOwnership[hop.Tag] {
		if _, capable := hop.Outbound.(adapter.DestinationDNSOwner); !capable {
			return failure("the configuration declares destination_dns_ownership for this outbound, " +
				"but outbound type " + hop.Outbound.Type() + " does not implement it; the destination " +
				"domain would be sent to the peer while the configuration says it must not be")
		}
		if canResolve, reason := resolver.CanResolveDestination(hop.Tag); !canResolve {
			return failure(reason)
		}
	}
	return nil
}

// HopUnknownsAreFatal is a helper for a caller that wants to treat an undetermined node as a
// failure in its own report. It exists so the rule is stated once rather than re-derived at each
// call site: an unknown path is never reported as reachable.
func HopUnknownsAreFatal(check HopCheck) bool {
	return len(check.Unknowns) > 0
}
