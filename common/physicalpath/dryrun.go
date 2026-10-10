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
// networks is the set of networks every root must be able to serve; each node is checked against
// the networks its own root advertises. An empty slice means TCP, which is the network every dial
// path in this tree supports.
//
// It dials nothing, resolves nothing, starts nothing, changes no selection and consumes no
// rotation, and it takes NO selection preview either: whether a node is on the path the root
// resolves to right now is decided by which members the groups DECLARED as their selection, so no
// group's Selected() is called. See Hops and the package documentation.
func ValidateRoots(resolver *Resolver, roots []adapter.Outbound, endpoints EndpointRegistry, networks []string, declarations Declarations) (Report, error) {
	report := Report{}
	if len(networks) == 0 {
		networks = []string{NetworkTCP}
	}
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
		for _, node := range nodes {
			check := HopCheck{
				Root:     node.Root,
				Hop:      node.Tag,
				Route:    node.Route(),
				Path:     node.Path(),
				Position: node.Position,
				Exit:     node.Exit,
				Current:  node.IsCurrent,
			}
			for _, failure := range validateNode(resolver, node, endpoints, networks, declarations) {
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

// validateNode is the per-node contract. Every check below is decidable without the network, which
// is what makes it legal to run before any traffic exists.
func validateNode(resolver *Resolver, hop PathNode, endpoints EndpointRegistry, networks []string, declarations Declarations) []Failure {
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
	networksCarried := networksOf(hop.Outbound)
	// 2. The node can serve the networks required at its position.
	//
	//    The requirement is the ROOT's, which is what the flow at this entry point is. Checking
	//    every node of a detour chain against it is not redundant: a middle hop that cannot carry
	//    the flow makes the whole chain unusable even when the exit can.
	for _, network := range networks {
		if slices.Contains(networksCarried, network) {
			continue
		}
		if len(networksCarried) == 0 {
			return failure("this outbound reports no network it can carry, so it cannot serve the " +
				network + " flow routed through it")
		}
		return failure("this outbound carries " + strings.Join(networksCarried, ",") + " and cannot " +
			"serve the " + network + " flow routed through it (the entry point routes " +
			strings.Join(networks, ",") + " to it)")
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
