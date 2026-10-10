package physicalpath

import (
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

// PathNode is one node the reachable-leaf enumeration visited, at the position it occupies.
//
// # Why intermediate nodes of a detour chain are enumerated too
//
// A chain `root -> middle -> exit` has ONE leaf (the exit) and three nodes, and every node is a
// position where the configuration can be wrong: the middle may be a TCP-only outbound in a
// UDP-carrying chain, or an endpoint nothing owns. Validating only the exit would report that
// configuration as usable and then fail on the flow.
type PathNode struct {
	// Root is the tag of the walk's root.
	Root string
	// ControlPath is the descent that reached this node: the root, then every group entered, in
	// selection order. It is not packet order.
	ControlPath []string
	// PhysicalPath is the packet-order chain that ends at this node.
	PhysicalPath []string
	// Tag is the node's own tag, which may name no existing object when a group declared a member
	// that does not exist.
	Tag string
	// Outbound is the live object, or nil when the tag does not resolve. It is the registry's
	// object, never a copy.
	Outbound adapter.Outbound
	// RequiredNetworks is every network the group that handed the flow here advertises, and
	// therefore what it requires this node to be able to carry. A node with no group above it
	// carries the root's own networks.
	RequiredNetworks []string
	// Exit is true when this node is where the packet leaves: a node with no dependency of its
	// own. Exactly one hop per route is the exit.
	Exit bool
	// IsCurrent is true when this node is on the path the root resolves to RIGHT NOW, as opposed
	// to one of the other reachable members. It is derived from the members the groups DECLARED as
	// their selection, so no selection function is called to produce it.
	IsCurrent bool
	// Resolved reports whether the tag names an object that exists.
	Resolved bool
	// Position is the node's packet-order index within this route.
	Position int
}

// Route renders the control route to this node, for an error message.
//
// The node's own tag is part of the route: a group that declares a member which does not exist has
// no object to name, and "sel" alone would not say WHICH member is the problem.
func (h PathNode) Route() string {
	chain := h.ControlPath
	if len(chain) == 0 || chain[len(chain)-1] != h.Tag {
		chain = append(append([]string(nil), chain...), h.Tag)
	}
	return strings.Join(chain, " -> ")
}

// Path renders the physical chain that reaches this node.
func (h PathNode) Path() string {
	if len(h.PhysicalPath) == 0 {
		return h.Tag
	}
	return strings.Join(h.PhysicalPath, " -> ")
}

// Leaves enumerates every EXIT reachable under one root - the node each route ends at, including
// the members of every group at every level whether or not they are currently selected - and Hops
// enumerates every node on the way to one.
//
// # Why every member, not the selected one
//
// A group materialises only the member it has chosen. The others are still part of the
// configuration: a selector whose current member is fine but whose second member is broken must
// fail at Start, not at the first switch, because the switch is decided by a health check or by a
// user action and the failure would then arrive as a traffic outage with no configuration change
// behind it.
//
// # Read-only
//
// The walk dials nothing, resolves nothing and starts nothing, and it consumes no group state: the
// members come from the group's own DECLARED list (adapter.Referrer.References and
// OutboundGroup.All), not from Selected, so not even a preview is taken. It is bounded by the
// object graph, and a cycle is reported rather than followed, so a malformed configuration cannot
// make it spin.
// The walk calls methods on user-configured objects - All, References, Dependencies, Tag, Network -
// and an object graph can be malformed in ways that panic: a typed-nil embedded interface is the
// case that has actually been observed. Containment matches Build's and group.ResolveURLTestLeaf's:
// a diagnostic that crashes on the configuration it is describing is worse than one that reports
// it, and the enumeration is discarded rather than partially reported.
func (r *Resolver) Hops(root adapter.Outbound) (nodes []PathNode, err error) {
	if root == nil {
		return nil, nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			nodes = nil
			err = E.New("reachable leaf enumeration panicked: ", recovered)
		}
	}()
	hops := make([]PathNode, 0, 4)
	seenHop := make(map[adapter.Outbound]int)
	err = r.enumerateHops(root, root.Tag(), nil, nil, networksOf(root), true, &hops, seenHop)
	if err != nil {
		return nil, err
	}
	return hops, nil
}

// Leaves is Hops filtered to the exits, which is the list a caller that wants "what can carry this
// flow" should use.
func (r *Resolver) Leaves(root adapter.Outbound) ([]PathNode, error) {
	nodes, err := r.Hops(root)
	if err != nil {
		return nil, err
	}
	leaves := make([]PathNode, 0, len(nodes))
	for _, node := range nodes {
		if node.Exit {
			leaves = append(leaves, node)
		}
	}
	return leaves, nil
}

func (r *Resolver) enumerateHops(node adapter.Outbound, rootTag string, chain []adapter.Outbound, physicalPath []string, required []string, isCurrent bool, hops *[]PathNode, seenHop map[adapter.Outbound]int) error {
	chain = append(chain, node)
	group, isGroup := node.(adapter.OutboundGroup)
	if isGroup {
		// A group is a control-plane object. It contributes to the CONTROL route only, and never
		// to the physical chain: it never carries a byte. What it DOES contribute to a hop is the
		// requirement - a group advertises the union of its members' networks to its own parents,
		// so every member below it must be able to serve what it advertises.
		required = networksOf(group)
		// The member the group DECLARED as its selection is the one the flow takes right now.
		// Reading the declaration rather than asking Selected() is what lets the report distinguish
		// "the live path" from "another reachable member" without consuming a preview; a group
		// whose declaration does not answer leaves every member unflagged, which is the honest
		// answer for a group whose choice is per flow.
		selectedTag := r.selectedTag(group)
		for _, memberTag := range r.candidatesOf(group) {
			member, reason := r.lookupDependency(memberTag)
			if member == nil {
				// A member that does not resolve becomes a hop-shaped fact, so the report names it
				// with the route that reaches it instead of dropping it here.
				*hops = append(*hops, PathNode{
					Root:             rootTag,
					ControlPath:      groupTags(chain),
					PhysicalPath:     append([]string(nil), physicalPath...),
					Tag:              memberTag,
					Outbound:         nil,
					RequiredNetworks: append([]string(nil), required...),
					Exit:             true,
					IsCurrent:        isCurrent && selectedTag == memberTag,
					Resolved:         false,
					Position:         len(physicalPath),
				})
				_ = reason
				continue
			}
			// The cycle check runs BEFORE the recursion, and before the deduplication below could
			// collapse it into "already seen": a cycle must be reported with its chain, because a
			// configuration that closes one starts successfully and then never returns a
			// connection. This is a back edge on the DECLARED membership and the DECLARED
			// dependencies - the same edges the start-order sort and the cross-kind validator read
			// - not a second graph.
			if containsNode(chain, member) {
				return cycleObjectsError(chain, member)
			}
			err := r.enumerateHops(member, rootTag, chain, physicalPath, required,
				isCurrent && selectedTag == memberTag, hops, seenHop)
			if err != nil {
				return err
			}
		}
		return nil
	}
	// A physical hop. Deduplicated by IDENTITY, so a diamond in the graph - two routes reaching one
	// object, which is legal - does not produce the same node twice.
	if _, present := seenHop[node]; present {
		return nil
	}
	physicalPath = append(append([]string(nil), physicalPath...), node.Tag())
	seenHop[node] = len(*hops)
	dependencyTag := firstDependency(node)
	visited := PathNode{
		Root:             rootTag,
		ControlPath:      groupTags(chain),
		PhysicalPath:     physicalPath,
		Tag:              node.Tag(),
		Outbound:         node,
		RequiredNetworks: append([]string(nil), required...),
		Exit:             dependencyTag == "",
		IsCurrent:        isCurrent,
		Resolved:         true,
		Position:         len(physicalPath) - 1,
	}
	*hops = append(*hops, visited)
	if dependencyTag == "" {
		return nil
	}
	dependency, _ := r.lookupDependency(dependencyTag)
	if dependency == nil {
		// The dependency does not exist. The enumeration stops here rather than inventing the hop;
		// Validate reports the missing tag through Build, which reads the same edge.
		return nil
	}
	if containsNode(chain, dependency) {
		// A cycle. Reported with its chain rather than followed, and reported BEFORE the
		// deduplication above would have collapsed it into "already seen" - a configuration error
		// that starts successfully and then never returns a connection must not be swallowed.
		return cycleObjectsError(chain, dependency)
	}
	return r.enumerateHops(dependency, rootTag, chain, physicalPath, required, isCurrent, hops, seenHop)
}

// groupTags renders the CONTROL nodes of a descent, which is what a leaf's control path is: the
// physical hops on the way are in PhysicalPath, not here.
func groupTags(chain []adapter.Outbound) []string {
	tags := make([]string, 0, len(chain))
	for _, element := range chain {
		if _, isGroup := element.(adapter.OutboundGroup); isGroup {
			tags = append(tags, element.Tag())
		}
	}
	return tags
}

// selectedTag reports the member a group DECLARED as its selection, or "".
//
// # Why the declaration and not Selected()
//
// A dry run must not take even a preview: the report only needs to say which reachable member is
// the live one, and that is a fact the group already publishes. adapter.Referrer is that
// publication for the two group types that have a single current choice - a selector and a urltest
// both report exactly the member they selected - and a group that reports nothing, or reports more
// than one reference, is one whose choice is per flow (a loadbalance). For those the honest answer
// is "no member is flagged as current", which is what this returns "" for.
func (r *Resolver) selectedTag(group adapter.OutboundGroup) string {
	referrer, isReferrer := group.(adapter.Referrer)
	if !isReferrer {
		return ""
	}
	references := referrer.References()
	if len(references) != 1 {
		return ""
	}
	return references[0]
}

// candidatesOf reports every member tag a group can reach.
//
// All() and References() are UNIONED rather than chosen between, because the two answer different
// questions and either can be the wider one: OutboundGroup.All is the membership the group
// materialises, while Referrer.References is the subset the group currently DEPENDS on - a
// selector reports only the member it selected, a loadbalance reports all of them. Enumerating the
// dependency subset alone would miss exactly the members this dry run exists to check, and
// enumerating the membership alone would miss a reference a group holds without listing. Both are
// declarations, so neither has to be asked for a selection.
func (r *Resolver) candidatesOf(group adapter.OutboundGroup) []string {
	if r.snapshot.Candidates != nil {
		if declared, present := r.snapshot.Candidates[group.Tag()]; present {
			return declared
		}
	}
	candidates := make([]string, 0, 4)
	appendTag := func(tag string) {
		if !slices.Contains(candidates, tag) {
			candidates = append(candidates, tag)
		}
	}
	for _, tag := range group.All() {
		appendTag(tag)
	}
	if referrer, isReferrer := group.(adapter.Referrer); isReferrer {
		for _, tag := range referrer.References() {
			appendTag(tag)
		}
	}
	return candidates
}

func tagChain(chain []adapter.Outbound) []string {
	if len(chain) == 0 {
		return nil
	}
	tags := make([]string, 0, len(chain))
	for _, element := range chain {
		tags = append(tags, element.Tag())
	}
	return tags
}

// cycleObjectsError names a loop from the object it closes on. It is the identity-based form, used
// by the descent that carries live objects rather than tags.
func cycleObjectsError(chain []adapter.Outbound, node adapter.Outbound) error {
	start := 0
	for index, element := range chain {
		if element == node {
			start = index
			break
		}
	}
	names := tagChain(chain[start:])
	names = append(names, node.Tag())
	return errCycle(strings.Join(names, " -> "))
}
