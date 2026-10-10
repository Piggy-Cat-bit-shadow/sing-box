package physicalpath

import (
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

// PathNode is one node the reachable-leaf enumeration visited, at the position it occupies ON ONE
// ROUTE.
//
// # One entry per (node, ROUTE), not one per node
//
// A legal object graph is a DAG, not a tree: two groups may both hold the same leaf, and the same
// leaf may sit at a different physical position under each of them. Everything below that is not a
// property of the OBJECT is therefore a property of the route:
//
//   - RequiredNetworks is what the group ABOVE this node on THIS route advertises, so route A can
//     require TCP of a leaf while route B requires UDP of the very same object;
//   - PhysicalPath and Position are where the node sits on THIS route;
//   - ControlPath and IsCurrent belong to ONE descent.
//
// Enumerating one entry per object instead collapses those routes into whichever one was walked
// first, and the second route's contract is then never validated - a start-time report that says
// "reachable" about a route that would fail on the first flow.
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

// DefaultNodeBudget is the number of nodes one Hops enumeration will visit before it REFUSES.
//
// # Why there is a budget at all
//
// Enumerating one entry per (node, route) pair is what makes a diamond correct, and a graph built
// out of layers of parallel groups has exponentially many pairs: a graph of k layers of two
// parallel groups has 2^k routes. Termination is guaranteed without a budget - a finite graph has
// no infinite acyclic path, and a back edge onto the current descent is reported as a cycle - but
// termination is not the same as finishing in useful time.
//
// # What the budget does, stated exactly
//
// It REFUSES. Hops returns an error naming the budget and saying that the remaining routes were NOT
// validated, and no partial node list is returned. A truncated enumeration is not a report: the one
// claim it exists to support - "every route reachable under this root was validated" - is exactly
// the claim a truncated list cannot support, so answering with a prefix would be worse than
// answering with nothing.
//
// The value is far above any plausible configuration (a graph of a thousand outbounds reaches this
// only through combinatorial explosion), and a caller that legitimately needs more raises it with
// Resolver.WithNodeBudget rather than editing this constant.
const DefaultNodeBudget = 65536

// WithNodeBudget returns a resolver whose Hops enumeration visits at most max nodes before it
// refuses. The receiver is NOT modified. A max of zero or less restores DefaultNodeBudget.
//
// It exists so the guard is a property of the resolver a caller built rather than a process-wide
// switch, and so a test can prove the refusal without building an exponentially large graph.
func (r *Resolver) WithNodeBudget(max int) *Resolver {
	return r.configure(func(configured *Resolver) {
		if max <= 0 {
			configured.nodeBudget = DefaultNodeBudget
			return
		}
		configured.nodeBudget = max
	})
}

// enumeration is the state of ONE Hops call: the nodes it has produced and the budget it is
// spending.
//
// # Why the state is here rather than on the Resolver
//
// The same reason Build's per-walk state is in a walkScope: this is state of a CALL, not of a view,
// and a Resolver is documented as safe to share. Nothing in this struct is reachable from another
// call, so two enumerations cannot interfere - and the budget cannot be spent twice.
type enumeration struct {
	resolver *Resolver
	hops     []PathNode
	visited  int
	budget   int
}

func newEnumeration(resolver *Resolver) *enumeration {
	budget := resolver.nodeBudget
	if budget <= 0 {
		budget = DefaultNodeBudget
	}
	return &enumeration{resolver: resolver, hops: make([]PathNode, 0, 4), budget: budget}
}

// errNodeBudgetExceeded is the refusal. It names what was NOT done, because "the enumeration
// stopped" and "the configuration is wrong" are different statements and only one of them is true.
func errNodeBudgetExceeded(rootTag string, budget int) error {
	return E.New("outbound/", rootTag, ": the reachable leaf enumeration exceeded its node budget of ",
		itoa(budget), " nodes; the graph has more (node, route) pairs than this diagnostic will visit, "+
			"so the remaining routes were NOT validated - raise the budget with "+
			"Resolver.WithNodeBudget if this configuration is legitimate")
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
// # One entry per route
//
// A node reached by two routes is enumerated TWICE, once per route, because the two routes require
// different things of it and may reach it at different positions. A caller that wants "the distinct
// objects" de-duplicates by Tag; a caller that wants "what can carry this flow" must not, which is
// why the enumeration itself does not.
//
// # Read-only
//
// The walk dials nothing, resolves nothing and starts nothing, and it consumes no group state: the
// members come from the group's own DECLARED list (adapter.Referrer.References and
// OutboundGroup.All), not from Selected, so not even a preview is taken. It is bounded by the
// object graph and by DefaultNodeBudget, and a cycle is reported rather than followed, so a
// malformed configuration cannot make it spin.
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
	scope := newEnumeration(r)
	err = scope.enumerateHops(root, root.Tag(), nil, nil, networksOf(root), true)
	if err != nil {
		// The enumeration is discarded rather than partially reported: see DefaultNodeBudget.
		return nil, err
	}
	return scope.hops, nil
}

// Leaves is Hops filtered to the exits, which is the list a caller that wants "what can carry this
// flow" should use.
//
// A leaf reachable by several routes appears once per route, each entry carrying its own route,
// requirement and position: that is the list of things to validate, not the list of distinct
// objects.
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

func (e *enumeration) enumerateHops(node adapter.Outbound, rootTag string, chain []adapter.Outbound, physicalPath []string, required []string, isCurrent bool) error {
	e.visited++
	if e.visited > e.budget {
		return errNodeBudgetExceeded(rootTag, e.budget)
	}
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
		selectedTag := e.resolver.selectedTag(group)
		for _, memberTag := range e.resolver.candidatesOf(group) {
			member, reason := e.resolver.lookupDependency(memberTag)
			if member == nil {
				// A member that does not resolve becomes a hop-shaped fact, so the report names it
				// with the route that reaches it instead of dropping it here.
				e.hops = append(e.hops, PathNode{
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
			// The cycle check runs BEFORE the recursion, and it reads the CURRENT descent rather
			// than a set of everything already visited: a node another route already reached is a
			// diamond - a legal graph that must be enumerated again for that route - while a node
			// on THIS descent is a back edge, and a configuration that closes one starts
			// successfully and then never returns a connection. This is a back edge on the DECLARED
			// membership and the DECLARED dependencies - the same edges the start-order sort and the
			// cross-kind validator read - not a second graph.
			if containsNode(chain, member) {
				return cycleObjectsError(chain, member)
			}
			err := e.enumerateHops(member, rootTag, chain, physicalPath, required,
				isCurrent && selectedTag == memberTag)
			if err != nil {
				return err
			}
		}
		return nil
	}
	// A physical hop. It is recorded ONCE PER ROUTE, which is the whole point: the same object
	// reached by a second route carries different requirements, a different physical chain and a
	// different position there, and collapsing the two would silently drop the second route's
	// contract. Only the pure properties of the object - its type, whether it is an exit, whether it
	// resolves - are the same on both routes.
	physicalPath = append(append([]string(nil), physicalPath...), node.Tag())
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
	e.hops = append(e.hops, visited)
	if dependencyTag == "" {
		return nil
	}
	dependency, _ := e.resolver.lookupDependency(dependencyTag)
	if dependency == nil {
		// The dependency does not exist. The enumeration stops here rather than inventing the hop;
		// Validate reports the missing tag through Build, which reads the same edge.
		return nil
	}
	if containsNode(chain, dependency) {
		// A cycle. Reported with its chain rather than followed, and detected against the CURRENT
		// descent - not against the set of nodes some route already visited, which would report a
		// legal diamond as a cycle. A configuration error that starts successfully and then never
		// returns a connection must not be swallowed.
		return cycleObjectsError(chain, dependency)
	}
	return e.enumerateHops(dependency, rootTag, chain, physicalPath, required, isCurrent)
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
