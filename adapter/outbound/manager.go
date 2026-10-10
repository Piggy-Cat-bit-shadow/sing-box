package outbound

import (
	"context"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/physicalpath"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.OutboundManager = (*Manager)(nil)

type Manager struct {
	registry                adapter.OutboundRegistry
	endpoint                adapter.EndpointManager
	defaultTag              string
	access                  sync.RWMutex
	outbounds               []adapter.Outbound
	outboundByTag           map[string]adapter.Outbound
	defaultOutbound         adapter.Outbound
	defaultOutboundFallback func() (adapter.Outbound, error)
	physicalPath            *physicalPathValidation
	// deliveredNetworks is what the ROUTES proved can reach a tag: the networks of the routing
	// rules that name it and constrain the network explicitly. A tag absent from the map has
	// nothing proven about it, which is not the same as "nothing reaches it".
	deliveredNetworks map[string][]string
}

// physicalPathValidation is everything the reachable-leaf dry run needs that is not readable from
// the outbound objects themselves.
//
// # Why the manager owns the dry run rather than the Box
//
// The manager is the only component that holds the whole outbound graph on every construction
// path, and it is the component that already refuses a circular dependency in its own namespace -
// the dry run is the same class of start-time decision, next to the sort that already exists for
// the outbound-only case. Doing it here means the check cannot be forgotten by a caller, and it
// does not duplicate anything: the sort still owns "does the dependency exist" and "is the
// outbound graph acyclic", and the dry run owns "is every reachable LEAF usable", which the sort
// cannot see because it materialises no group members.
type physicalPathValidation struct {
	declarations  physicalpath.Declarations
	resolverFor   func(tag string) string
	defaultConfig bool
}

// EnablePhysicalPathValidation installs the facts the reachable-leaf dry run needs beyond the
// outbound objects: which tags DECLARED destination_dns_ownership, and how a domain resolver is
// derived for one of them.
//
// A Manager without this runs no dry run, which is what keeps a manager built by a test or an
// embedder that has no configuration text behaving exactly as before. The Box always installs it.
func (m *Manager) EnablePhysicalPathValidation(declarations physicalpath.Declarations, resolverFor func(tag string) string, defaultDomainResolver bool) {
	m.access.Lock()
	m.physicalPath = &physicalPathValidation{
		declarations:  declarations,
		resolverFor:   resolverFor,
		defaultConfig: defaultDomainResolver,
	}
	m.access.Unlock()
}

// EnablePhysicalPathDelivery installs what the ROUTES proved can reach a tag: for each tag named by
// a routing rule that constrains the network explicitly, the set of those networks.
//
// # Why delivery is a separate fact from the declarations
//
// It is the fact that decides whether a network requirement is a PROOF or a guess. A requirement
// with no delivery behind it must not be invented - the dry run falls back to what the objects
// advertise between them - and a delivery that IS declared is what lets the dry run refuse a leaf
// that a rule delivers UDP to while it declares it carries only TCP. Installing it separately keeps
// a Manager that was never given it behaving exactly as one that has no route model at all, which
// is what every embedder that calls EnablePhysicalPathValidation alone keeps.
//
// A nil or empty map means nothing was proven, never "no requirement": the two are distinguished by
// presence, so a caller cannot accidentally forbid every network by passing nothing.
func (m *Manager) EnablePhysicalPathDelivery(delivered map[string][]string) {
	m.access.Lock()
	m.deliveredNetworks = delivered
	m.access.Unlock()
}

func NewManager(registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, defaultTag string) *Manager {
	return &Manager{
		registry:      registry,
		endpoint:      endpoint,
		defaultTag:    defaultTag,
		outboundByTag: make(map[string]adapter.Outbound),
	}
}

func (m *Manager) Initialize(defaultOutboundFallback func() (adapter.Outbound, error)) {
	m.defaultOutboundFallback = defaultOutboundFallback
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	if stage == adapter.StartStateInitialize {
		if m.defaultTag != "" && m.defaultOutbound == nil {
			defaultEndpoint, loaded := m.endpoint.Get(m.defaultTag)
			if !loaded {
				m.access.Unlock()
				return E.New("default outbound not found: ", m.defaultTag)
			}
			m.defaultOutbound = defaultEndpoint
		}
		if m.defaultOutbound == nil {
			directOutbound, err := m.defaultOutboundFallback()
			if err != nil {
				m.access.Unlock()
				return E.Cause(err, "create direct outbound for fallback")
			}
			m.outbounds = append(m.outbounds, directOutbound)
			m.outboundByTag[directOutbound.Tag()] = directOutbound
			m.defaultOutbound = directOutbound
		}
	}
	outbounds := m.outbounds
	validation := m.physicalPath
	delivered := m.deliveredNetworks
	m.access.Unlock()
	if stage == adapter.StartStateStart {
		// The start-order sort runs FIRST, and it is the same call the start itself makes.
		//
		// # Why the order between the two checks is not a detail
		//
		// The sort owns "does a declared dependency exist" and "is the declared graph acyclic", and
		// its message names the dependency chain, which is the more precise report for an outbound
		// cycle. The dry run below walks the same declared edges, so without this ordering it would
		// reach the same cycle first and replace that message with its own - a second answer to a
		// question that already has one. Running the sort here, before the outbound objects are
		// started, gives the pre-existing answer, and the dry run then owns only what the sort
		// cannot see: a group's FULL membership, which the sort never materialises.
		startable, err := m.lintOutbounds(append(append([]adapter.Outbound(nil), outbounds...),
			common.Map(m.endpoint.Endpoints(), func(it adapter.Endpoint) adapter.Outbound { return it })...))
		if err != nil {
			return err
		}
		// The reachable-leaf dry run runs HERE, after the sort and before any outbound is started.
		//
		// # Why it belongs in this manager rather than in a Box stage
		//
		// A group materialises only the member it selected. A configuration whose selector points
		// at a healthy node and whose second member is not usable therefore starts successfully and
		// fails at the FIRST SWITCH - which is decided by a health check or by a user action, so
		// the failure arrives as a traffic outage with no configuration change behind it. Running
		// the dry run here, in front of the start, on the whole graph, is the smallest place that
		// can see every member.
		//
		// It is deliberately NOT duplicated in box.go: this manager owns the outbound namespace and
		// already refuses a circular dependency in it, and a second copy of the traversal in the
		// Box would be a second answer to the same question. box.go supplies only the facts the
		// objects cannot report - see EnablePhysicalPathValidation.
		if validation != nil {
			err = m.validatePhysicalPaths(outbounds, validation, delivered)
			if err != nil {
				return err
			}
		}
		return m.startOutbounds(scope, append(outbounds, common.Map(m.endpoint.Endpoints(), func(it adapter.Endpoint) adapter.Outbound { return it })...), startable)
	}
	for _, outbound := range outbounds {
		lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
		if !isLifecycle {
			continue
		}
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		err := scope.Start(name, lifecycle, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

// validatePhysicalPaths runs the reachable-leaf dry run over the whole outbound graph.
//
// It is read-only: it dials nothing, resolves nothing, changes no selection and consumes no
// rotation. See common/physicalpath for the model and the per-leaf contract.
func (m *Manager) validatePhysicalPaths(outbounds []adapter.Outbound, validation *physicalPathValidation, delivered map[string][]string) error {
	resolver := physicalpath.NewResolver(m.Outbound, physicalpath.Snapshot{}).
		WithDomainResolvers(validation.resolverFor, validation.defaultConfig)
	// The roots are ordered so a GROUP is validated before the objects it names.
	//
	// # Why the order is not cosmetic
	//
	// One broken object is reachable by many routes: as a selector's unselected member, and as a
	// top-level outbound in its own right. Reporting it once per route turns one defect into three
	// lines that look like three defects, and the route through the group is the one that carries
	// the information an operator needs - it names the selection step that would hand the flow to
	// it. Validating the groups first and then suppressing the routes they already describe is
	// what makes the report one line per defect.
	//
	// # Why each root is validated on its own
	//
	// The requirement is a fact about ONE root - what the routes proved reaches it, or, when
	// nothing is proven, what its own reachable objects advertise. Passing one set for a batch of
	// roots is precisely the mistake that made the requirement the union of every outbound in the
	// configuration, so the set is computed per root and handed to a call for that root.
	type rootEntry struct {
		root     adapter.Outbound
		optional bool
	}
	entries := make([]rootEntry, 0, len(outbounds)+4)
	for _, outbound := range outbounds {
		if _, isGroup := outbound.(adapter.OutboundGroup); isGroup {
			entries = append(entries, rootEntry{root: outbound})
		}
	}
	for _, outbound := range outbounds {
		if _, isGroup := outbound.(adapter.OutboundGroup); isGroup {
			continue
		}
		entries = append(entries, rootEntry{root: outbound})
	}
	// The default outbound and the endpoints are roots in their own right: the default is what an
	// unmatched flow reaches, and an endpoint is a tunnel the device can be routed into directly.
	// An object a group report already described is not repeated.
	if defaultOutbound := m.Default(); defaultOutbound != nil {
		entries = append(entries, rootEntry{root: defaultOutbound, optional: true})
	}
	for _, endpoint := range m.endpoint.Endpoints() {
		entries = append(entries, rootEntry{root: endpoint, optional: true})
	}
	report := physicalpath.Report{}
	// described is the set of tags a previous root already REPRESENTED, and it is what keeps one
	// defect from being reported once per route that reaches it. It is filled from the tags this
	// root actually covers.
	described := make(map[string]bool)
	// reported is the set of ROOTS that have already contributed a failure, and it is deliberately
	// narrower than described.
	//
	// # Why the key is the root and not the leaf
	//
	// Keying on the leaf made the verdict depend on the order the outbounds were DECLARED in, and
	// suppressed a real one. MEASURED, on a configuration whose two routing rules both deliver udp
	// to one tcp-only leaf, once through a selector and once directly:
	//
	//	outbounds: [tcp-only, A(selector -> tcp-only), B(selector -> tcp-only)]
	//	rules:     {network: udp, outbound: A}, {network: udp, outbound: B}
	//
	// `tcp-only` is a declared outbound, so the manager validates it as a root FIRST and records its
	// tag in `reported`. `A` then failed against that leaf and its failure was DROPPED, so the report
	// named only `outbound/tcp-only` and never mentioned the route. Reordering the outbounds changes
	// which root is named. `Failure.Root` is what tells an operator which entry point to fix, so a
	// unit that hides it is the wrong unit.
	//
	// The duplication the mechanism exists for is one OBJECT described once per route, which the
	// `described` set already handles - a group member that is also a top-level outbound is skipped
	// as a ROOT when `described` covers its tag. `reported` is the narrow second guard that stops one
	// root contributing the same failure twice.
	//
	// # Why a verdict cannot be suppressed by a tag that never failed
	//
	// The requirement is a fact about ONE root: what the routes proved reaches it, or what its own
	// objects advertise. A tag that appeared in an earlier root's route WITHOUT failing has not
	// been judged against this root's requirement, so suppressing its failure here makes the
	// report depend on the order the outbounds happen to be declared in - the same configuration
	// refused when a dependency is listed first and accepted when it is listed last. Filtering on
	// the failures that were actually reported keeps the deduplication (one line per defect) and
	// drops the order dependence.
	reported := make(map[string]bool)
	seenRoot := make(map[adapter.Outbound]bool)
	for _, entry := range entries {
		root := entry.root
		if root == nil || seenRoot[root] {
			continue
		}
		if entry.optional && described[root.Tag()] {
			continue
		}
		seenRoot[root] = true
		rootReport, err := physicalpath.ValidateRoots(resolver, []adapter.Outbound{root}, m.endpoint, deliveredNetworksFor(delivered, root), validation.declarations)
		if err != nil {
			return err
		}
		report.Roots = append(report.Roots, rootReport.Roots...)
		report.Nodes = append(report.Nodes, rootReport.Nodes...)
		for _, failure := range rootReport.Failures {
			if reported[failure.Root] {
				continue
			}
			reported[failure.Root] = true
			report.Failures = append(report.Failures, failure)
		}
		// The set of tags this root DESCRIBED. The roots that follow must not repeat them: a
		// broken member of a group is also a top-level outbound in its own right, and reporting it
		// once per route turns one defect into three lines that look like three defects.
		for _, node := range rootReport.Nodes {
			described[node.Hop] = true
			for _, tag := range strings.Split(node.Path, " -> ") {
				described[tag] = true
			}
		}
		for _, failure := range rootReport.Failures {
			described[failure.Leaf] = true
		}
	}
	return report.Err()
}

// deliveredNetworksFor reports the networks PROVEN to reach one root, or nil when nothing is.
//
// Nil and an empty slice both mean "nothing proven" to the dry run, so a tag that no rule
// constrains is reported the same way as a tag no rule names: the requirement then comes from what
// the root's own objects advertise.
func deliveredNetworksFor(delivered map[string][]string, root adapter.Outbound) []string {
	if len(delivered) == 0 {
		return nil
	}
	return delivered[root.Tag()]
}

// lintOutbounds is the start-order sort and the per-kind dependency validation, separated from the
// start itself so it can run BEFORE the reachable-leaf dry run.
//
// It returns the topological order it computed, so an outbound is sorted exactly once per Start:
// the dry run and the checks that follow it must not pay for a second sort, and - more importantly
// - must not be able to disagree with the order the start will actually use.
//
// The two failure modes it owns are the ones it always owned: `dependency[tag] not found for
// outbound[tag]` for a declared tag that names nothing, and `circular outbound dependency: a -> b
// -> a` for a declared cycle. Both are reported from the declared DEPENDENCIES, which is the same
// edge set the dry run reads.
func (m *Manager) lintOutbounds(outbounds []adapter.Outbound) ([]adapter.Outbound, error) {
	started := make(map[string]bool, len(outbounds))
	order := make([]adapter.Outbound, 0, len(outbounds))
	for {
		canContinue := false
	startOne:
		for _, outboundToStart := range outbounds {
			outboundTag := outboundToStart.Tag()
			if started[outboundTag] {
				continue
			}
			dependencies := outboundToStart.Dependencies()
			for _, dependency := range dependencies {
				if !started[dependency] {
					continue startOne
				}
			}
			started[outboundTag] = true
			order = append(order, outboundToStart)
			canContinue = true
		}
		if len(started) == len(outbounds) {
			break
		}
		if canContinue {
			continue
		}
		currentOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
			return !started[it.Tag()]
		})
		var lintOutbound func(oTree []string, oCurrent adapter.Outbound) error
		lintOutbound = func(oTree []string, oCurrent adapter.Outbound) error {
			problemOutboundTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !started[it]
			})
			if common.Contains(oTree, problemOutboundTag) {
				return E.New("circular outbound dependency: ", strings.Join(oTree, " -> "), " -> ", problemOutboundTag)
			}
			problemOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
				return it.Tag() == problemOutboundTag
			})
			if problemOutbound == nil {
				return E.New("dependency[", problemOutboundTag, "] not found for outbound[", oCurrent.Tag(), "]")
			}
			return lintOutbound(append(oTree, problemOutboundTag), problemOutbound)
		}
		return nil, lintOutbound([]string{currentOutbound.Tag()}, currentOutbound)
	}
	return order, nil
}

// startOutbounds starts the outbounds in the order lintOutbounds computed.
//
// The order is passed in rather than recomputed: a second sort could disagree with the one the
// validation saw, and the whole point of moving the validation in front of the start is that both
// describe the same graph.
func (m *Manager) startOutbounds(scope *adapter.Scope, outbounds []adapter.Outbound, order []adapter.Outbound) error {
	started := make(map[string]bool, len(outbounds))
	for _, outboundToStart := range order {
		outboundTag := outboundToStart.Tag()
		started[outboundTag] = true
		if endpoint, isEndpoint := outboundToStart.(adapter.Endpoint); isEndpoint {
			err := m.endpoint.StartEndpoint(endpoint)
			if err != nil {
				return err
			}
			continue
		}
		lifecycle, isLifecycle := outboundToStart.(adapter.Lifecycle)
		if !isLifecycle {
			continue
		}
		name := "outbound/" + outboundToStart.Type() + "[" + outboundTag + "]"
		err := scope.Start(name, lifecycle, adapter.StartStateStart)
		if err != nil {
			return err
		}
	}
	// An endpoint attached to this manager but not part of the sorted set - which happens when an
	// endpoint is registered after the sort read the list - is still started, because the endpoint
	// manager owns its lifecycle. This preserves the previous behaviour exactly for that case.
	for _, outboundToStart := range outbounds {
		if started[outboundToStart.Tag()] {
			continue
		}
		endpoint, isEndpoint := outboundToStart.(adapter.Endpoint)
		if !isEndpoint {
			continue
		}
		if err := m.endpoint.StartEndpoint(endpoint); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Outbounds() []adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.outbounds
}

func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	m.access.RLock()
	outbound, found := m.outboundByTag[tag]
	m.access.RUnlock()
	if found {
		return outbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Default() adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultOutbound
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}

	// Reject a duplicate BEFORE constructing anything.
	//
	// Constructing first and replacing afterwards discards an object whose constructor side effects
	// cannot be undone - a bridge outbound claims a process-global slot at construction, for example
	// - and it silently runs a configuration the user did not write.
	m.access.Lock()
	if _, loaded := m.outboundByTag[tag]; loaded {
		m.access.Unlock()
		return E.New("outbound ", tag, " already exists")
	}
	m.access.Unlock()

	outbound, err := m.registry.CreateOutbound(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	// Re-check under the lock: the constructor runs outside it, so another goroutine may have
	// installed this tag meanwhile. The loser releases what it built rather than leaking it.
	if _, loaded := m.outboundByTag[tag]; loaded {
		_ = common.Close(outbound)
		return E.New("outbound ", tag, " already exists")
	}
	m.outbounds = append(m.outbounds, outbound)
	m.outboundByTag[tag] = outbound
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultOutbound == nil) {
		m.defaultOutbound = outbound
	}
	return nil
}
