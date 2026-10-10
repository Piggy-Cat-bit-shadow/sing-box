package group

import (
	"context"
	"io"
	"net"
	"slices"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterSelector(registry *outbound.Registry) {
	outbound.Register[option.SelectorOutboundOptions](registry, C.TypeSelector, NewSelector)
}

var (
	_ adapter.OutboundGroup = (*Selector)(nil)
	_ adapter.Referrer      = (*Selector)(nil)
	_ adapter.OutboundGroup = (*Selector)(nil)
	_ adapter.Referrer      = (*Selector)(nil)
)

type Selector struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	logger                       logger.ContextLogger
	tags                         []string
	defaultTag                   string
	outbounds                    map[string]adapter.Outbound
	selected                     common.TypedValue[adapter.Outbound]
	history                      *urltest.HistoryStorage
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	// preference is the evidence Start gathered about the PREFERENCE it did not commit to, in one
	// immutable value so a reader never sees half of an update and never races Start. It is nil
	// until Start has looked.
	preference atomic.Pointer[selectionPreference]
}

// selectionPreference is what the cachefile said, recorded by Start.
//
// It exists so a later reader does not have to re-read the cachefile and does not have to race
// Start to see it, and it keeps the two outcomes apart: a stored member that this selector really
// declares, and a stored member that it does not. The second is a configuration fact an operator
// needs - "your stored selection was refused" is not "you have no stored selection".
type selectionPreference struct {
	persisted string
	rejected  string
}

// SelectionState names which of the four things is known about a selector's selection.
//
// # Why these four are separate and must not be merged
//
// They are four different claims, and only the last is about traffic:
//
//	ConfiguredDefault       the initial preference in the configuration
//	PersistedSelection      the member the cachefile holds, once validated as legal
//	LiveCommittedSelection  what the live slot actually holds after Start
//	Unknown                 not enough evidence yet
//
// A report that collapses them describes a path the traffic may not take. `References` therefore
// publishes only the third, and this type is how a reader sees the other two WITHOUT being told
// they are live.
type SelectionState uint8

const (
	// SelectionUnknown means Start has not run and the configuration names no preference either.
	// The selector would fall back to the first declared member, and that is a fallback rather than
	// a preference, so it is not reported as one.
	SelectionUnknown SelectionState = iota
	// SelectionConfigured means the configuration names a default member. It is a PREFERENCE that
	// Start would install, not a commitment.
	SelectionConfigured
	// SelectionPersisted means the cachefile names a member this selector really declares. It is
	// the preference Start will restore, and it is likewise not a commitment.
	SelectionPersisted
	// SelectionCommitted means Start or SelectOutbound has put a member in the live slot. This is
	// the only state that describes the traffic.
	SelectionCommitted
)

func (s SelectionState) String() string {
	switch s {
	case SelectionConfigured:
		return "configured"
	case SelectionPersisted:
		return "persisted"
	case SelectionCommitted:
		return "committed"
	default:
		return "unknown"
	}
}

// SelectionReport is one read of a selector's selection state, with the evidence for every state it
// is not in.
//
// It is a VALUE: every field is a copy, so a caller cannot mutate the selector through it.
type SelectionReport struct {
	// State is the one state this report is in.
	State SelectionState
	// Tag is the member the state names: the committed member, or the preferred one, or "" when
	// the state names none.
	Tag string
	// ConfiguredDefault is the configuration's default, or "" when none was given.
	ConfiguredDefault string
	// Persisted is the cachefile's member, reported only when it is a legal member of this
	// selector. An illegal one is reported in PersistedRejected instead.
	Persisted string
	// PersistedRejected is the cachefile's member when it is NOT a member of this selector, so a
	// reader can tell "no stored preference" from "a stored preference that was refused".
	PersistedRejected string
	// Committed is the member the live slot holds, or "" when nothing is committed. It is non-empty
	// exactly when State is SelectionCommitted, and it is the only field that describes traffic.
	Committed string
}

// CommittedMember reports the member the live slot holds, and whether there is one.
func (r SelectionReport) CommittedMember() (string, bool) {
	return r.Committed, r.Committed != ""
}

func NewSelector(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SelectorOutboundOptions) (adapter.Outbound, error) {
	outbound := &Selector{
		Adapter:                      outbound.NewAdapter(C.TypeSelector, tag, nil, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		defaultTag:                   options.Default,
		outbounds:                    make(map[string]adapter.Outbound),
		history:                      service.PtrFromContext[urltest.HistoryStorage](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: options.InterruptExistConnections,
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}
	return outbound, nil
}

func (s *Selector) Network() []string {
	selected := s.selected.Load()
	if selected == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return selected.Network()
}

func (s *Selector) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		s.outbounds[tag] = detour
	}

	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			selected := cacheFile.LoadSelected(s.Tag())
			if selected != "" {
				detour, loaded := s.outbounds[selected]
				if loaded {
					// The stored preference is legal, so it is the one committed - AND it is
					// recorded as the preference it was, which is what SelectionStatus reports
					// when a reader wants to know where the commitment came from.
					s.preference.Store(&selectionPreference{persisted: selected})
					s.selected.Store(detour)
					return nil
				}
				// A stored member this selector does not declare. It is recorded rather than
				// dropped, because "your stored selection was refused" is a different fact from
				// "you have no stored selection", and only one of them is a configuration mistake.
				s.preference.Store(&selectionPreference{rejected: selected})
			}
		}
	}

	if s.defaultTag != "" {
		detour, loaded := s.outbounds[s.defaultTag]
		if !loaded {
			return E.New("default outbound not found: ", s.defaultTag)
		}
		s.selected.Store(detour)
		return nil
	}

	s.selected.Store(s.outbounds[s.tags[0]])
	return nil
}

func (s *Selector) All() []string {
	return s.tags
}

func (s *Selector) Selected(network string) adapter.Outbound {
	return s.selected.Load()
}

func (s *Selector) AttachConnection(closer io.Closer) func() {
	return s.interruptGroup.Add(closer, true)
}

// References publishes the member this selector has COMMITTED to, and nothing before it has one.
//
// # Why an uncommitted selector publishes nothing (#P2)
//
// This used to return the FIRST declared member while nothing was selected:
//
//	if selected == nil {
//		return s.tags[:1]
//	}
//
// and that is a claim the selector cannot make. Before Start the live slot is empty, so no member is
// live - and the first declared member is not even the preference in the ordinary case: a selector
// with `default: B` prefers B, and one whose cachefile holds B will restore B, and both were
// reported as A. Two consumers turn a one-element answer into a statement about LIVE state, because
// that is the contract `adapter.Referrer` documents and the only shape this return type has:
//
//   - common/physicalpath/leaves.go's `selectedTag` requires exactly one reference and uses it to
//     set `PathNode.IsCurrent`, "the path the root resolves to RIGHT NOW".
//   - common/physicalpath/status.go's `controlNode` sets `Decision` from it and `Committed = true`.
//
// So the lie reached a report whose whole purpose is to distinguish the live path from another
// reachable member. Returning the default instead would be the same defect wearing a better name,
// because `controlNode` maps any single reference to `Committed = true`: a CONFIGURED preference
// would be displayed as a COMMITTED one.
//
// Nothing is the honest answer, and it is the answer the siblings already give:
// URLTest.References (protocol/group/urltest.go) returns nil until a generation is selected, and
// common/physicalpath's own `testGroup` fixture returns nil for an unselected group
// (common/physicalpath/physicalpath_test.go). A consumer that needs the PREFERENCE asks
// SelectionStatus, which names it and says it is not committed.
//
// # Why this is not a dependency-graph change
//
// Neither structural reader reads this method for an outbound. The start-order sort
// (adapter/outbound/manager.go's `lintOutbounds`, and its cycle lint) and the cross-kind cycle check
// (adapter/outbound/cross_kind_cycle.go's `edges`) both walk `Dependencies()`, which for a selector
// is the whole declared tag list (outbound.Adapter.Dependencies, built from options.Outbounds) - so
// the graph they validate is unchanged by this. The cross-kind walk reads `References()` only for a
// DNS TRANSPORT, which a selector is not.
//
// route/reference.go's idle walk does follow `References()` for a Referrer outbound, and it is the
// one caller that would notice: it is reached from ReferenceManager.update, whose first run is at
// adapter.StartStateStarted - after every outbound, started at StartStateStart - so it reads a
// committed selection and never this branch. Its walk also unions nothing else for a Referrer, which
// is why the branch must not be invented here rather than merely be wrong.
func (s *Selector) References() []string {
	selected := s.selected.Load()
	if selected == nil {
		return nil
	}
	return []string{selected.Tag()}
}

// SelectionStatus reports which of the four states this selector is in, with the evidence for the
// states it is not in.
//
// # Read-only, and safe to call at any time
//
// It reads four things and mutates none: the committed member (an atomic), the preference evidence
// Start recorded (an atomic), the immutable declared tag list and default, and - only while nothing
// is committed - the cachefile, through the same read-only `LoadSelected` Start performs. It does
// NOT read the `outbounds` map, which Start fills and which therefore must not be touched from a
// diagnostics path that may run concurrently with Start; legality of a stored tag is tested against
// the DECLARED list instead. Those are the same set: Start builds `outbounds` from `tags` and fails
// outright if any tag is missing.
//
// Reading it consumes no preview, takes no selection, advances no cursor, and changes no state -
// the property `SnapshotStatus` is required to have, asserted in
// TestReadingStatusConsumesNoSelection.
func (s *Selector) SelectionStatus() SelectionReport {
	report := SelectionReport{ConfiguredDefault: s.defaultTag}
	committed := s.selected.Load()
	if preference := s.preference.Load(); preference != nil {
		// Start has looked, so its record is the evidence - including when the cachefile held
		// nothing, which Start records by leaving no member in the record.
		report.Persisted = preference.persisted
		report.PersistedRejected = preference.rejected
	} else if committed == nil {
		// Nothing is committed and Start has not looked, so the persisted preference - which is
		// real state that exists before Start - is read here.
		report.Persisted, report.PersistedRejected = s.readPersistedPreference()
	}
	if committed != nil {
		report.State = SelectionCommitted
		report.Tag = committed.Tag()
		report.Committed = committed.Tag()
		return report
	}
	switch {
	case report.Persisted != "":
		report.State = SelectionPersisted
		report.Tag = report.Persisted
	case s.defaultTag != "":
		report.State = SelectionConfigured
		report.Tag = s.defaultTag
	default:
		report.State = SelectionUnknown
	}
	return report
}

// readPersistedPreference reads the cachefile's member and reports whether this selector declares
// it.
//
// It is the one read SelectionStatus performs, and it is the same read-only `LoadSelected` Start
// performs. Legality is tested against the DECLARED tag list rather than against the `outbounds`
// map, because Start fills that map and a diagnostics path may run while it does; the two are the
// same set, since Start builds the map from the list and fails outright if a tag is missing.
func (s *Selector) readPersistedPreference() (persisted string, rejected string) {
	if s.Tag() == "" {
		return "", ""
	}
	cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
	if cacheFile == nil {
		return "", ""
	}
	stored := cacheFile.LoadSelected(s.Tag())
	if stored == "" {
		return "", ""
	}
	if slices.Contains(s.tags, stored) {
		return stored, ""
	}
	return "", stored
}

func (s *Selector) SelectOutbound(tag string) bool {
	detour, loaded := s.outbounds[tag]
	if !loaded {
		return false
	}
	if s.selected.Swap(detour) == detour {
		return true
	}
	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			err := cacheFile.StoreSelected(s.Tag(), tag)
			if err != nil {
				s.logger.Error("store selected: ", err)
			}
		}
	}
	s.interruptGroup.Interrupt(s.interruptExternalConnections)
	if s.history != nil {
		s.history.NotifyUpdated()
	}
	return true
}

func (s *Selector) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := s.selected.Load().DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

func (s *Selector) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := s.selected.Load().ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

// ResolveURLTestLeaf resolves a detour to the real leaf outbound behind it.
//
// A plain outbound resolves to itself; a group resolves to its current selection, and that
// selection may itself be a group. The result is the node that would actually carry the traffic,
// which is what a measurement's result must be attributed to.
//
// # Why this must be resolved BEFORE measuring
//
// A group's selection can change while a measurement is in flight - a periodic check may finish,
// or a failing connection may clear it. Resolving afterwards would attribute the delay to whatever
// the group had moved TO, which may never have been measured at all. The caller resolves once, up
// front, and the attribution is then a fact about the connection that was actually tested.
//
// # Cycles
//
// A configuration can describe a cycle, and the traversal must not recurse into it. Each visited
// outbound is recorded by identity, so a cycle is detected on the second visit rather than followed
// forever. The previous implementation was a bare loop with no record, so a cycle hung.
func ResolveURLTestLeaf(detour adapter.Outbound, network string) (leaf adapter.Outbound, err error) {
	// Contain a panic from the traversal itself.
	//
	// # Why the resolver and not each caller
	//
	// This walks user-configured objects: Selected() and Tag() are implemented by every group type,
	// including ones this package does not own. A panic there would otherwise reach the runtime and
	// terminate the process, and the callers are on display paths - the Clash API's node list and
	// the native UI both resolve a leaf to label a measurement - where a crash is far worse than an
	// unlabelled node.
	//
	// Recovering here covers every caller at once, including ones added later. The traversal cannot
	// return a partial answer either: either a leaf is resolved or the caller is told it could not
	// be, so no caller can act on half a chain.
	defer func() {
		if recovered := recover(); recovered != nil {
			leaf = nil
			err = E.New("resolve outbound leaf panicked: ", recovered)
		}
	}()

	if detour == nil {
		return nil, E.New("nil detour")
	}
	visited := make(map[adapter.Outbound]struct{}, 4)
	for {
		group, isGroup := detour.(adapter.OutboundGroup)
		if !isGroup {
			return detour, nil
		}
		if _, seen := visited[detour]; seen {
			return nil, E.New("outbound group cycle detected at ", detour.Tag())
		}
		visited[detour] = struct{}{}

		var next adapter.Outbound
		if flowAware, isFlowAware := group.(adapter.FlowAwareOutboundGroup); isFlowAware {
			// A preview. This traversal labels a measurement, and a measurement is not a
			// user flow: it has no metadata to balance on and it does not own the
			// connection it is about to make. Letting it consume a rotation or write an
			// affinity pin would let a health check move the member a real flow is then
			// given.
			next = flowAware.SelectForFlow(nil, network, false)
		} else {
			next = group.Selected(network)
		}
		if next == nil {
			return nil, E.New("outbound group ", group.Tag(), " has no selected member for ", network)
		}
		detour = next
	}
}

// RealTag resolves a detour to the tag of its real leaf outbound, or empty if it cannot be
// resolved.
//
// It is a convenience wrapper over ResolveURLTestLeaf: a caller that needs the outbound itself, or
// that needs to distinguish "no selection" from "cycle", should use that directly.
func RealTag(detour adapter.Outbound, network string) string {
	leaf, err := ResolveURLTestLeaf(detour, network)
	if err != nil || leaf == nil {
		return ""
	}
	return leaf.Tag()
}
