package group

import (
	"context"
	"errors"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// Live dial failure feedback and the bounded failover retry.
//
// # The gap this closes
//
// A balancing group chooses a member and hands the flow to that member's own data plane,
// and the route path dials the chosen leaf itself - so the group never learns whether the
// choice worked. A member a probe marked healthy that then times out on live traffic is
// reported to the caller and forgotten, on every flow, for as long as the outage lasts.
//
// # Why the feedback is a penalty and not a health verdict
//
// A real connection failing is not a measurement of the node. The destination can refuse,
// the remote can reset, the caller can give up - a node that carried the connection
// perfectly produces all of those. Only a failure that says something about the PATH
// between this process and the member earns a penalty, and the penalty only DEMOTES; it
// never deletes health evidence, because deleting a correct measurement because a website
// was down is how a group moves to a worse node.
//
// # What is deliberately stronger than the reference
//
// The reference implementation classifies unreachable-host and network-unreachable errors
// as path-dead and keeps the resulting penalty for ever. On a Wi-Fi-to-cellular handover
// every member dialled during the transition earns one of those errors, and because only a
// successful dial clears a penalty, the whole group stays demoted afterwards. Two
// mechanisms below answer that: the ledger is scoped to the network GENERATION the
// coordinator publishes, and a record expires on its own. Both are described where they are
// implemented.

// loadBalancePenaltyThreshold is the failure count at which a member is demoted.
//
// Three, because one path-dead failure is not evidence: a single timeout is as likely to be
// a transient on a working path as a dead one, and the retry already replaces the flow. Three
// failures with no success in between is a member that is not carrying traffic, and the cost
// of being wrong is bounded - a demoted member is still an ALTERNATE, so it keeps earning
// proof of life rather than being locked out.
const loadBalancePenaltyThreshold = 3

// loadBalancePenaltyTTL is how long a failure record may keep demoting its member.
//
// The reference has no such bound, and that is a defect: a penalty is only ever cleared by a
// successful dial, so a transient that no probe ever revisits - a member that is simply never
// chosen again, or a group whose URL is unreachable so nothing re-measures - demotes for the
// life of the process. A TTL is safe precisely because demotion is not exclusion: the member
// remains dialable as an alternate, which is the only way it can clear the record in the
// reference, and expiry only restores it to the primary rotation it would have had.
//
// Two minutes is short on purpose. It is the same window as the forced-retest throttle, so an
// expired record has had at least one chance to be contradicted by a measurement before it
// stops applying.
const loadBalancePenaltyTTL = 2 * time.Minute

// loadBalanceForcedRetestInterval throttles the forced health round a demotion asks for.
//
// It is measured from the END of the previous forced round, not its start: a round that took
// a minute to time out every member would otherwise leave a window already half consumed and
// let the next burst start another immediately. A burst of failures within one window is one
// round.
const loadBalanceForcedRetestInterval = 2 * time.Minute

// isPathDeadDialError classifies a dial failure.
//
// It answers exactly one question: does this failure say something about the PATH to the
// member, as opposed to the destination or the caller? The answer decides whether the group
// is allowed to conclude anything about its own choice.
//
// NEUTRAL - never penalised, because the node answered or the caller withdrew:
//
//	nil                  no failure at all
//	context.Canceled     the caller gave up; a second member cannot help
//	ECONNREFUSED         the destination (or the member's listener) answered and refused
//	ECONNRESET           something on the path answered and then closed
//
// PATH DEAD - penalised, because the attempt never reached an answer:
//
//	context.DeadlineExceeded, os.ErrDeadlineExceeded   the attempt timed out
//	EHOSTUNREACH, ENETUNREACH, ETIMEDOUT               the path itself is gone
//	any net.Error whose Timeout() reports true         the dialer's own timeout
//
// The list is consulted with errors.Is/errors.As, so a wrapped error is classified by its
// cause rather than by the message some layer above it added.
func isPathDeadDialError(err error) bool {
	if err == nil {
		return false
	}
	// The neutral set first: these are the failures a second member cannot fix, and reading
	// one of them as evidence about the path is the mistake that makes a group chase a
	// destination's outage.
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ETIMEDOUT) {
		return true
	}
	var netError net.Error
	if errors.As(err, &netError) && netError.Timeout() {
		return true
	}
	return false
}

// loadBalancePenalty is one member's failure record.
type loadBalancePenalty struct {
	count      int
	recordedAt time.Time
	expiresAt  time.Time
}

// loadBalancePenaltyTable is an immutable snapshot of the failure ledger.
//
// # Why the generation lives on the table and not in each record
//
// Every write rebuilds the whole table, so a table can only ever contain records made in one
// generation: a write against a table from an older generation starts a new one instead of
// extending it. That makes the generation a property of the snapshot, and makes the read a
// single comparison rather than a comparison per member.
type loadBalancePenaltyTable struct {
	generation uint64
	entries    map[string]loadBalancePenalty
}

// loadBalancePenalties is this selection's frozen view of the ledger.
//
// now is captured once, so every member of one selection is judged against the same instant;
// re-reading the clock per member would let a member expire halfway through a walk and change
// the candidate count underneath it.
type loadBalancePenalties struct {
	table  *loadBalancePenaltyTable
	now    time.Time
	ignore bool
}

// loadBalanceAttempt is everything the strategies and the retry must agree on for one
// selection: which member a retry may not choose again, whether health filtering is
// suspended, and the failure ledger's view.
type loadBalanceAttempt struct {
	ignoreHealth bool
	penalties    loadBalancePenalties
	exclude      adapter.Outbound
}

// countOf reports the member's live penalty count, or zero when it has none, its record
// belongs to another generation, or its record has expired.
func (p loadBalancePenalties) countOf(member adapter.Outbound) int {
	if p.table == nil {
		return 0
	}
	entry, loaded := p.table.entries[member.Tag()]
	if !loaded {
		return 0
	}
	if !p.now.Before(entry.expiresAt) {
		// Expiry is evaluated here, lazily, at the moment the count would be used. There is
		// no sweeper and no timer: a group that never selects again has nothing to expire,
		// and nothing outlives the group to be cleaned up.
		return 0
	}
	return entry.count
}

// demotes reports whether the count is high enough to take the member out of candidacy.
func (p loadBalancePenalties) demotes(member adapter.Outbound) bool {
	if p.ignore {
		return false
	}
	return p.countOf(member) >= loadBalancePenaltyThreshold
}

// epoch reports the current network generation, or zero when no coordinator is installed.
//
// Zero is a real generation: a core that has never reset its network is generation zero, and
// a penalty recorded there is current. A build without a coordinator therefore keeps the
// reference behaviour - the ledger simply never crosses a generation boundary, because there
// is none.
func (g *LoadBalance) epoch() uint64 {
	if g.runtime == nil {
		return 0
	}
	return g.runtime.Epoch()
}

// penaltySelection freezes the ledger for one selection.
//
// It returns the zero value - which demotes nobody - unless a member is actually at or above
// the threshold in THIS generation. The threshold is tested from the raw records BEFORE the
// coordinator is consulted, because a demotion that does not exist is not made real by the
// generation it would have belonged to: a group whose worst member has failed once or twice
// pays one clock read, no coordinator lock and no member walk, and a group that has never
// failed a dial pays not even that.
func (g *LoadBalance) penaltySelection(members []adapter.Outbound, network string, ignoreHealth bool, exclude adapter.Outbound) loadBalancePenalties {
	table := g.penalties.Load()
	if table == nil {
		return loadBalancePenalties{}
	}
	now := g.now()
	atThreshold := false
	for _, entry := range table.entries {
		if now.Before(entry.expiresAt) && entry.count >= loadBalancePenaltyThreshold {
			atThreshold = true
			break
		}
	}
	if !atThreshold {
		return loadBalancePenalties{}
	}
	if table.generation != g.epoch() {
		// A record from generation N says nothing about generation N+1. On a handover every
		// member dialled during the transition can fail with an unreachable error, and the
		// reference keeps those penalties for ever; ignoring the whole table is what stops
		// the old network's outage from demoting the new one.
		return loadBalancePenalties{}
	}
	view := loadBalancePenalties{table: table, now: now}
	// A demotion may only take a member out while another one can take its place. This is
	// the same fail-open rule health filtering follows: a group whose every member has been
	// penalised has nothing to go on, and must dial one of them rather than refuse the flow.
	hasAlternative := false
	for _, member := range members {
		if member == exclude {
			continue
		}
		if !common.Contains(member.Network(), network) {
			continue
		}
		if g.url != "" && !ignoreHealth && !g.healthy(member, network) {
			continue
		}
		if view.countOf(member) < loadBalancePenaltyThreshold {
			hasAlternative = true
			break
		}
	}
	if !hasAlternative {
		view.ignore = true
	}
	return view
}

// emergencyOrder returns the candidate members ranked by penalty count and then by measured
// latency, or nil when the failure filter does not apply to this selection.
//
// # Why this cannot disturb the normal case
//
// It returns nil unless a member is at or above the demotion threshold and some other member
// can replace it. Below the threshold the member list is returned unwalked, so round-robin
// rotates in configuration order and the latency of a member is never consulted - a group
// that has not failed a dial cannot have its distribution changed by this feature.
//
// # Why penalised members are still in the list
//
// They are ranked last rather than dropped, because they remain dialable as alternates and
// the walk's own candidate test is what skips them. Keeping one list means the rank order and
// the candidacy decision cannot disagree.
func (g *LoadBalance) emergencyOrder(members []adapter.Outbound, network string, attempt loadBalanceAttempt) []adapter.Outbound {
	if attempt.penalties.table == nil || attempt.penalties.ignore {
		return nil
	}
	order := make([]adapter.Outbound, 0, len(members))
	for _, member := range members {
		if member == attempt.exclude {
			continue
		}
		if !common.Contains(member.Network(), network) {
			continue
		}
		if g.url != "" && !attempt.ignoreHealth && !g.healthy(member, network) {
			continue
		}
		order = append(order, member)
	}
	if len(order) < 2 {
		return nil
	}
	sort.SliceStable(order, func(i, j int) bool {
		left, right := attempt.penalties.countOf(order[i]), attempt.penalties.countOf(order[j])
		if left != right {
			return left < right
		}
		return g.measurementDelay(order[i], network) < g.measurementDelay(order[j], network)
	})
	return order
}

// measurementDelay reports the member's last measured delay, or no-evidence.
//
// An unmeasured member ranks last among equals rather than first: latency is only a
// tie-breaker between members the ledger considers equally reliable, and preferring the one
// nothing is known about would make the filter choose on the absence of evidence.
func (g *LoadBalance) measurementDelay(member adapter.Outbound, network string) uint16 {
	if g.history == nil || g.healthScope.IsZero() {
		return math.MaxUint16
	}
	history := g.history.LoadURLTestHistoryFor(RealTag(member, network), g.healthScope)
	if history == nil {
		return math.MaxUint16
	}
	return history.Delay
}

// recordPenalty adds one failure to the member's record and reports the new count.
//
// # Why the table is rebuilt rather than mutated
//
// The selection path reads the ledger without a lock, so a writer cannot be mutating the map
// it reads. A new immutable table published with one atomic store gives readers a consistent
// snapshot for the cost of a pointer load, and keeps the write - which only happens on a
// failed dial - behind a mutex where a read-modify-write is safe.
//
// The write is where the generation is enforced as well as observed: extending a table from
// another generation would carry the old network's failures into the new one, so an
// out-of-generation table is replaced instead of updated.
func (g *LoadBalance) recordPenalty(member adapter.Outbound) int {
	generation := g.epoch()
	now := g.now()
	tag := member.Tag()
	g.penaltyWrite.Lock()
	defer g.penaltyWrite.Unlock()
	current := g.penalties.Load()
	var entries map[string]loadBalancePenalty
	if current != nil && current.generation == generation {
		entries = make(map[string]loadBalancePenalty, len(current.entries)+1)
		for existingTag, entry := range current.entries {
			entries[existingTag] = entry
		}
	} else {
		entries = make(map[string]loadBalancePenalty, 1)
	}
	entry := entries[tag]
	if !now.Before(entry.expiresAt) {
		// An expired record is forgotten, not extended. Continuing its count would let a
		// single fresh failure re-arm a demotion that the TTL had already answered.
		entry = loadBalancePenalty{}
	}
	entry.count++
	entry.recordedAt = now
	entry.expiresAt = now.Add(loadBalancePenaltyTTL)
	entries[tag] = entry
	g.penalties.Store(&loadBalancePenaltyTable{generation: generation, entries: entries})
	return entry.count
}

// recordProofOfLife clears the member's record after a successful dial.
//
// This is the ONLY thing a successful dial is allowed to conclude: that this member's path
// works right now. It does not touch health evidence, and it does not touch another member's
// record.
func (g *LoadBalance) recordProofOfLife(member adapter.Outbound) {
	current := g.penalties.Load()
	if current == nil || current.generation != g.epoch() {
		return
	}
	tag := member.Tag()
	if _, loaded := current.entries[tag]; !loaded {
		// The common case: a successful dial by a member that has never failed. Nothing to
		// clear, so nothing is locked and nothing is allocated.
		return
	}
	g.penaltyWrite.Lock()
	defer g.penaltyWrite.Unlock()
	current = g.penalties.Load()
	if current == nil || current.generation != g.epoch() {
		return
	}
	if _, loaded := current.entries[tag]; !loaded {
		return
	}
	entries := make(map[string]loadBalancePenalty, len(current.entries))
	for existingTag, entry := range current.entries {
		if existingTag == tag {
			continue
		}
		entries[existingTag] = entry
	}
	g.penalties.Store(&loadBalancePenaltyTable{generation: current.generation, entries: entries})
}

// loadBalanceRetestValve throttles the forced health round a demotion asks for.
//
// It is an atomic state machine and not a timer or a goroutine: a timer per penalty is a
// resource that has to be cancelled on close and can outlive the group, and the whole point
// of evaluating expiry lazily is that this feature owns no background work of its own.
type loadBalanceRetestValve struct {
	running atomic.Bool
	lastEnd atomic.Int64
}

// begin claims the valve for one forced round, reporting whether the caller owns it.
//
// The CAS collapses a burst: the first failure that reaches the threshold starts a round and
// every other failure in the window leaves it alone. The window is then measured from the END
// of the previous round, so a slow round cannot be immediately followed by another.
func (v *loadBalanceRetestValve) begin(now time.Time, interval time.Duration) bool {
	if !v.running.CompareAndSwap(false, true) {
		return false
	}
	if last := v.lastEnd.Load(); last != 0 && now.Sub(time.Unix(0, last)) < interval {
		v.running.Store(false)
		return false
	}
	return true
}

// end releases the valve and stamps the window from this moment.
func (v *loadBalanceRetestValve) end(now time.Time) {
	v.lastEnd.Store(now.UnixNano())
	v.running.Store(false)
}

// requestForcedRetest asks the group's own health checker for one forced round.
//
// The round runs on the group's context, so Close cancels it, and the valve means at most one
// round is in flight per window no matter how many members are failing.
func (g *LoadBalance) requestForcedRetest() {
	health := g.health.Load()
	if health == nil {
		// Nothing measures the members, so there is no round to force. The penalty still
		// demotes, and a successful dial still clears it.
		return
	}
	if !g.retest.begin(g.now(), loadBalanceForcedRetestInterval) {
		return
	}
	go func() {
		defer g.retest.end(g.now())
		health.CheckOutbounds(g.ctx, true)
	}()
}

// DialWithFailover implements adapter.FailoverOutboundGroup.
//
// One selection, one dial; on a path-dead failure, one more selection with the failed member
// excluded and one more dial. Never a third attempt, never a fresh deadline, never an
// interruption of a connection that already exists.
//
// # Why the alternate is chosen by re-running the strategy
//
// The retry is a new selection, not an index step. It therefore re-applies the strategy, the
// per-flow key, the health filter and the failure filter, and it can only ever name a member
// of this group's published list - which is what keeps a group structurally unable to fail
// over outside itself: the "AI pool" restriction in this fork is expressed by a route rule
// selecting a different group whose member list IS that pool, so a group that stayed inside
// its own list needs no separate traffic-class filter to stay in its lane.
//
// # Why the original error is what a failed retry returns
//
// Two path-dead failures are two facts, and both members are penalised for their own. The
// error the caller sees is the FIRST one, because that is the failure of the member the
// group chose: reporting the alternate's error would describe a member the caller never
// heard of and hide the fact that the preferred choice is the one that failed.
func (g *LoadBalance) DialWithFailover(ctx context.Context, metadata *adapter.InboundContext, network string, destination M.Socksaddr) (net.Conn, error) {
	members := g.snapshot()
	if len(members) == 0 {
		return nil, E.New(strings.ToUpper(network), " is not supported by outbound: ", g.Tag())
	}
	member := g.selectForFlow(members, metadata, network, true, g.attempt(members, network, nil))
	if member == nil {
		return nil, E.New(strings.ToUpper(network), " is not supported by outbound: ", g.Tag())
	}
	g.Touch()
	conn, err := g.dialMember(ctx, member, metadata, network, destination)
	if err == nil {
		g.recordProofOfLife(member)
		return g.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	if !isPathDeadDialError(err) {
		// The node answered, or the caller withdrew. A second member cannot fix either, and
		// retrying on the caller's cancellation would turn one cancelled flow into two
		// attempts on a context that is already done.
		return nil, err
	}
	if g.recordPenalty(member) >= loadBalancePenaltyThreshold {
		g.requestForcedRetest()
	}
	alternate := g.selectForFlow(members, metadata, network, true, g.attempt(members, network, member))
	if alternate == nil || alternate == member {
		// Nothing else to try: a single-member group, or every other member is unusable.
		// Reporting the original failure is the honest answer.
		return nil, err
	}
	if g.logger != nil {
		g.logger.Debug("loadbalance group ", g.Tag(), ": ", member.Tag(), " failed (", err, "), trying ", alternate.Tag())
	}
	alternateConn, alternateErr := g.dialMember(ctx, alternate, metadata, network, destination)
	if alternateErr != nil {
		if isPathDeadDialError(alternateErr) {
			// Both paths are dead, and both facts are worth keeping: the alternate failed
			// for its own reason, not because the first member did.
			g.recordPenalty(alternate)
		}
		return nil, err
	}
	g.recordProofOfLife(alternate)
	if g.logger != nil {
		// The selection move is logged because it is otherwise invisible: the connection
		// works, and only the group knows that a different member carried it. Nothing is
		// interrupted here - a connection already handed to a caller belongs to the member
		// it was given, and this decision is about the attempt that has not produced one.
		g.logger.Info("loadbalance group ", g.Tag(), ": moved a flow from ", member.Tag(), " to ", alternate.Tag(), " after a path failure")
	}
	return g.interruptGroup.NewConn(alternateConn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

// dialMember dials one selected member.
//
// A member that is itself a failover-capable group is asked to dial through its OWN policy,
// so a nested group's replacement stays inside the nested group: the outer group chose the
// nested group, and which member inside it serves the flow is the nested group's decision.
// Any other group is resolved to its leaf here - committing the nested choice, because the
// connection this is for is real - and the leaf dials.
func (g *LoadBalance) dialMember(ctx context.Context, member adapter.Outbound, metadata *adapter.InboundContext, network string, destination M.Socksaddr) (net.Conn, error) {
	if failover, isFailover := member.(adapter.FailoverOutboundGroup); isFailover {
		return failover.DialWithFailover(ctx, metadata, network, destination)
	}
	leaf, err := loadBalanceDialLeaf(member, metadata, network)
	if err != nil {
		return nil, err
	}
	return leaf.DialContext(ctx, network, destination)
}

// loadBalanceDialLeaf resolves a selected member down to the outbound that will carry the
// connection, committing a nested group's choice on the way.
//
// It is the dial-side counterpart of ResolveURLTestLeaf: that one previews, because a
// measurement must not move a group, and this one commits, because the connection is what the
// choice is for.
func loadBalanceDialLeaf(member adapter.Outbound, metadata *adapter.InboundContext, network string) (adapter.Outbound, error) {
	visited := make(map[adapter.Outbound]struct{}, 4)
	for {
		group, isGroup := member.(adapter.OutboundGroup)
		if !isGroup {
			return member, nil
		}
		if _, seen := visited[member]; seen {
			return nil, E.New("outbound group cycle detected at ", member.Tag())
		}
		visited[member] = struct{}{}
		var next adapter.Outbound
		if flowAware, isFlowAware := group.(adapter.FlowAwareOutboundGroup); isFlowAware {
			next = flowAware.SelectForFlow(metadata, network, true)
		} else {
			next = group.Selected(network)
		}
		if next == nil {
			return nil, E.New(strings.ToUpper(network), " is not supported by outbound: ", group.Tag())
		}
		member = next
	}
}
