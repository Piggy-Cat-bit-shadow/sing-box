package group

import (
	"context"
	"errors"
	"io"
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
	C "github.com/sagernet/sing-box/constant"
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
//
// # Opt-in, because behaviour is part of the configuration
//
// The feature predates its option and used to be always on, which silently rewrote
// "a timeout reports an error" into "a timeout dials another member" for every existing
// config. It is now gated on `"failover": true`: an unopted group does not even advertise
// the capability, so the route path resolves and dials it through the code that existed
// before this file. See the option's own comment for the full reasoning.
//
// # Two questions, never one errno
//
// A single classifier used to decide both whether to retry and whether to blame the member.
// Those are different questions with different right answers: RetryThisFlow is permissive and
// about the flow, PenalizeMemberGlobally is conservative and about the member's own first
// hop. They are separate functions here, and each carries the set it accepts and why.
//
// # One budget for the whole flow
//
// The retry is bounded per FLOW, not per group, through failoverAttemptState in the context:
// a nested chain spends one alternate in total, so depth cannot multiply the cost of an
// outage. The budget owns no lock, no goroutine and no timer.

// loadBalancePenaltyThreshold is the failure count at which a member is demoted.
//
// Three, because one first-hop failure is not evidence: a single refusal or lost route is as
// likely to be a transient on a working path as a dead one, and the retry already replaces the
// flow. Three failures with no success in between is a member whose own endpoint is not
// carrying traffic, and the cost of being wrong is bounded - a demoted member is still an
// ALTERNATE, so it keeps earning proof of life rather than being locked out.
//
// The threshold is only ever reached by the conservative classifier in this file: a timeout is
// never counted at all, so three is three refusals, not three website outages.
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

// RetryThisFlow reports whether another member could still carry this flow.
//
// It answers the FLOW question - "would this attempt have a chance elsewhere?" - and it is
// deliberately the more permissive of the two classifiers, because the two costs are not
// symmetric. A wrong yes costs one extra dial, bounded by the flow's own budget; a wrong no
// fails a flow while a working member sits idle. Nothing classified here has been handed to a
// caller yet, so no application byte has been delivered and a second attempt cannot replay a
// request the destination already saw.
//
// RETRY - the attempt produced no answer, or a listener refused:
//
//	context.DeadlineExceeded, os.ErrDeadlineExceeded   the attempt timed out
//	any net.Error whose Timeout() reports true         the dialer's own timeout
//	EHOSTUNREACH, ENETUNREACH, EADDRNOTAVAIL, ENETDOWN the path is gone at the kernel
//	ETIMEDOUT                                          the connect timed out in the kernel
//	ECONNREFUSED                                       a listener refused; another member's
//	                                                   listener may be up
//
// NEUTRAL - a second member cannot help, or the failure is not understood:
//
//	nil                  no failure at all
//	context.Canceled     the caller gave up; nobody is waiting for a second attempt
//	net.ErrClosed        this process tore the dial down (a group close, a network switch)
//	ECONNRESET, io.EOF   something on the path answered and then closed - which is also how a
//	                     proxy protocol reports a destination-side failure in band
//	anything unclassified
//
// The last line is the conservative default: an error this code has never heard of is not
// evidence that another member would behave differently, and retrying it would spend the
// flow's only alternate on a guess.
//
// The list is consulted with errors.Is/errors.As, so a wrapped error is classified by its
// cause rather than by the message some layer above it added.
func RetryThisFlow(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		// The caller withdrew, or this process did. A second member cannot fix either, and
		// retrying on a cancelled context would turn one cancelled flow into two attempts on
		// a context that is already done.
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) {
		// Something answered and then closed. That is the shape of a destination-side
		// failure reported in band by a proxy protocol, so it is explicitly NOT retried: an
		// alternate member would very likely reproduce it, and the flow's one alternate is
		// worth more than a second look at a target that already spoke.
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.ENETDOWN) ||
		errors.Is(err, syscall.ETIMEDOUT) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		// A refusal is the one answer that is worth a second member. On a proxying member the
		// refusal came from the member's own endpoint, and a different member's endpoint is
		// very likely listening; on a direct member it came from the destination, where the
		// extra dial costs one attempt out of a budget of two and proves the target is
		// closed. The two are indistinguishable here, and the cheap, safe reading is to try.
		return true
	}
	var netError net.Error
	if errors.As(err, &netError) && netError.Timeout() {
		return true
	}
	return false
}

// PenalizeMemberGlobally reports whether a dial failure is evidence that this MEMBER's own
// first hop is broken.
//
// It answers a different question from RetryThisFlow - "is the member's path establishment
// broken?" - and it is deliberately far narrower, because the two situations it must separate
// can produce an identical final error:
//
//	client -> member endpoint       OK
//	member -> blocked destination   timeout
//
// The DialContext error is a timeout in both cases. Reading it as "the member is dead" means a
// blocked or down destination costs a healthy member a penalty on every flow, and a client
// that retries a few times demotes that member for every destination - exactly the penalty the
// ledger then applies to a node that is carrying traffic perfectly.
//
// # What the stack does and does not tell this function
//
// There is no stage tag anywhere in the dial path: the proxy outbounds return their first-hop
// transport error unwrapped, and a destination-side failure is reported in band, on the
// connection, rather than as the dial error. So the errno alone cannot separate the two rows
// above, and this function refuses to guess from it. The one structural fact available is the
// member's own kind, used below: a member that dials the DESTINATION (direct, block) never
// gets a global verdict, because the same errno there describes the destination.
//
// GLOBAL PENALTY - kernel evidence that a first hop failed before any answer:
//
//	ECONNREFUSED    a listener on the member's endpoint refused
//	EHOSTUNREACH    no route to the member's endpoint
//	ENETUNREACH     the network carrying the member's endpoint is gone
//
// NO GLOBAL PENALTY - and this is the point of the split:
//
//	a timeout, at any layer   a first-hop timeout and a destination-side timeout are
//	                          indistinguishable in the final error, so the member keeps its
//	                          retries and only a health probe may retire it
//	EADDRNOTAVAIL, ENETDOWN   the local interface, which every member shares
//	ECONNRESET, io.EOF        something answered and closed; possibly the remote destination
//	context.Canceled          the caller withdrew
//	a destination dial        member.Type() is direct or block: the error is the destination's
//	anything unclassified
//
// The result is a ledger that fires rarely but is almost always right: a member is demoted
// only when a listener refused it or its network is gone, never because a website was down.
func PenalizeMemberGlobally(member adapter.Outbound, err error) bool {
	if err == nil || member == nil {
		return false
	}
	if memberDialsDestination(member) {
		// The member IS the destination dial. A refusal or an unreachable here describes the
		// destination, and demoting the member for a target that happened to be closed would
		// take a working outbound out of the rotation for every future flow.
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

// memberDialsDestination reports whether a failure from this member describes the flow's
// destination rather than the member's own first hop.
//
// protocol/direct and protocol/block perform the connection to the destination themselves, so
// their DialContext error IS the destination's answer. Every proxying outbound terminates the
// flow at an endpoint of its own first and only reports the remote's verdict in band, so a
// synchronous error from one of those is a first-hop error. A member that is itself a group is
// treated the same way: the group's dial is still a first hop, whichever leaf inside it
// answers.
func memberDialsDestination(member adapter.Outbound) bool {
	switch member.Type() {
	case C.TypeDirect, C.TypeBlock:
		return true
	default:
		return false
	}
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

// failoverAttemptState is one FLOW's retry budget, carried in the context.
//
// # Why the budget is per-flow context state
//
// The retry belongs to a user flow, not to a group call. A flow through outer -> inner must
// make at most two dial attempts in total, and a per-group bound multiplies with nesting:
// outer attempt #1 -> inner #1, inner #2; outer alternate -> inner #3, inner #4. A
// package-level counter would be shared by unrelated flows; a parameter would have to be
// threaded through every caller, including the route path, which has no retry of its own to
// name; and a mutex would be needed for either. The context is the one channel every attempt
// already shares, and deriving it inside the outermost capability dial makes it per-flow by
// construction.
//
// The state is touched only on the flow's own sequential path - a dial returns before its
// retry begins - so it owns no lock, no atomic, no goroutine and no timer. The zero value is
// not a usable budget: one is created with exactly one alternate for the whole flow.
type failoverAttemptState struct {
	remainingAlternates int
}

// failoverAttemptStateKey is the context key for the budget.
//
// It is an unexported struct type, so no other package can install a budget the group would
// then trust: only the group's own outermost dial can start one, and the group is the only
// code that can widen it.
type failoverAttemptStateKey struct{}

// failoverBudget returns the flow's budget and a context carrying it, creating the budget when
// this call is the outermost capability dial.
//
// "Outermost" is identified by the ABSENCE of a budget, not by a flag: a nested group called
// with the derived context finds the existing one and consumes it, which is exactly what stops
// nesting from multiplying the alternates. Creation installs the budget on a context derived
// for this call only, so two concurrent flows that share a parent context never share a
// budget.
func failoverBudget(ctx context.Context) (context.Context, *failoverAttemptState) {
	budget, loaded := ctx.Value(failoverAttemptStateKey{}).(*failoverAttemptState)
	if loaded && budget != nil {
		return ctx, budget
	}
	budget = &failoverAttemptState{remainingAlternates: 1}
	return context.WithValue(ctx, failoverAttemptStateKey{}, budget), budget
}

// FailoverEnabled implements adapter.FailoverOutboundGroup.
//
// It reports the configuration's choice, read once at construction. The route path and a
// parent group both refuse to use the retry when it is false, so a configuration that predates
// the option keeps the single attempt it had before the capability existed.
func (g *LoadBalance) FailoverEnabled() bool {
	return g.failover
}

// DialWithFailover implements adapter.FailoverOutboundGroup.
//
// One selection, one dial; on a failure that leaves another member worth trying, one more
// selection with the failed member excluded and one more dial. Never a third attempt, never a
// fresh deadline, never an interruption of a connection that already exists.
//
// # Why the two classifiers are separate
//
// The retry decision (RetryThisFlow) is about the flow and may be permissive; the penalty
// decision (PenalizeMemberGlobally) is about the member and must be conservative. They were
// once one errno test, which is how a destination that was merely down could demote a healthy
// member for every flow. See the two functions for the sets and the reasoning.
//
// # Why the budget is consumed only after every check
//
// The alternate is the flow's last dial, so it is not spent until a dial is actually about to
// happen: a failure that is not retryable, an exhausted budget, a caller whose deadline is
// already gone, and a selection that can name nobody all return before the counter moves.
// That is what makes "a cancellation does not consume a retry it then does not use" true
// rather than incidental.
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
// Two failed attempts are two facts, and each member is penalised for its own. The error the
// caller sees is the FIRST one, because that is the failure of the member the group chose:
// reporting the alternate's error would describe a member the caller never heard of and hide
// the fact that the preferred choice is the one that failed.
func (g *LoadBalance) DialWithFailover(ctx context.Context, metadata *adapter.InboundContext, network string, destination M.Socksaddr) (net.Conn, error) {
	if !g.failover {
		// Both call sites refuse to reach here on an unopted group, so this is the honest
		// answer for a direct caller rather than a business path: one committed selection,
		// one dial, and not one touch of the failure ledger, which is the behaviour the group
		// had before the retry existed.
		return g.dialOnce(ctx, metadata, network, destination)
	}
	ctx, budget := failoverBudget(ctx)
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
	if !RetryThisFlow(err) {
		// The node answered, or the caller withdrew. A second member cannot fix either, and
		// the flow's one alternate is not spent on it.
		return nil, err
	}
	if PenalizeMemberGlobally(member, err) {
		if g.recordPenalty(member) >= loadBalancePenaltyThreshold {
			g.requestForcedRetest()
		}
	}
	if budget.remainingAlternates <= 0 {
		// A nested group already spent the flow's alternate on its own retry. The budget is
		// what turns "one alternate per group" into "one alternate per flow": without it this
		// branch would dial a second chain and a two-level nesting could reach four attempts.
		return nil, err
	}
	if ctx.Err() != nil {
		// The caller's deadline is already gone (or the flow was cancelled) after the first
		// attempt. Starting a second on a context that can no longer complete would spend the
		// alternate to produce nothing, so the budget is left intact.
		return nil, err
	}
	alternate := g.selectForFlow(members, metadata, network, true, g.attempt(members, network, member))
	if alternate == nil || alternate == member {
		// Nothing else to try: a single-member group, or every other member is unusable.
		// Reporting the original failure is the honest answer.
		return nil, err
	}
	budget.remainingAlternates--
	if g.logger != nil {
		g.logger.Debug("loadbalance group ", g.Tag(), ": ", member.Tag(), " failed (", err, "), trying ", alternate.Tag())
	}
	alternateConn, alternateErr := g.dialMember(ctx, alternate, metadata, network, destination)
	if alternateErr != nil {
		if PenalizeMemberGlobally(alternate, alternateErr) {
			// Both first hops failed, and both facts are worth keeping: the alternate failed
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

// dialOnce is the pre-failover behaviour: one committed selection, one dial, no ledger and no
// retry.
//
// It exists so the compatibility guarantee has a single implementation to point at. A group
// that did not opt in reaches it through DialWithFailover's guard, and the route path reaches
// the equivalent behaviour by never asking for the capability at all.
func (g *LoadBalance) dialOnce(ctx context.Context, metadata *adapter.InboundContext, network string, destination M.Socksaddr) (net.Conn, error) {
	member := g.SelectForFlow(metadata, network, true)
	if member == nil {
		return nil, E.New(strings.ToUpper(network), " is not supported by outbound: ", g.Tag())
	}
	g.Touch()
	conn, err := g.dialMember(ctx, member, metadata, network, destination)
	if err != nil {
		return nil, err
	}
	return g.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

// dialMember dials one selected member.
//
// A member that is itself an OPTED-IN failover-capable group is asked to dial through its OWN
// policy, so a nested group's replacement stays inside the nested group: the outer group chose
// the nested group, and which member inside it serves the flow is the nested group's decision.
// The nested call receives the same context, so it consumes the flow's shared budget instead of
// starting a second one.
//
// A group that did NOT opt in - and any leaf - is resolved here, committing the nested choice,
// because the connection this is for is real, and dialled exactly once. The opt-in of a member
// is the member's own decision: an outer group cannot enable a nested group's retry.
func (g *LoadBalance) dialMember(ctx context.Context, member adapter.Outbound, metadata *adapter.InboundContext, network string, destination M.Socksaddr) (net.Conn, error) {
	if failover, isFailover := member.(adapter.FailoverOutboundGroup); isFailover && failover.FailoverEnabled() {
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
