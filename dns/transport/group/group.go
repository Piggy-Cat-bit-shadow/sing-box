// Package group implements the `group` DNS server type: several member servers
// behind one tag, one selection policy, and a bounded amount of work per query.
//
// # Record model
//
// The group keeps no server states - no up/down flag, no backoff, no health
// machine - and therefore no timer to drive one. It keeps two tables of
// expiring records instead, and every read prunes them against the clock:
//
//   - an ERROR record is appended by any failed exchange, and it erases that
//     member's live wins;
//   - a WIN record (win_ttl, read only by fastest) is appended by the first
//     successful answer of a fan. A plain success erases the member's live
//     errors, which returns it to the clean set but is deliberately NOT a win:
//     if it were, the current member would self-reinforce and the group could
//     never notice that another member became faster.
//
// CLEAN means zero live errors. Lazy pruning is why no timer exists here: an
// expired record is simply not live the next time anybody asks, so there is
// nothing to schedule, nothing to cancel, and no timer goroutine per member.
//
// # Anti-storm
//
// A query fans only while at least one member is clean. With no clean member
// the query makes exactly ONE attempt against the least dirty member and never
// fans, in EVERY mode including parallel. That is what stops a burst of client
// queries from multiplying into queries x members connection attempts against a
// network where every member is already failing, and it is why the group needs
// no circuit breaker to protect the upstreams from the group itself.
//
// # Position in the stack
//
// The group is a transport like any other: it is registered in the transport
// registry, named by `dns.final` and by rules, and may contain another group.
// It sits under the DNS cache (cache keys carry the group tag), so only the
// answer the group returns is cached; the fanned answers it discards never
// reach the cache.
package group

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

const (
	ModeStable   = "stable"
	ModeFastest  = "fastest"
	ModeParallel = "parallel"

	DefaultErrorTTL = 2 * time.Minute
	DefaultWinTTL   = 5 * time.Minute

	// maxRecords caps each record slice. Counts above it are indistinguishable
	// for every decision the group makes - selection only asks whether a member
	// is clean, who has the most wins, and who has the fewest errors - while
	// the slice itself grows with every query. Without the cap a member that
	// has been dead for a week accumulates one timestamp per query for as long
	// as it stays dead, which is precisely the situation the anti-storm path
	// exists for, so the one unbounded field would grow fastest where memory is
	// already under pressure.
	maxRecords = 64
)

func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.GroupDNSServerOptions](registry, C.DNSTypeGroup, NewTransport)
}

var _ adapter.DNSTransport = (*Transport)(nil)

// member is one resolved member: its configured tag and the transport the
// manager created for it. The transport is filled in at Start, never at
// construction, because the manager may legitimately create the group before
// the servers it names.
type member struct {
	tag       string
	transport adapter.DNSTransport
}

// memberRecord is the per-member TTL record pair. It is guarded by
// Transport.access and its slices are pruned lazily on read.
type memberRecord struct {
	errors []time.Time
	wins   []time.Time
}

type Transport struct {
	dns.TransportAdapter
	ctx        context.Context
	logger     log.ContextLogger
	serverTags []string
	mode       string
	errorTTL   time.Duration
	winTTL     time.Duration

	access  sync.Mutex
	members []*member
	records map[string]*memberRecord
	current string // sticky target (stable/fastest); "" = not chosen yet
	// election is the single-flight lock for the fastest election. It is held
	// from the moment a query decides to elect until that fan has consumed
	// every participant result, so concurrent queries cannot each start an
	// election fan. collectFan clears it on every exit path, including the
	// abandoned one, which is what keeps a caller's cancellation from leaking
	// the flag forever.
	election bool
	// gen is bumped by Reset (and by a fresh Start) so a probe that began
	// before the amnesty cannot write into the tables that replaced it.
	gen int

	// runCtx is cancelled by Close so anything in flight stops. It is merged
	// with each request context in Exchange rather than replacing it, because
	// both lifetimes matter: the caller's deadline bounds the query, and the
	// transport's own lifetime must be able to cut it short at shutdown.
	runCtx    context.Context
	cancelRun context.CancelFunc
	closed    bool
}

func NewTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.GroupDNSServerOptions) (adapter.DNSTransport, error) {
	if len(options.Servers) == 0 {
		return nil, E.New("group[", tag, "]: servers is required and must not be empty")
	}
	// Both checks are decided before anything is built, and self-reference is
	// checked first: a group that lists itself is not a duplicate, it is a
	// cycle, and reporting it as "duplicate server" would hide the shape of the
	// mistake from the user.
	seen := make(map[string]bool, len(options.Servers))
	for _, serverTag := range options.Servers {
		if serverTag == tag {
			return nil, E.New("group[", tag, "]: group cannot contain itself")
		}
		if seen[serverTag] {
			return nil, E.New("group[", tag, "]: duplicate server: ", serverTag)
		}
		seen[serverTag] = true
	}
	mode := options.Mode
	switch mode {
	case "":
		mode = ModeStable
	case ModeStable, ModeFastest, ModeParallel:
	default:
		return nil, E.New("group[", tag, "]: unknown mode: ", mode, " (expected ", ModeStable, ", ", ModeFastest, " or ", ModeParallel, ")")
	}
	winTTL := time.Duration(options.WinTTL)
	if mode != ModeFastest && winTTL != 0 {
		// A warning, not an error: the field is simply unused, and refusing the
		// configuration would break a user who switches modes back and forth.
		logger.Warn("group[", tag, "]: win_ttl is only used in fastest mode, ignoring")
		winTTL = 0
	}
	if winTTL <= 0 {
		winTTL = DefaultWinTTL
	}
	errorTTL := time.Duration(options.ErrorTTL)
	if errorTTL <= 0 {
		errorTTL = DefaultErrorTTL
	}
	return &Transport{
		TransportAdapter: dns.NewTransportAdapter(C.DNSTypeGroup, tag, options.Servers),
		ctx:              ctx,
		logger:           logger,
		serverTags:       options.Servers,
		mode:             mode,
		errorTTL:         errorTTL,
		winTTL:           winTTL,
		records:          make(map[string]*memberRecord),
	}, nil
}

func (t *Transport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		if scope != nil {
			// Close is registered on the scope rather than left to the manager
			// so teardown cancels in-flight probes in the same reverse order as
			// every other transport's resources.
			scope.Add(t.Close)
		}
		return nil
	case adapter.StartStateStart:
		return t.resolveMembers(scope)
	default:
		return nil
	}
}

// resolveMembers turns the configured tags into transports and opens the
// transport lifetime. It is idempotent: a re-Start rebuilds the member list and
// replaces the record tables instead of appending to them, so a restart cannot
// duplicate members or inherit the previous run's health.
func (t *Transport) resolveMembers(scope *adapter.Scope) error {
	transportManager := service.FromContext[adapter.DNSTransportManager](t.ctx)
	if transportManager == nil {
		return E.New("group[", t.Tag(), "]: missing DNS transport manager")
	}
	members := make([]*member, 0, len(t.serverTags))
	for _, serverTag := range t.serverTags {
		rawTransport, loaded := transportManager.Transport(serverTag)
		if !loaded {
			return E.New("group[", t.Tag(), "]: DNS server not found: ", serverTag)
		}
		// Only members that perform a real network exchange may participate. A
		// member that synthesises its answer from local state can never produce
		// a transport failure, so there is nothing to fail over FROM: it would
		// answer every fan immediately and pin the group to a local answer,
		// silently defeating the remote servers the user actually asked for.
		//
		// The criterion is therefore "cannot fail over the network", and the
		// transports in this repo's registry that meet it are exactly fakeip
		// and hosts - both compute their answer locally and return it without
		// touching the network. local, mdns, dhcp and the remote transports all
		// depend on the network and are allowed; a nested group is allowed too,
		// because its own members are still network-backed.
		switch rawTransport.Type() {
		case C.DNSTypeFakeIP, C.DNSTypeHosts:
			return E.New("group[", t.Tag(), "]: server type ", rawTransport.Type(), " is not allowed in a group: ", serverTag)
		}
		members = append(members, &member{tag: serverTag, transport: rawTransport})
	}
	parent := t.ctx
	if scope != nil {
		parent = scope.Context()
	}
	runCtx, cancelRun := context.WithCancel(parent)

	t.access.Lock()
	t.members = members
	t.records = make(map[string]*memberRecord)
	t.current = ""
	t.election = false
	t.gen++
	if t.cancelRun != nil {
		t.cancelRun()
	}
	t.runCtx = runCtx
	t.cancelRun = cancelRun
	t.closed = false
	t.access.Unlock()
	return nil
}

// Close cancels anything in flight and is safe to call repeatedly.
//
// Idempotency is not a convenience here: Close is registered on the scope and
// the scope may also be closed while a caller is already closing the transport,
// so a second call is a normal event rather than a programming error. The
// member list is deliberately left in place - Close stops work, it does not
// make the transport unaddressable, and a query arriving during teardown gets
// an answer or a cancellation from its own context rather than a confusing
// "not started".
func (t *Transport) Close() error {
	t.access.Lock()
	defer t.access.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	if t.cancelRun != nil {
		t.cancelRun()
		t.cancelRun = nil
	}
	t.runCtx = nil
	return nil
}

// Reset is the network-change amnesty: both record tables, the sticky target
// and the generation drop. Members are reset by the manager's own loop, so the
// group must not fan Reset out to them; the in-flight `election` flag is left
// alone because its fan still owns it and will clear it on completion, while
// its state writes are dropped by the generation check.
func (t *Transport) Reset() {
	t.access.Lock()
	defer t.access.Unlock()
	t.records = make(map[string]*memberRecord)
	t.current = ""
	t.gen++
}

// --- record operations (all under access) ------------------------------------

func (t *Transport) recordLocked(tag string) *memberRecord {
	record := t.records[tag]
	if record == nil {
		record = &memberRecord{}
		t.records[tag] = record
	}
	return record
}

// pruneTimes drops the expired prefix of an append-ordered timestamp slice.
//
// Appends happen under access with time.Now(), so the slice is non-decreasing
// and the first live entry is the boundary: everything before it is expired,
// everything after it is live even if an older-looking neighbour was not.
func pruneTimes(times []time.Time, ttl time.Duration, now time.Time) []time.Time {
	firstLive := len(times)
	for index, at := range times {
		if now.Sub(at) < ttl {
			firstLive = index
			break
		}
	}
	return times[firstLive:]
}

// appendCapped appends while keeping at most maxRecords entries, dropping the
// oldest. The dropped entries are the least useful for every decision made from
// the slice, and the cap is what bounds memory on a permanently dead member.
func appendCapped(times []time.Time, at time.Time) []time.Time {
	times = append(times, at)
	if len(times) > maxRecords {
		times = times[len(times)-maxRecords:]
	}
	return times
}

func (t *Transport) liveErrorsLocked(tag string, now time.Time) []time.Time {
	record := t.records[tag]
	if record == nil {
		return nil
	}
	record.errors = pruneTimes(record.errors, t.errorTTL, now)
	return record.errors
}

func (t *Transport) liveWinsLocked(tag string, now time.Time) []time.Time {
	record := t.records[tag]
	if record == nil {
		return nil
	}
	record.wins = pruneTimes(record.wins, t.winTTL, now)
	return record.wins
}

// noteError records a failed exchange: an error record is written and the
// member's live wins are erased. A win must not outlive a failure, or a member
// that answered once before its upstream died would keep winning elections it
// can no longer serve. The write is generation-guarded so a probe started
// before Reset cannot poison the amnestied tables.
func (t *Transport) noteError(tag string, gen int) {
	t.access.Lock()
	defer t.access.Unlock()
	if t.gen != gen {
		return
	}
	record := t.recordLocked(tag)
	record.errors = appendCapped(record.errors, time.Now())
	record.wins = nil
}

// noteSuccess records a successful exchange: the member's live errors are
// erased, which returns it to the clean set. This is deliberately NOT a win -
// erasing errors gives the member no advantage inside the clean set, so a
// member cannot promote itself simply by being the one that was asked.
func (t *Transport) noteSuccess(tag string, gen int) {
	t.access.Lock()
	defer t.access.Unlock()
	if t.gen != gen {
		return
	}
	record := t.recordLocked(tag)
	record.errors = nil
}

// noteWin records a competitive win: only the first success of a fan earns one,
// and only fastest ever reads them.
func (t *Transport) noteWin(tag string, gen int) {
	t.access.Lock()
	defer t.access.Unlock()
	if t.gen != gen {
		return
	}
	record := t.recordLocked(tag)
	record.wins = appendCapped(record.wins, time.Now())
}

// setCurrent updates the sticky target and reports the previous value when it
// actually changed, so the caller can log a real transition rather than a
// re-selection of the member that was already current.
func (t *Transport) setCurrent(tag string, gen int) (previous string, changed bool) {
	t.access.Lock()
	defer t.access.Unlock()
	if t.gen != gen || t.current == tag {
		return "", false
	}
	previous = t.current
	t.current = tag
	return previous, true
}

// --- target selection --------------------------------------------------------

// selection is the routing decision for one query.
type selection struct {
	target *member   // single-exchange target (nil when fan is set)
	fan    []*member // fan participants (parallel / fastest election)
	// election marks the query that owns the fastest single-flight flag; it is
	// the only query allowed to mint a win and re-elect current.
	election bool
	// survival marks the no-clean-member path: exactly one attempt, never a fan.
	survival bool
	// provisional marks an election-window concurrent. It serves the query but
	// must not re-elect or overwrite current, because the election in flight is
	// the only thing entitled to do that.
	provisional bool
	gen         int
}

func (t *Transport) selectTarget() (selection, error) {
	now := time.Now()
	t.access.Lock()
	defer t.access.Unlock()

	// An Exchange may legally arrive before Start(StartStateStart) has filled
	// members. Empty members therefore means "not started" - NewTransport
	// rejects an empty server list and Start fails on any missing member, so
	// the only way to reach the pickers below with nothing to pick is to have
	// skipped Start. Answering with a retryable error is better than panicking
	// inside a picker that assumes a non-empty candidate set.
	if len(t.members) == 0 {
		return selection{}, E.New("group[", t.Tag(), "]: not started")
	}

	var clean []*member
	for _, current := range t.members {
		if len(t.liveErrorsLocked(current.tag, now)) == 0 {
			clean = append(clean, current)
		}
	}

	if len(clean) == 0 {
		// Anti-storm: one attempt against the least dirty member, in every mode.
		return selection{target: t.leastDirtyLocked(now), survival: true, gen: t.gen}, nil
	}

	switch t.mode {
	case ModeParallel:
		// No target and no elections: every query fans, nothing is written back.
		return selection{fan: append([]*member(nil), clean...), gen: t.gen}, nil
	case ModeFastest:
		best, maxWins := t.fastestCandidatesLocked(clean, now)
		if maxWins > 0 {
			return selection{target: t.stickyPickLocked(best), gen: t.gen}, nil
		}
		// Nobody has a live win, so there is nothing to rank on and the group
		// must measure. Exactly one query fans; the rest of the window goes to a
		// random clean member and is barred from writing current.
		if !t.election {
			t.election = true
			return selection{fan: append([]*member(nil), clean...), election: true, gen: t.gen}, nil
		}
		return selection{target: clean[rand.IntN(len(clean))], provisional: true, gen: t.gen}, nil
	default: // ModeStable
		return selection{target: t.stickyPickLocked(clean), gen: t.gen}, nil
	}
}

// stickyPickLocked keeps the current target while it is still a candidate and
// otherwise elects a random one. Stickiness first is what makes stable stable:
// a member that has been answering keeps answering, so an installation does not
// silently migrate to a different upstream on every query.
//
// candidates must be non-empty; selectTarget gates the empty case before any
// picker runs.
func (t *Transport) stickyPickLocked(candidates []*member) *member {
	if t.current != "" {
		for _, candidate := range candidates {
			if candidate.tag == t.current {
				return candidate
			}
		}
	}
	return candidates[rand.IntN(len(candidates))]
}

// fastestCandidatesLocked returns the clean members carrying the maximum number
// of live wins, and that maximum. A maximum of zero means nobody has a win and
// an election must run.
func (t *Transport) fastestCandidatesLocked(clean []*member, now time.Time) ([]*member, int) {
	maxWins := 0
	var best []*member
	for _, candidate := range clean {
		wins := len(t.liveWinsLocked(candidate.tag, now))
		switch {
		case wins > maxWins:
			maxWins = wins
			best = best[:0]
			best = append(best, candidate)
		case wins == maxWins:
			best = append(best, candidate)
		}
	}
	return best, maxWins
}

// leastDirtyLocked picks the survival target: fewest live errors, tie broken by
// the oldest last error, full tie randomly.
//
// It is "least dirty" rather than "random" because the member with the fewest
// recent failures is the best remaining guess, and oldest-last-error is what
// makes the survival path rotate instead of hammering one member: the member
// that just failed is the newest, so the next query tries a different one.
//
// members must be non-empty; selectTarget gates the empty case before any picker
// runs.
func (t *Transport) leastDirtyLocked(now time.Time) *member {
	var (
		best      []*member
		bestCount = -1
		bestLast  time.Time
	)
	for _, candidate := range t.members {
		errs := t.liveErrorsLocked(candidate.tag, now)
		count := len(errs)
		var last time.Time
		if count > 0 {
			last = errs[count-1]
		}
		switch {
		case bestCount == -1 || count < bestCount || (count == bestCount && last.Before(bestLast)):
			best = best[:0]
			best = append(best, candidate)
			bestCount = count
			bestLast = last
		case count == bestCount && last.Equal(bestLast):
			best = append(best, candidate)
		}
	}
	return best[rand.IntN(len(best))]
}

// --- exchange ----------------------------------------------------------------

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	ctx, cancel := t.mergedContext(ctx)
	defer cancel()

	sel, err := t.selectTarget()
	if err != nil {
		return nil, err
	}

	if sel.fan != nil {
		return t.fan(ctx, message, sel.fan, sel.gen, sel.election)
	}
	if sel.survival {
		return t.exchangeSurvival(ctx, message, sel)
	}
	return t.exchangeSingle(ctx, message, sel)
}

func (t *Transport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}

// mergedContext derives a request context that is also cancelled when Close
// tears the transport down. Only the transport's own cancellation is added; the
// caller's deadline, values and cancellation pass through unchanged. A transport
// that used the scope context directly instead would make a single query
// uncancellable by its caller, and one that ignored the scope context could not
// be stopped at shutdown - so both are needed.
func (t *Transport) mergedContext(ctx context.Context) (context.Context, context.CancelFunc) {
	t.access.Lock()
	runCtx := t.runCtx
	t.access.Unlock()
	if runCtx == nil {
		return ctx, func() {}
	}
	merged, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(runCtx, cancel)
	return merged, func() {
		stop()
		cancel()
	}
}

// exchangeSingle is the normal path: one exchange with the sticky/best target
// under a sub-deadline of HALF the remaining budget.
//
// The half is the whole point of the split. A blackholed target otherwise eats
// the entire request budget, and the rescue fan is then started with a dead
// deadline, so the group reports failure without ever having asked the members
// that might still be alive.
func (t *Transport) exchangeSingle(ctx context.Context, message *mDNS.Msg, sel selection) (*mDNS.Msg, error) {
	// An election-window concurrent serves the query but must not trash the
	// sticky target: current changes only via a sticky pick or a fan winner.
	if !sel.provisional {
		if previous, changed := t.setCurrent(sel.target.tag, sel.gen); changed {
			t.logCurrentChange(ctx, previous, sel.target.tag)
		}
	}
	targetCtx, cancel := context.WithTimeout(ctx, t.targetBudget(ctx))
	response, err := sel.target.transport.Exchange(targetCtx, message)
	cancel()
	if !isFailure(response, err) {
		t.noteSuccess(sel.target.tag, sel.gen)
		return response, err
	}
	// The target's sub-deadline was honest, so its failure is always recorded.
	t.noteError(sel.target.tag, sel.gen)
	t.logProbeFailure(ctx, sel.target.tag, response, err)

	rescuers := t.cleanExcept(sel.target.tag)
	if len(rescuers) == 0 {
		// No clean member is left to rescue with. Returning the real error is
		// better than a second doomed attempt: the next query will see no clean
		// member and take the single attempt of the survival path.
		return response, err
	}
	return t.fan(ctx, message, rescuers, sel.gen, false)
}

// exchangeSurvival is the no-clean-member path: exactly one attempt against the
// least dirty member, never a fan, in every mode. It gets the FULL remaining
// budget because there is no fan to reserve a half for.
func (t *Transport) exchangeSurvival(ctx context.Context, message *mDNS.Msg, sel selection) (*mDNS.Msg, error) {
	target := sel.target
	t.logger.WarnContext(ctx, "group[", t.Tag(), "]: no clean servers, survival attempt via ", target.tag)
	response, err := target.transport.Exchange(ctx, message)
	if !isFailure(response, err) {
		// Erasing its errors returns it to the clean set and stickiness holds
		// it there, which is the intended reward for being the survivor.
		t.noteSuccess(target.tag, sel.gen)
		return response, err
	}
	t.noteError(target.tag, sel.gen)
	t.logProbeFailure(ctx, target.tag, response, err)
	return response, err
}

// targetBudget is half of the remaining request budget, with half of the client
// default as the fallback when the context carries no deadline.
func (t *Transport) targetBudget(ctx context.Context) time.Duration {
	if deadline, loaded := ctx.Deadline(); loaded {
		if remaining := time.Until(deadline); remaining > 0 {
			return remaining / 2
		}
	}
	return C.DNSTimeout / 2
}

// cleanExcept returns the clean members minus one tag, used to build the rescue
// fan after a target failure.
func (t *Transport) cleanExcept(exceptTag string) []*member {
	now := time.Now()
	t.access.Lock()
	defer t.access.Unlock()
	var clean []*member
	for _, current := range t.members {
		if current.tag == exceptTag {
			continue
		}
		if len(t.liveErrorsLocked(current.tag, now)) == 0 {
			clean = append(clean, current)
		}
	}
	return clean
}

// --- classification / log ----------------------------------------------------

// isFailure classifies a member result. A transport error, a timeout and
// SERVFAIL are failures; NXDOMAIN and an empty answer are VALID ANSWERS and are
// returned to the caller.
//
// The distinction is the difference between "this member is broken" and "this
// member gave the only correct answer there is". An empty NOERROR answer is a
// legitimate reply for a name with no records, and NXDOMAIN is a legitimate
// reply for a name that does not exist; treating either as a failure would
// record errors against a healthy member, fan to a second member, and let a
// different, equally empty answer win.
//
// Members surface rcodes in both representations - as a *mDNS.Msg and as
// dns.RcodeError, because the client converts SERVFAIL into the error form
// above the transport - so both are checked.
func isFailure(response *mDNS.Msg, err error) bool {
	if err != nil {
		var rcode dns.RcodeError
		if errors.As(err, &rcode) {
			return rcode == dns.RcodeServerFailure
		}
		return true
	}
	if response == nil {
		// No answer and no error is not an "empty answer": an empty answer is a
		// well-formed message carrying no records. A nil response is nothing the
		// caller can use - it dereferences the message when the error is nil -
		// so it can only be classified as a failure.
		return true
	}
	return response.Rcode == mDNS.RcodeServerFailure
}

func (t *Transport) logProbeFailure(ctx context.Context, tag string, response *mDNS.Msg, err error) {
	if err == nil {
		err = dns.RcodeError(response.Rcode)
	}
	t.logger.DebugContext(ctx, "group[", t.Tag(), "]: server ", tag, " error recorded (ttl ", t.errorTTL.String(), "): ", err)
}

func (t *Transport) logCurrentChange(ctx context.Context, previous string, next string) {
	if previous == "" {
		t.logger.InfoContext(ctx, "group[", t.Tag(), "]: current server: ", next)
		return
	}
	t.logger.InfoContext(ctx, "group[", t.Tag(), "]: current server changed ", previous, " -> ", next)
}
