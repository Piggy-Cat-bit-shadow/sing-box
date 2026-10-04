package trafficsched

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/trafficclass"
)

// lane is one of the two service classes the scheduler arbitrates between.
type lane uint8

const (
	laneHigh lane = iota
	laneNormal
	laneCount
)

// Mode selects what the scheduler controls.
//
// The first two modes are the ones the contention experiment measured and rejected: they change
// WHEN a write starts without changing how much is already queued ahead of it. They are kept
// because they are the control group, and because a design decision without a runnable
// counterexample is an opinion.
type Mode uint8

const (
	// ModeAdmission lets a NORMAL write start only while no high-priority write is in flight. It is
	// nearly free and it measured as no improvement at all.
	ModeAdmission Mode = iota

	// ModeService owns a single service slot for the whole scheduler: exactly one managed write is
	// in flight at any instant, granted by lane. It also measured as no improvement, at the cost of
	// serialising every managed write.
	ModeService

	// ModePacedNormalOnly shapes the NORMAL lane to the configured rate and leaves high-priority
	// traffic entirely unshaped.
	//
	// It is the mode that first showed the mechanism working, and it has a hole the
	// HIGH-versus-HIGH experiment was written to find: a high-priority flow doing bulk work is not
	// shaped, so it can create the same queue the NORMAL lane was just prevented from creating, and
	// a small high-priority write then waits behind it.
	ModePacedNormalOnly

	// ModePaced shapes the whole managed upload set to one aggregate rate, and arbitrates WITHIN
	// that budget: high priority first, with a guaranteed NORMAL floor.
	ModePaced
)

// paced reports whether the mode shapes rather than only orders.
func (m Mode) paced() bool { return m == ModePaced || m == ModePacedNormalOnly }

// aggregate reports whether the shaper covers every managed flow rather than only the NORMAL lane.
func (m Mode) aggregate() bool { return m == ModePaced }

// Defaults.
const (
	// DefaultHighIdleWindow is how long the ordering modes stay armed after the last
	// high-priority write. The paced modes do not use it; see Scheduler.
	DefaultHighIdleWindow = 2 * time.Second

	// DefaultHighPerNormal is how many consecutive high-priority grants are served before one
	// NORMAL grant is forced, so a saturated high-priority lane cannot starve NORMAL.
	DefaultHighPerNormal = 4

	// DefaultBurst is the shaping bucket's capacity in bytes.
	//
	// It is the largest amount of data a fully credited bucket can hand over at once, so it is also
	// the largest queue a burst can inject - a direct latency/overhead trade-off rather than a
	// safety margin. It is measured, not guessed; see the package benchmark.
	DefaultBurst = 64 * 1024

	// paceTick is how often a parked waiter is re-examined. The loop only runs while something is
	// parked, so an idle scheduler holds no timer at all.
	paceTick = time.Millisecond
)

// RateSource is the shaping input.
//
// It is deliberately one method. The scheduler asks for a rate and never asks how it was arrived
// at, which is what lets a learned rate replace a configured one without the gate, the lane policy
// or the buffer accounting changing. FixedRate is the only implementation that ships; the adaptive
// prototype in the benchmark implements the same interface.
type RateSource interface {
	// Rate reports the managed upload rate in bytes per second. A non-positive value disables
	// shaping entirely, which is the default.
	Rate() int64
}

// WriteObserver is implemented by a rate source that learns from the writes it shaped.
//
// It is a separate interface on purpose: a configured rate has nothing to learn from and pays
// nothing. The scheduler resolves it once, and the gate only reads the clock when one is installed.
type WriteObserver interface {
	// ObserveWrite is called once per shaped write, with the bytes the write carried, how long it
	// took, and which lane it was in.
	ObserveWrite(size int, elapsed time.Duration, high bool)
}

// FixedRate is a configured rate. It is safe for concurrent use so a controller can drive it
// without the scheduler changing.
type FixedRate struct {
	rate atomic.Int64
}

// NewFixedRate returns a rate source reporting bytesPerSecond. A non-positive value is inert.
func NewFixedRate(bytesPerSecond int64) *FixedRate {
	fixed := &FixedRate{}
	fixed.rate.Store(bytesPerSecond)
	return fixed
}

func (f *FixedRate) Rate() int64 { return f.rate.Load() }

// Set replaces the configured rate. A non-positive value turns shaping off.
func (f *FixedRate) Set(bytesPerSecond int64) { f.rate.Store(bytesPerSecond) }

// Options configures a Scheduler. The zero value is usable and selects the defaults.
type Options struct {
	Mode Mode
	// RateSource is the shaping input. A nil source, or a non-positive rate, means no shaping: the
	// gate observes every byte and admits all of them immediately.
	RateSource RateSource
	// Burst is the shaping bucket's capacity in bytes.
	Burst int
	// HighPerNormal is the NORMAL floor, in high-priority grants per NORMAL grant.
	HighPerNormal int
	// HighIdleWindow is how long the ordering modes stay armed after the last high-priority write.
	HighIdleWindow time.Duration
}

func (o Options) withDefaults() Options {
	if o.Burst <= 0 {
		o.Burst = DefaultBurst
	}
	if o.HighPerNormal <= 0 {
		o.HighPerNormal = DefaultHighPerNormal
	}
	if o.HighIdleWindow <= 0 {
		o.HighIdleWindow = DefaultHighIdleWindow
	}
	return o
}

// Scheduler arbitrates the upload write path of every managed flow.
//
// # Lifetime
//
// One scheduler is shared by every flow of one box, because contention is a property of the shared
// uplink and never of one connection. It is owned by the connection manager, which creates and
// finalises flows.
//
// # Why the paced modes do not arm
//
// The ordering modes are armed by high-priority activity, because their whole policy is "yield to
// interactive traffic while it is happening". The paced modes deliberately are NOT. Their job is to
// stop the managed queue from filling in the first place, and a queue that filled during five
// seconds of bulk work does not empty itself because an interactive request has now arrived: a
// pacer that starts pacing on the first interactive write is a pacer that protects the SECOND one.
//
// So when a rate is configured, shaping runs continuously for as long as the scheduler exists. That
// is also why the configured number has to be a rate the path actually sustains: it is not a
// ceiling that only applies under contention, it is the rate.
// rateSourceHolder bundles the shaping input with its optional learning half, so replacing the
// source is one atomic store rather than two fields that could be seen half-updated.
type rateSourceHolder struct {
	source   RateSource
	observer WriteObserver
}

type Scheduler struct {
	options Options
	// source is the shaping input. It is read on every refill and on the fast path rather than
	// captured, so a controller can be installed or replaced while flows are running, without the
	// gate, the lane policy or the flow holding a copy of it.
	//
	// It is an atomic pointer rather than a field under the mutex because Flow.wait reads it with
	// no lock held: an uncontended NORMAL write must not have to take one.
	source atomic.Pointer[rateSourceHolder]
	// observing is the cheap half of "is anything learning": the gate reads it once per write to
	// decide whether to read the clock at all.
	observing atomic.Bool

	// armed is the ordering modes' predicate.
	armed          atomic.Bool
	highLastActive atomic.Int64

	closeOnce sync.Once
	closeCh   chan struct{}

	mu         sync.Mutex
	cond       *sync.Cond
	closed     bool
	lanes      [laneCount]laneState
	highStreak int
	// highInflight counts high-priority writes in progress in ModeAdmission.
	highInflight int
	// inflightService counts the single service slot in ModeService.
	inflightService int

	// tokens is the shaping credit in bytes. It may go negative: an oversized write is admitted
	// once the bucket is full and carries the remainder as debt, which is what keeps it inside the
	// budget instead of exempting it from the budget.
	tokens     float64
	lastRefill time.Time

	// paceRunning records whether a wake loop exists, so an idle scheduler has no timer.
	paceRunning bool
}

type laneState struct {
	queue []*Flow
	head  int
}

func (l *laneState) empty() bool { return l.head >= len(l.queue) }

func (l *laneState) push(f *Flow) { l.queue = append(l.queue, f) }

func (l *laneState) pop() *Flow {
	if l.empty() {
		return nil
	}
	f := l.queue[l.head]
	l.queue[l.head] = nil
	l.head++
	if l.empty() {
		l.queue = l.queue[:0]
		l.head = 0
	}
	return f
}

func (l *laneState) remove(f *Flow) bool {
	for index := l.head; index < len(l.queue); index++ {
		if l.queue[index] == f {
			copy(l.queue[index:], l.queue[index+1:])
			l.queue = l.queue[:len(l.queue)-1]
			if l.empty() {
				l.queue = l.queue[:0]
				l.head = 0
			}
			return true
		}
	}
	return false
}

// NewScheduler creates a scheduler. It allocates nothing per flow and starts no goroutine or timer
// until something actually has to wait.
func NewScheduler(options Options) *Scheduler {
	options = options.withDefaults()
	scheduler := &Scheduler{
		options: options,
		closeCh: make(chan struct{}),
	}
	scheduler.installRateSourceLocked(options.RateSource)
	scheduler.cond = sync.NewCond(&scheduler.mu)
	scheduler.tokens = float64(options.Burst)
	scheduler.lastRefill = time.Now()
	return scheduler
}

// SetRateSource replaces the shaping input.
//
// A learned controller can be installed at any time, including after flows exist, because the rate
// is read on every refill rather than captured: nothing in the gate, the lane policy or the flow
// holds a copy of it.
func (s *Scheduler) SetRateSource(source RateSource) {
	s.mu.Lock()
	s.installRateSourceLocked(source)
	// A rate change can make a parked waiter admissible immediately - most obviously by turning
	// shaping off altogether, which removes the credit rule entirely - and there is no guarantee a
	// wake loop is running to notice. Running one grant pass here closes that window rather than
	// leaving it to the next tick.
	s.grantLocked()
	s.cond.Broadcast()
	s.mu.Unlock()
}

// installRateSourceLocked publishes a rate source. The callers hold s.mu, but the store is atomic
// because the readers do not.
func (s *Scheduler) installRateSourceLocked(source RateSource) {
	holder := &rateSourceHolder{source: source}
	if observer, isObserver := source.(WriteObserver); isObserver {
		holder.observer = observer
	}
	s.source.Store(holder)
	s.observing.Store(holder.observer != nil)
}

// NewFlow returns a scheduler handle for one logical flow.
//
// This takes no lock and touches no shared state: a connection being established on one goroutine
// must never contend with flows already writing on another.
func (s *Scheduler) NewFlow(class trafficclass.Class) *Flow {
	flow := &Flow{sched: s, high: class.IsHighPriority(), lane: laneNormal}
	if flow.high {
		flow.lane = laneHigh
	}
	return flow
}

// Armed reports whether the ordering modes consider high-priority activity recent. Exported for
// tests and diagnostics; the paced modes do not use it.
func (s *Scheduler) Armed() bool { return s.armed.Load() }

// Rate reports the shaping rate currently in effect, in bytes per second. Zero means no shaping.
func (s *Scheduler) Rate() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rateLocked()
}

func (s *Scheduler) rateLocked() int64 {
	if !s.options.Mode.paced() {
		return 0
	}
	holder := s.source.Load()
	if holder == nil || holder.source == nil {
		return 0
	}
	rate := holder.source.Rate()
	if rate <= 0 {
		return 0
	}
	return rate
}

// Flow is one managed flow's handle on the scheduler.
//
// wait and done are confined to the flow's copy goroutine: only one write per flow can be in
// flight, because the copy loop that owns it is sequential. Close is the exception and is safe from
// any goroutine, which is what lets a shutdown release a flow parked in the scheduler.
type Flow struct {
	sched *Scheduler
	lane  lane
	high  bool
	// closeOnce makes Close idempotent without a registry, so creating a flow never takes the
	// scheduler lock and a connection can be established without contending with flows that are
	// already writing.
	closeOnce atomic.Bool

	// admitted counts the bytes this flow has handed to the outbound through the gate. It is
	// per-flow, so the atomic is uncontended; it exists because "did the bytes really pass through
	// the scheduler" is otherwise unobservable, and a scheduler that silently stopped being in the
	// path would look exactly like a working one.
	admitted atomic.Int64
	// grants counts the writes the scheduler actually arbitrated.
	grants atomic.Int64

	// pending and gated belong to the owning copy goroutine. pending is additionally read under
	// s.mu by the grant loop.
	pending int
	gated   bool

	// owedUntil is when this flow has finished paying for the part of an oversized write that the
	// shared bucket could not carry. See chargeOversizedLocked. Written under s.mu.
	owedUntil time.Time
	// holdsSlot is true between a grant and its release. It is NOT the same as gated: gated records
	// that this wait took the scheduled path, while holdsSlot records that the flow currently
	// requires a release - which Close has to be able to do from another goroutine after wait has
	// already returned. Written under s.mu.
	holdsSlot bool
	// closed is written under s.mu.
	closed bool
}

// wait blocks until the flow may hand n bytes to the outbound.
func (f *Flow) wait(n int) error {
	if f == nil {
		return nil
	}
	s := f.sched
	f.admitted.Add(int64(n))
	if s.inert() {
		return nil
	}
	if !s.options.Mode.paced() && !f.high && !s.armed.Load() {
		return nil
	}
	return s.waitSlow(f, n)
}

// inert reports whether the scheduler is installed but deliberately not scheduling.
//
// This is the production default. A paced mode with no rate has nothing to shape with, and the
// ordering modes measured as no improvement, so the honest configuration is one that provably does
// nothing: no queue, no lock and no timer, while the gate still observes every byte.
func (s *Scheduler) inert() bool {
	if !s.options.Mode.paced() {
		return false
	}
	holder := s.source.Load()
	if holder == nil || holder.source == nil {
		return true
	}
	return holder.source.Rate() <= 0
}

// done releases the credit or slot the flow holds, if any.
//
// It must run exactly once per successful wait, whatever the write returned: an upstream error does
// not free a slot by itself, and leaking one would stall the lane for every other flow.
func (f *Flow) done() {
	if f == nil || !f.gated {
		return
	}
	f.gated = false
	s := f.sched
	s.mu.Lock()
	if f.holdsSlot {
		s.releaseGrantLocked(f)
		// The grant pass is skipped when nothing is waiting, which is the common case: it would
		// otherwise re-walk both lanes and read the clock again for every single write, and it can
		// only ever produce a permit for a waiter that does not exist.
		if s.hasWaitersLocked() {
			s.grantLocked()
		}
	}
	s.mu.Unlock()
}

// hasWaitersLocked reports whether either lane has a parked flow.
func (s *Scheduler) hasWaitersLocked() bool {
	return !s.lanes[laneHigh].empty() || !s.lanes[laneNormal].empty()
}

// observeWriteStart reports whether the flow's writes are being timed, so the gate can skip reading
// the clock entirely when no rate source is learning.
func (f *Flow) observeWriteStart() time.Time {
	if f == nil || !f.sched.observing.Load() {
		return time.Time{}
	}
	return time.Now()
}

// observeWrite feeds one completed write to the rate source, if it is learning.
func (f *Flow) observeWrite(start time.Time, n int) {
	if f == nil || start.IsZero() {
		return
	}
	holder := f.sched.source.Load()
	if holder == nil || holder.observer == nil {
		return
	}
	// The observer is read from the same holder the rate came from, so a controller that is being
	// replaced cannot be observed and consulted as two different objects.
	holder.observer.ObserveWrite(n, time.Since(start), f.high)
}

// AdmittedBytes reports how many bytes have passed through the gate for this flow.
func (f *Flow) AdmittedBytes() int64 {
	if f == nil {
		return 0
	}
	return f.admitted.Load()
}

// HighPriority reports which lane this flow was placed in.
//
// The lane is decided once, from the resolved traffic class, and it is the only thing about a flow
// that its class changes. Exposed so that "the class reached the scheduler" can be asserted rather
// than inferred from timing, which is the difference between a test that pins the mapping and one
// that pins whatever the host happened to do.
func (f *Flow) HighPriority() bool {
	if f == nil {
		return false
	}
	return f.high
}

// Grants reports how many writes the scheduler arbitrated for this flow.
func (f *Flow) Grants() int64 {
	if f == nil {
		return 0
	}
	return f.grants.Load()
}

// Close unregisters the flow and releases anything parked on it. It is idempotent and safe to call
// from any goroutine.
func (f *Flow) Close() error {
	if f == nil {
		return nil
	}
	if !f.closeOnce.CompareAndSwap(false, true) {
		return nil
	}
	s := f.sched
	s.mu.Lock()
	f.closed = true
	for laneIndex := range s.lanes {
		s.lanes[laneIndex].remove(f)
	}
	if f.holdsSlot {
		s.releaseGrantLocked(f)
	}
	s.grantLocked()
	s.cond.Broadcast()
	s.mu.Unlock()
	return nil
}

// Close shuts the scheduler down and releases every parked flow with ErrClosed.
func (s *Scheduler) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeCh)
		s.mu.Lock()
		s.closed = true
		for laneIndex := range s.lanes {
			s.lanes[laneIndex].queue = nil
			s.lanes[laneIndex].head = 0
		}
		s.inflightService = 0
		s.highInflight = 0
		s.cond.Broadcast()
		s.mu.Unlock()
	})
	return nil
}

func (s *Scheduler) waitSlow(f *Flow, n int) error {
	s.mu.Lock()
	if s.closed || f.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	f.pending = n
	f.gated = true
	f.grants.Add(1)
	s.refillLocked()
	s.lanes[f.lane].push(f)
	s.grantLocked()
	for !f.holdsSlot && !s.closed && !f.closed {
		s.cond.Wait()
	}
	if s.closed || f.closed {
		// The flow is being torn down. If it was granted in the same instant, the grant has to be
		// handed back here or the lane would stall on a slot nobody owns.
		if f.holdsSlot {
			s.releaseGrantLocked(f)
			s.grantLocked()
		}
		f.gated = false
		s.mu.Unlock()
		return ErrClosed
	}
	s.mu.Unlock()
	return nil
}

// releaseGrantLocked undoes the bookkeeping a grant performed. It must be called exactly once per
// grant, from done() on the normal path and from waitSlow/Close when a grant is abandoned.
func (s *Scheduler) releaseGrantLocked(f *Flow) {
	f.holdsSlot = false
	if s.closed {
		// Shutdown already zeroed the counters and dropped every queue. Decrementing them again
		// would drive them negative, and a negative count is the kind of state that reads as a
		// leak the next time someone inspects it.
		return
	}
	switch s.options.Mode {
	case ModeAdmission:
		if f.high {
			s.highInflight--
		}
	case ModeService:
		s.inflightService--
	default:
		// The paced modes charge credit at admission. The debt an oversized write incurred is
		// deliberately NOT refunded here: those bytes were handed over, and the bucket repays them
		// at the configured rate. Refunding would turn the debt mechanism into exactly the free
		// exemption it replaced.
	}
}

// refillLocked advances the shaping bucket to the current time.
func (s *Scheduler) refillLocked() {
	rate := s.rateLocked()
	if rate <= 0 {
		return
	}
	now := time.Now()
	elapsed := now.Sub(s.lastRefill)
	if elapsed <= 0 {
		return
	}
	s.lastRefill = now
	s.tokens += float64(rate) * elapsed.Seconds()
	if capacity := float64(s.options.Burst); s.tokens > capacity {
		s.tokens = capacity
	}
}

// creditNeededLocked is how much credit a write of n bytes must SEE before it may start.
//
// A write no larger than the bucket must be fully covered, which is what makes the admitted rate
// equal the configured rate rather than merely approach it. A write larger than the bucket can
// never be covered, so it is admitted once the bucket is full - and then charged in full, which is
// the part that keeps it inside the budget instead of exempting it. See chargeLocked.
func (s *Scheduler) creditNeededLocked(n int) float64 {
	if n > s.options.Burst {
		return float64(s.options.Burst)
	}
	return float64(n)
}

// chargeLocked records what a granted write consumed.
//
// # Two charges, for two different jobs
//
// The SHARED bucket is charged what the write had to see to start - min(size, burst) - and is
// never allowed to go negative. That is the aggregate limit: it is what makes the sum over all
// managed flows equal the configured rate, and it is why no flow can hold another flow hostage,
// because the most any single write can take from the shared bucket is one burst.
//
// The FLOW is charged the whole write's worth of time, size/rate. That is the per-flow limit, and
// it is what stops an oversized write from escaping: a write larger than the burst takes one burst
// from the shared bucket and pays for the rest itself, in its own future.
//
// Charging only the first way would make a 1 MiB write cost the same as a 64 KiB one, which is the
// free escape this replaced. Charging only the second would let one huge write stop every other
// flow for as long as it would have taken at the configured rate.
//
// The result is exact: a flow that writes nothing but n-byte writes is admitted at n / (n/rate) =
// rate, and a flow that writes an oversized one is admitted at size / (size/rate) = rate. The wait
// an oversized write puts on the flow that sent it is unbounded in time - which is the correct
// place for it - while the wait it puts on everyone else is capped at one burst.
func (s *Scheduler) chargeLocked(f *Flow) {
	s.tokens -= s.creditNeededLocked(f.pending)
	if s.tokens < 0 {
		s.tokens = 0
	}
	rate := s.rateLocked()
	if rate <= 0 {
		return
	}
	now := time.Now()
	base := f.owedUntil
	if base.Before(now) {
		base = now
	}
	f.owedUntil = base.Add(writePeriod(f.pending, rate))
}

// writePeriod is how long one write of size bytes is worth at rate bytes per second.
//
// The arithmetic is done in float64 seconds and then saturated, because the alternative is a
// conversion the language does not define: a write whose period exceeds what a time.Duration can
// represent would become an arbitrary value, and an arbitrary value in the past is an over-admitted
// rate while one in the far future is a stalled connection. Neither is reachable from a copy loop
// whose buffers are bounded, and a helper that cannot produce either is worth the three lines.
func writePeriod(size int, rate int64) time.Duration {
	if size <= 0 {
		return 0
	}
	if rate <= 0 {
		return 0
	}
	nanoseconds := float64(size) / float64(rate) * float64(time.Second)
	if nanoseconds >= float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(nanoseconds)
}

// flowTimeReadyLocked reports whether a flow has finished paying for its last write.
func (s *Scheduler) flowTimeReadyLocked(f *Flow) bool {
	if f.owedUntil.IsZero() {
		return true
	}
	if time.Now().Before(f.owedUntil) {
		return false
	}
	f.owedUntil = time.Time{}
	return true
}

// creditAppliesLocked reports whether the shaper covers this lane.
func (s *Scheduler) creditAppliesLocked(index lane) bool {
	if !s.options.Mode.paced() || s.rateLocked() <= 0 {
		return false
	}
	if s.options.Mode.aggregate() {
		return true
	}
	return index == laneNormal
}

// maxLaneScan bounds how far into a lane the grant loop looks for a waiter that can start.
//
// The scan is what stops a lane's head from blocking the whole lane: a 64 KiB head waiting for
// 64 KiB of credit must not make a 256-byte interactive write behind it wait for the same credit.
// The bound keeps the loop O(1) in the pathological case, and it is generous relative to the number
// of managed flows that are ever parked at once on a client.
const maxLaneScan = 64

// pickReadyLocked returns the first waiter in a lane that may start, or nil.
//
// It scans rather than only inspecting the head, so a flow waiting for a large credit requirement
// does not hold up smaller writes behind it. Order is preserved among waiters that are ready, so a
// large write is served ahead of anything that arrived after it as soon as its own credit exists.
func (s *Scheduler) pickReadyLocked(index lane) *Flow {
	l := &s.lanes[index]
	if l.empty() {
		return nil
	}
	if !s.creditAppliesLocked(index) {
		return l.queue[l.head]
	}
	limit := len(l.queue)
	if limit > l.head+maxLaneScan {
		limit = l.head + maxLaneScan
	}
	for scan := l.head; scan < limit; scan++ {
		flow := l.queue[scan]
		if !s.flowTimeReadyLocked(flow) {
			continue
		}
		if s.tokens >= s.creditNeededLocked(flow.pending) {
			if scan != l.head {
				// Keep the queue ordered by arrival once the scan serves out of order.
				copy(l.queue[l.head+1:scan+1], l.queue[l.head:scan])
				l.queue[l.head] = flow
			}
			return flow
		}
	}
	return nil
}

// grantLocked hands out as many permits as the current mode allows.
//
// It runs with s.mu held, from every point that can create capacity: a new waiter, a completed
// write, a closed flow, a refill tick.
func (s *Scheduler) grantLocked() {
	for !s.closed {
		laneIndex, flow := s.pickLocked()
		if flow == nil {
			break
		}
		l := &s.lanes[laneIndex]
		l.pop()
		if laneIndex == laneHigh && l.empty() {
			s.highStreak = 0
		}
		flow.holdsSlot = true
		if flow.high {
			s.arm()
		}
		switch s.options.Mode {
		case ModeAdmission:
			if flow.high {
				s.highInflight++
			}
		case ModeService:
			s.inflightService++
		default:
			if s.creditAppliesLocked(flow.lane) {
				s.chargeLocked(flow)
			}
		}
		s.cond.Broadcast()
	}
	s.startPaceWakeLocked()
}

// pickLocked chooses the next lane to serve, or -1 when nothing can be served right now.
//
// Within a lane the queue is FIFO, so a granted flow that wants to write again goes to the back and
// one large flow cannot starve a small one. Across lanes the policy is high priority first with a
// guaranteed NORMAL floor: at most HighPerNormal consecutive high-priority grants before one NORMAL
// grant is forced.
//
// Credit readiness is part of readiness rather than a second pass: a lane whose head cannot afford
// its write is not a candidate, and the other lane may proceed. That keeps capacity from idling
// while one lane waits for credit, without a reservation scheme that could itself starve a lane.
func (s *Scheduler) pickLocked() (lane, *Flow) {
	highFlow := s.laneFlowLocked(laneHigh)
	normalFlow := s.laneFlowLocked(laneNormal)
	switch {
	case highFlow != nil && (normalFlow == nil || s.highStreak < s.options.HighPerNormal):
		if normalFlow != nil {
			s.highStreak++
		}
		return laneHigh, highFlow
	case normalFlow != nil:
		s.highStreak = 0
		return laneNormal, normalFlow
	case highFlow != nil:
		return laneHigh, highFlow
	default:
		return laneNormal, nil
	}
}

// laneFlowLocked returns a waiter this lane may start under both the mode's capacity rule and the
// shaper's credit rule, or nil.
func (s *Scheduler) laneFlowLocked(index lane) *Flow {
	switch s.options.Mode {
	case ModeService:
		if s.inflightService > 0 {
			return nil
		}
	case ModeAdmission:
		// High-priority writes are never delayed; a NORMAL write waits only while a high-priority
		// write is actually in flight.
		if index == laneNormal && s.highInflight > 0 {
			return nil
		}
	}
	return s.pickReadyLocked(index)
}

// startPaceWakeLocked ensures a wake loop exists while a parked waiter is waiting for credit.
func (s *Scheduler) startPaceWakeLocked() {
	if s.paceRunning || s.closed {
		return
	}
	if s.rateLocked() <= 0 {
		return
	}
	if s.lanes[laneHigh].empty() && s.lanes[laneNormal].empty() {
		return
	}
	s.paceRunning = true
	go s.paceWakeLoop()
}

// paceWakeLoop re-runs the refill and the grant loop until nothing is waiting for credit.
//
// It exists instead of a per-deadline timer because the granularity that matters is the smallest
// write anyone issues, and one tick that serves every waiter is simpler than a timer that has to be
// re-armed for the new head after every grant. It runs only while something is parked, so an idle
// scheduler holds no timer at all.
func (s *Scheduler) paceWakeLoop() {
	timer := time.NewTimer(paceTick)
	defer timer.Stop()
	for {
		select {
		case <-s.closeCh:
			s.mu.Lock()
			s.paceRunning = false
			s.mu.Unlock()
			return
		case <-timer.C:
		}
		s.mu.Lock()
		s.refillLocked()
		s.grantLocked()
		idle := s.lanes[laneHigh].empty() && s.lanes[laneNormal].empty()
		if idle || s.closed {
			s.paceRunning = false
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		timer.Reset(paceTick)
	}
}

// arm records high-priority activity and starts the disarm timer if it is not already running.
//
// Only the ordering modes use it. The paced modes shape continuously on purpose; see Scheduler.
func (s *Scheduler) arm() {
	if s.options.Mode.paced() {
		return
	}
	s.highLastActive.Store(time.Now().UnixNano())
	if s.armed.CompareAndSwap(false, true) {
		go s.disarmLoop()
	}
}

// disarmLoop clears the armed flag once high-priority activity has been idle for the window.
func (s *Scheduler) disarmLoop() {
	interval := s.options.HighIdleWindow / 8
	if interval < 5*time.Millisecond {
		interval = 5 * time.Millisecond
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-s.closeCh:
			return
		case <-timer.C:
		}
		if s.idleFor() < s.options.HighIdleWindow {
			timer.Reset(interval)
			continue
		}
		s.armed.Store(false)
		// Disarming releases anything waiting on the ordering policy, which is a slot or a yield
		// rather than credit, so the wake has to come from here.
		s.mu.Lock()
		s.grantLocked()
		s.mu.Unlock()
		if s.idleFor() < s.options.HighIdleWindow {
			if s.armed.CompareAndSwap(false, true) {
				timer.Reset(interval)
				continue
			}
			return
		}
		return
	}
}

func (s *Scheduler) idleFor() time.Duration {
	last := s.highLastActive.Load()
	if last == 0 {
		return time.Duration(1<<62 - 1)
	}
	return time.Since(time.Unix(0, last))
}
