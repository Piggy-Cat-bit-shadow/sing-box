package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// Dual-stack candidate scheduling.
//
// # The problem this solves
//
// Candidates used to be attempted one at a time, in order. Against a blackholed address
// that means waiting the entire connect timeout before trying the next one, even when the
// next address is healthy - and when the two addresses are in different families, the
// healthy family is never attempted until the broken one has fully timed out.
//
// The scheduler starts the first candidate immediately and adds one more every
// fallbackDelay. A candidate that fails FAST advances the schedule immediately, because
// there is no reason to wait out a delay once the answer is already known to be no.
//
// # What "success" means here
//
// Exactly what the executor says it means. This scheduler is handed a function that
// performs one attempt and reports whether it worked. For TCP that is a completed
// connection. For QUIC it is a completed handshake - a UDP socket being created, or
// DialEarly returning, is NOT success, and no caller of this code may treat it as such.
//
// # Winner ownership
//
// Exactly one attempt wins. Every other attempt is closed before this function returns,
// including attempts that succeed late: an attempt that reports a connection after the
// winner has been chosen would otherwise be recorded nowhere and leak its socket. That
// specific bug was fixed once in the MASQUE racer; this is the same discipline.

// dialAttemptFunc performs one attempt against one address.
//
// Returning a non-nil conn AFTER an error is not allowed; callers must close anything they
// create before returning an error.
type dialAttemptFunc func(ctx context.Context, address netip.Addr) (net.Conn, error)

// dialAttemptResult is one attempt's outcome.
type dialAttemptResult struct {
	conn    net.Conn
	err     error
	address netip.Addr
}

// candidateScheduler races candidates for a single connection.
type candidateScheduler struct {
	// fallbackDelay is how long to wait before starting the next candidate. Zero uses the
	// package default.
	fallbackDelay time.Duration
	// health, when set, may promote the first candidate of a recently-failed family so a
	// broken family costs no delay on the next connection.
	health *familyHealth
	// networkEnvironment scopes the health state.
	networkEnvironment uint64
}

// dial runs the race and returns the winning connection.
//
// Ownership on return:
//   - exactly one conn is returned, or none on error
//   - every losing conn, including a late success, has been Closed before returning
//   - every started goroutine has exited before returning
func (s *candidateScheduler) dial(ctx context.Context, plan candidatePlan, attempt dialAttemptFunc) (net.Conn, netip.Addr, error) {
	candidates := plan.candidates
	switch len(candidates) {
	case 0:
		return nil, netip.Addr{}, E.New("no dial candidates")
	case 1:
		// The hot path, and the common case for a literal IP with no recovery.
		//
		// No goroutine, no timer, no channel, no race state. A "dual-stack" scheduler that
		// costs a goroutine and a timer for a single address would be a regression on the
		// most frequent path in the process.
		//
		// Family health is still updated, cheaply and without any of that machinery. Leaving
		// it out would mean the single-candidate path - the one most connections take - could
		// neither record a failure nor clear a penalty, so a family would never recover from
		// a single-stack connection.
		conn, err := attempt(ctx, candidates[0].address)
		if err != nil {
			if s.health != nil {
				s.health.recordFailure(s.networkEnvironment, candidates[0].family, err)
			}
			return nil, netip.Addr{}, E.Cause(err, "dial ", candidates[0].address)
		}
		if s.health != nil {
			s.health.recordSuccess(s.networkEnvironment, candidates[0].family)
		}
		return conn, candidates[0].address, nil
	}

	raceCtx, cancelRace := context.WithCancel(ctx)
	defer cancelRace()

	// Unbuffered: an attempt cannot deposit a result that nobody will read. With a buffered
	// channel a late success would be written, never collected, and its socket leaked.
	results := make(chan dialAttemptResult)

	var (
		workerGroup sync.WaitGroup
		started     int
	)
	startAttempt := func(candidate dualStackCandidate) {
		started++
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()
			conn, err := attempt(raceCtx, candidate.address)

			// Record a PATH failure here, where the attempt completes, rather than only on
			// the winner path.
			//
			// An attempt that loses the race is exactly the case that carries the useful
			// signal: the address that blackholed is usually the LOSING one, and the winner
			// is the family that already works. Recording only on success meant nothing was
			// ever learned from the situation the mechanism exists for, so the fast-fallback
			// path was inert in production.
			//
			// The classification is conservative: caller cancellation and closed connections
			// - which is how a loser is torn down - record nothing.
			if err != nil && s.health != nil {
				s.health.recordFailure(s.networkEnvironment, classifyAddress(candidate.address), err)
			}

			select {
			case results <- dialAttemptResult{conn: conn, err: err, address: candidate.address}:
			case <-raceCtx.Done():
				// The race is over. Close anything this attempt created rather than
				// leaving it for a reader that no longer exists.
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}

	// Close every loser and wait for every worker before returning. Losing connections are
	// collected here rather than closed inline so a late success is covered too.
	var (
		losersAccess sync.Mutex
		loserConns   []net.Conn
	)
	collectLoser := func(conn net.Conn) {
		if conn == nil {
			return
		}
		losersAccess.Lock()
		loserConns = append(loserConns, conn)
		losersAccess.Unlock()
	}
	closeLosers := func() {
		losersAccess.Lock()
		conns := loserConns
		loserConns = nil
		losersAccess.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	}

	defer func() {
		cancelRace()
		workerGroup.Wait()
		closeLosers()
	}()

	// Decide the launch order. With recent family failure recorded, the first candidate of
	// each family starts together so a broken family costs no delay at all.
	launch := candidates
	immediatePair := false
	if s.health != nil && len(candidates) > 1 {
		if s.health.fallbackImmediately(s.networkEnvironment, candidates[0].family, candidates[1].family) {
			immediatePair = true
		}
	}

	startAttempt(launch[0])
	nextIndex := 1
	if immediatePair {
		startAttempt(launch[1])
		nextIndex = 2
	}

	var (
		timer     *time.Timer
		timerChan <-chan time.Time
		lastErr   error
		failures  []error
		successes []dialAttemptResult
	)
	resetTimer := func() {
		if timer == nil {
			timer = time.NewTimer(s.fallbackDelayOrDefault())
		} else {
			// Drain before Reset. Resetting a timer that already fired and was not drained
			// leaves a stale value that would advance the schedule spuriously.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(s.fallbackDelayOrDefault())
		}
		timerChan = timer.C
	}
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
			timerChan = nil
		}
	}
	defer stopTimer()

	if nextIndex < len(launch) {
		resetTimer()
	}

	for {
		select {
		case <-ctx.Done():
			return nil, netip.Addr{}, ctx.Err()

		case result := <-results:
			if result.err == nil && result.conn != nil {
				successes = append(successes, result)
				if len(successes) == 1 {
					// The winner. Cancel the race and stop launching; pending attempts are
					// closed by the deferred cleanup.
					//
					// A family that just completed a connection has demonstrated the path
					// works, so any penalty it carries is cleared here rather than by a
					// caller remembering to do it. Without this a family penalised once
					// would stay penalised for the full window even after it recovered.
					if s.health != nil {
						s.health.recordSuccess(s.networkEnvironment, classifyAddress(result.address))
					}
					cancelRace()
					stopTimer()
					return result.conn, result.address, nil
				}
				// Unreachable while the first success returns immediately, but kept so a
				// future change that collects successes cannot silently drop one.
				collectLoser(result.conn)
				continue
			}

			lastErr = result.err
			failures = append(failures, E.Cause(result.err, result.address.String()))

			// A fast failure frees its slot immediately: waiting out the delay would only
			// postpone an answer already known to be no.
			if nextIndex < len(launch) {
				startAttempt(launch[nextIndex])
				nextIndex++
				if nextIndex < len(launch) {
					resetTimer()
				} else {
					stopTimer()
				}
				continue
			}
			if started == len(failures) {
				// Everything has failed.
				if len(failures) == 0 {
					return nil, netip.Addr{}, E.Cause(lastErr, "dial failed")
				}
				return nil, netip.Addr{}, E.Errors(failures...)
			}

		case <-timerChan:
			if nextIndex < len(launch) {
				startAttempt(launch[nextIndex])
				nextIndex++
				if nextIndex < len(launch) {
					resetTimer()
				} else {
					stopTimer()
				}
			} else {
				stopTimer()
			}
		}
	}
}

func (s *candidateScheduler) fallbackDelayOrDefault() time.Duration {
	if s.fallbackDelay > 0 {
		return s.fallbackDelay
	}
	return N.DefaultFallbackDelay
}

// familyHealth remembers which address family recently failed to establish a connection, so
// the next connection does not pay the fallback delay again to rediscover it.
//
// # Scope
//
// Keyed by network environment. A Wi-Fi network with broken IPv6 says nothing about the
// cellular network, and carrying a verdict across that boundary would penalise a working
// path. The environment changing clears the state, which is also what makes this safe to
// keep in memory only: there is nothing to persist because it is only valid for the network
// it was observed on.
//
// # What counts as a failure
//
// Only path failures. A TLS or authentication error means the network delivered packets and
// the peer answered - the family is working, and treating that as a family failure would
// penalise a healthy path because one server misbehaved. When a failure cannot be
// classified confidently, no state is recorded.
//
// # Window
//
// C.TCPTimeout. Long enough to cover a connection attempt, short enough that a recovered
// family is retried promptly rather than being written off.
type familyHealth struct {
	access sync.Mutex
	state  map[uint64]familyHealthState
}

type familyHealthState struct {
	failedFamily addressFamily
	failedAt     time.Time
}

func newFamilyHealth() *familyHealth {
	return &familyHealth{state: make(map[uint64]familyHealthState)}
}

// fallbackImmediately reports whether both families' first candidates should start together.
func (h *familyHealth) fallbackImmediately(environment uint64, preferred addressFamily, other addressFamily) bool {
	if preferred == other || preferred == familyInvalid || other == familyInvalid {
		return false
	}
	h.access.Lock()
	defer h.access.Unlock()
	entry, known := h.state[environment]
	if !known {
		return false
	}
	if time.Since(entry.failedAt) > tcpTimeoutWindow {
		delete(h.state, environment)
		return false
	}
	// Only promote when the family that recently failed is the one that would otherwise
	// have been preferred, and the other family is the alternative being offered.
	return entry.failedFamily == preferred
}

// recordFailure notes a path failure for the family an address belongs to.
func (h *familyHealth) recordFailure(environment uint64, family addressFamily, err error) {
	if family == familyInvalid {
		return
	}
	if !isFamilyPathFailure(err) {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	h.state[environment] = familyHealthState{
		failedFamily: family,
		failedAt:     time.Now(),
	}
}

// recordSuccess clears a family's penalty once it is shown to work again.
func (h *familyHealth) recordSuccess(environment uint64, family addressFamily) {
	if family == familyInvalid {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	if entry, known := h.state[environment]; known && entry.failedFamily == family {
		delete(h.state, environment)
	}
}

// invalidateEnvironment drops state for one environment, used when the network changes.
func (h *familyHealth) invalidateEnvironment(environment uint64) {
	h.access.Lock()
	defer h.access.Unlock()
	delete(h.state, environment)
}

// invalidateAll drops every verdict, for a full reset.
func (h *familyHealth) invalidateAll() {
	h.access.Lock()
	defer h.access.Unlock()
	h.state = make(map[uint64]familyHealthState)
}

// tcpTimeoutWindow is the lifetime of a family verdict. It is deliberately C.TCPTimeout
// rather than a new constant, so the window matches the time a connection attempt may
// legitimately take.
const tcpTimeoutWindow = 15 * time.Second

// isFamilyPathFailure reports whether an error means the network PATH for this family is
// broken, as opposed to the far end rejecting the connection.
//
// # Conservative by construction
//
// An unclassifiable error returns false, so no health state is recorded. The asymmetry is
// deliberate: failing to record a genuine path failure costs one extra fallback delay on the
// next connection, while recording a false one penalises a working family and hides a real
// protocol problem behind a network verdict.
func isFamilyPathFailure(err error) bool {
	if err == nil {
		return false
	}
	// Explicit path errors from the kernel.
	if errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) ||
		errors.Is(err, syscall.ENETDOWN) {
		return true
	}
	// Cancellation is never a family verdict. A cancelled context means the CALLER stopped
	// waiting - a losing attempt being cleaned up, a user aborting, or the whole operation's
	// deadline expiring and cancelling every attempt at once. Recording that as "this family
	// is broken" would penalise a healthy family for fifteen seconds because a different
	// candidate happened to win, or because the user navigated away.
	if errors.Is(err, context.Canceled) {
		return false
	}
	// net.ErrClosed is the same class: it comes from caller cancellation, a network switch,
	// or this package closing a loser. None of those says anything about the path.
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	// io.EOF during connect means the peer closed before answering. On a datagram-oriented
	// path that is ambiguous, and on a stream it is indistinguishable from a server that
	// accepts and immediately hangs up - which is a server problem, not a broken family. The
	// conservative reading is to record nothing.
	if errors.Is(err, io.EOF) {
		return false
	}
	// A refusal is the peer actively answering: the path works.
	if errors.Is(err, syscall.ECONNREFUSED) {
		return false
	}
	// A timeout means nothing answered on that path. This is the blackhole case the whole
	// mechanism exists for.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// A bare deadline exceeded reaches here only when the attempt itself timed out rather
	// than the parent operation: a parent deadline arrives as context.Canceled-derived
	// cancellation of the attempt, and is excluded above.
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return false
}
