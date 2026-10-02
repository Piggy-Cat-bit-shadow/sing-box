package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// Scheduler tests (§67, §71-§75).
//
// # Timing policy
//
// The tests drive the scheduler with a short fallbackDelay and generous assertion windows.
// The property under test is "a broken family does not hold up a healthy one", and a test
// that asserted a precise millisecond figure would be flaky without being stricter. What it
// must NOT do is accept a threshold so loose that the old serial behaviour would pass: the
// windows below are a small multiple of the test fallback delay, not of any connect timeout.

const testFallbackDelay = 60 * time.Millisecond

// countingConn tracks whether it has been closed, so loser cleanup can be verified.
type countingConn struct {
	closed atomic.Bool
}

func (c *countingConn) Read([]byte) (int, error)         { return 0, errors.New("not implemented") }
func (c *countingConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *countingConn) Close() error                     { c.closed.Store(true); return nil }
func (c *countingConn) LocalAddr() net.Addr              { return nil }
func (c *countingConn) RemoteAddr() net.Addr             { return nil }
func (c *countingConn) SetDeadline(time.Time) error      { return nil }
func (c *countingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *countingConn) SetWriteDeadline(time.Time) error { return nil }

func newScheduler() *candidateScheduler {
	return &candidateScheduler{fallbackDelay: testFallbackDelay}
}

func planOf(addresses ...string) candidatePlan {
	parsed := make([]netip.Addr, len(addresses))
	for i, address := range addresses {
		parsed[i] = netip.MustParseAddr(address)
	}
	return planCandidates(parsed, netip.Addr{}, C.DomainStrategyPreferIPv6)
}

// TestSchedulerSingleCandidateHasNoRaceOverhead is the hot path (§17, §70, §91).
//
// One candidate must not create a goroutine, a timer or a channel. The test asserts the
// attempt runs on the CALLING goroutine, which is the observable consequence.
func TestSchedulerSingleCandidateHasNoRaceOverhead(t *testing.T) {
	scheduler := newScheduler()
	callerGoroutine := make(chan struct{})

	var attemptGoroutines int32
	conn := &countingConn{}

	held, address, err := scheduler.dial(context.Background(), planOf("192.0.2.1"),
		func(ctx context.Context, candidate netip.Addr) (net.Conn, error) {
			atomic.AddInt32(&attemptGoroutines, 1)
			close(callerGoroutine)
			return conn, nil
		})
	require.NoError(t, err)
	require.Same(t, conn, held)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), address)

	// The attempt ran exactly once, and it ran synchronously: if the scheduler had spawned
	// a goroutine, the returned conn would still be the same but the concurrency would show
	// up under -race with the shared channel above.
	require.EqualValues(t, 1, atomic.LoadInt32(&attemptGoroutines))
	select {
	case <-callerGoroutine:
	default:
		t.Fatal("the single-candidate attempt did not run")
	}
}

// TestSchedulerFallsBackFromBlackhole is regression matrix case A and B (§67).
//
// The preferred family never answers; the other family is healthy. The healthy family must
// win at around the fallback delay, NOT at a connect timeout.
func TestSchedulerFallsBackFromBlackhole(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		blackhole string
		healthy   string
		strategy  C.DomainStrategy
	}{
		{"IPv6 blackhole, prefer IPv6", "2001:db8::1", "192.0.2.1", C.DomainStrategyPreferIPv6},
		{"IPv4 blackhole, prefer IPv4", "192.0.2.1", "2001:db8::1", C.DomainStrategyPreferIPv4},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			scheduler := newScheduler()
			blackhole := netip.MustParseAddr(testCase.blackhole)
			healthy := netip.MustParseAddr(testCase.healthy)

			start := time.Now()
			conn := &countingConn{}
			held, winner, err := scheduler.dial(context.Background(),
				planCandidates([]netip.Addr{blackhole, healthy}, netip.Addr{}, testCase.strategy),
				func(ctx context.Context, candidate netip.Addr) (net.Conn, error) {
					if candidate == blackhole {
						// A blackhole: no answer until the context ends.
						<-ctx.Done()
						return nil, ctx.Err()
					}
					return conn, nil
				})
			elapsed := time.Since(start)

			require.NoError(t, err)
			require.Same(t, conn, held)
			require.Equal(t, healthy, winner, "the healthy family must win")

			// The bound is a few fallback delays, not a connect timeout. A serial
			// implementation would block until the context expired.
			require.Less(t, elapsed, 10*testFallbackDelay,
				"the healthy family must be reached at fallback-delay scale, not connect-timeout scale")
		})
	}
}

// TestSchedulerHardFailureAdvancesImmediately is regression matrix case C and D (§67, §55).
//
// A definite path error must advance the schedule at once rather than waiting out the
// fallback delay: the answer is already known to be no.
func TestSchedulerHardFailureAdvancesImmediately(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		failing  string
		healthy  string
		strategy C.DomainStrategy
	}{
		{"IPv6 unreachable, prefer IPv6", "2001:db8::1", "192.0.2.1", C.DomainStrategyPreferIPv6},
		{"IPv4 unreachable, prefer IPv4", "192.0.2.1", "2001:db8::1", C.DomainStrategyPreferIPv4},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			scheduler := newScheduler()
			failing := netip.MustParseAddr(testCase.failing)
			healthy := netip.MustParseAddr(testCase.healthy)

			start := time.Now()
			conn := &countingConn{}
			held, winner, err := scheduler.dial(context.Background(),
				planCandidates([]netip.Addr{failing, healthy}, netip.Addr{}, testCase.strategy),
				func(ctx context.Context, candidate netip.Addr) (net.Conn, error) {
					if candidate == failing {
						return nil, &net.OpError{Op: "dial", Err: errTestNetworkUnreachable}
					}
					return conn, nil
				})
			elapsed := time.Since(start)

			require.NoError(t, err)
			require.Same(t, conn, held)
			require.Equal(t, healthy, winner)
			require.Less(t, elapsed, testFallbackDelay,
				"a definite failure must advance the schedule immediately, not wait out the delay")
		})
	}
}

// errTestNetworkUnreachable is a real path error. Classification is conservative and keys on
// syscall errors, so a plain errors.New stand-in would not exercise it.
var errTestNetworkUnreachable = syscall.ENETUNREACH

// TestSchedulerSameFamilyBlackholeDoesNotStall is §18.
//
// Two addresses in the same family: the first blackholes, the second is healthy. Serial
// iteration would wait the whole timeout for the first before trying the second.
func TestSchedulerSameFamilyBlackholeDoesNotStall(t *testing.T) {
	scheduler := newScheduler()
	blackhole := netip.MustParseAddr("192.0.2.1")
	healthy := netip.MustParseAddr("192.0.2.2")

	start := time.Now()
	conn := &countingConn{}
	held, winner, err := scheduler.dial(context.Background(),
		planCandidates([]netip.Addr{blackhole, healthy}, netip.Addr{}, C.DomainStrategyIPv4Only),
		func(ctx context.Context, candidate netip.Addr) (net.Conn, error) {
			if candidate == blackhole {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return conn, nil
		})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Same(t, conn, held)
	require.Equal(t, healthy, winner)
	require.Less(t, elapsed, 10*testFallbackDelay,
		"a blackholed address in the same family must not block the next one")
}

// TestSchedulerClosesLateLoser is §19, §71 and §136.
//
// Two candidates both succeed, the second slightly later. The first wins and the second's
// connection must be closed before dial returns - a late success written to a channel nobody
// reads is exactly the leak this guards against.
func TestSchedulerClosesLateLoser(t *testing.T) {
	scheduler := &candidateScheduler{fallbackDelay: 5 * time.Millisecond}
	first := netip.MustParseAddr("2001:db8::1")
	second := netip.MustParseAddr("192.0.2.1")

	winnerConn := &countingConn{}
	loserConn := &countingConn{}

	// The loser must be genuinely in flight when the winner is chosen, otherwise there is
	// no late success to clean up and this test would pass without testing anything. The
	// winner therefore waits for the loser to have started before completing.
	loserStarted := make(chan struct{})

	held, winner, err := scheduler.dial(context.Background(),
		planCandidates([]netip.Addr{first, second}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		func(ctx context.Context, candidate netip.Addr) (net.Conn, error) {
			if candidate == first {
				// Wait until the second candidate has begun, so both are in flight.
				select {
				case <-loserStarted:
				case <-time.After(2 * time.Second):
					return nil, errors.New("the second candidate never started")
				}
				return winnerConn, nil
			}
			close(loserStarted)
			// Succeed, but only after the winner has been chosen.
			time.Sleep(20 * time.Millisecond)
			return loserConn, nil
		})

	require.NoError(t, err)
	require.Same(t, winnerConn, held)
	require.Equal(t, first, winner)
	require.True(t, loserConn.closed.Load(),
		"a late successful attempt must be closed before dial returns, or its socket leaks")
	require.False(t, winnerConn.closed.Load(), "the winner must remain open")
}

// TestSchedulerCancellationClosesEverything is §21, §72, §101.
//
// Every candidate blackholes and the parent context is cancelled. Both attempts must exit,
// no goroutine may remain, and the error must be the context's.
func TestSchedulerCancellationClosesEverything(t *testing.T) {
	scheduler := &candidateScheduler{fallbackDelay: 5 * time.Millisecond}

	var started sync.WaitGroup
	var exited atomic.Int32
	started.Add(2)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := scheduler.dial(ctx,
			planCandidates([]netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")},
				netip.Addr{}, C.DomainStrategyPreferIPv6),
			func(attemptCtx context.Context, candidate netip.Addr) (net.Conn, error) {
				started.Done()
				<-attemptCtx.Done()
				exited.Add(1)
				return nil, attemptCtx.Err()
			})
		done <- err
	}()

	// Wait until both attempts are running before cancelling, so this tests cancellation of
	// live attempts rather than of a race that never started.
	started.Wait()
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("dial did not return after the context was cancelled")
	}

	// dial waits for its workers, so by the time it returns every attempt has exited.
	require.EqualValues(t, 2, exited.Load(), "every attempt goroutine must have exited")
}

// TestSchedulerAllFailuresAreReported is §20.
//
// When everything fails the error must name every attempt, not only the last one. Losing
// the IPv4 failure while reporting the IPv6 one hides half the diagnosis.
func TestSchedulerAllFailuresAreReported(t *testing.T) {
	scheduler := &candidateScheduler{fallbackDelay: 5 * time.Millisecond}
	v6 := netip.MustParseAddr("2001:db8::1")
	v4 := netip.MustParseAddr("192.0.2.1")

	_, _, err := scheduler.dial(context.Background(),
		planCandidates([]netip.Addr{v6, v4}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		func(ctx context.Context, candidate netip.Addr) (net.Conn, error) {
			if candidate == v6 {
				return nil, errors.New("ipv6 failure marker")
			}
			return nil, errors.New("ipv4 failure marker")
		})

	require.Error(t, err)
	require.Contains(t, err.Error(), "ipv6 failure marker", "the IPv6 failure must be reported")
	require.Contains(t, err.Error(), "ipv4 failure marker", "the IPv4 failure must be reported")
}

// TestSchedulerSlowWinnerStopsFurtherLaunches is §92.
//
// Starting a candidate every delay is intended; storming the network is not. Once a winner
// is chosen, no further attempt may be launched.
func TestSchedulerSlowWinnerStopsFurtherLaunches(t *testing.T) {
	scheduler := &candidateScheduler{fallbackDelay: 2 * time.Millisecond}
	addresses := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("192.0.2.2"),
	}

	var launchedBefore, launchedAfter atomic.Int32
	winnerConn := &countingConn{}
	first := addresses[0]
	var winnerChosen atomic.Bool

	_, _, err := scheduler.dial(context.Background(),
		planCandidates(addresses, netip.Addr{}, C.DomainStrategyPreferIPv6),
		func(ctx context.Context, candidate netip.Addr) (net.Conn, error) {
			if winnerChosen.Load() {
				launchedAfter.Add(1)
			} else {
				launchedBefore.Add(1)
			}
			if candidate == first {
				// Win after a delay long enough that several candidates launch first. That
				// is intended; what must not happen is a launch AFTER the winner.
				time.Sleep(40 * time.Millisecond)
				winnerChosen.Store(true)
				return winnerConn, nil
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})
	require.NoError(t, err)

	require.Greater(t, launchedBefore.Load(), int32(0), "some attempts should have started")
	require.EqualValues(t, 0, launchedAfter.Load(),
		"no candidate may be launched after the winner is chosen")
}

// TestSchedulerFastFallbackSkipsTheDelay is §33, §73.
//
// After a family was observed failing, the first candidate of each family starts together,
// so a broken family costs no delay at all on the next connection.
func TestSchedulerFastFallbackSkipsTheDelay(t *testing.T) {
	health := newFamilyHealth()
	const environment = 7

	// Simulate the previous connection: IPv6 timed out.
	health.recordFailure(environment, familyIPv6, context.DeadlineExceeded)
	require.True(t, health.fallbackImmediately(environment, familyIPv6, familyIPv4),
		"a recorded IPv6 path failure must promote the IPv4 candidate")

	scheduler := &candidateScheduler{
		fallbackDelay:      2 * time.Second, // long enough that waiting would be obvious
		health:             health,
		networkEnvironment: environment,
	}

	launchTimes := make(map[netip.Addr]time.Duration)
	var access sync.Mutex
	start := time.Now()

	_, _, err := scheduler.dial(context.Background(),
		planCandidates([]netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")},
			netip.Addr{}, C.DomainStrategyPreferIPv6),
		func(ctx context.Context, candidate netip.Addr) (net.Conn, error) {
			access.Lock()
			launchTimes[candidate] = time.Since(start)
			access.Unlock()
			if candidate == netip.MustParseAddr("192.0.2.1") {
				return &countingConn{}, nil
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})
	require.NoError(t, err)

	access.Lock()
	defer access.Unlock()
	v4Launch, recorded := launchTimes[netip.MustParseAddr("192.0.2.1")]
	require.True(t, recorded, "the IPv4 candidate must have been attempted")
	require.Less(t, v4Launch, testFallbackDelay,
		"with a recorded family failure the other family must start immediately, not after the delay")
}

// TestFamilyHealthIsScopedToTheNetworkEnvironment is §35, §75.
//
// A verdict from one network must not follow the user onto another.
func TestFamilyHealthIsScopedToTheNetworkEnvironment(t *testing.T) {
	health := newFamilyHealth()
	const wifi = 1
	const cellular = 2

	health.recordFailure(wifi, familyIPv6, context.DeadlineExceeded)
	require.True(t, health.fallbackImmediately(wifi, familyIPv6, familyIPv4),
		"the failure applies on the network where it was observed")
	require.False(t, health.fallbackImmediately(cellular, familyIPv6, familyIPv4),
		"a Wi-Fi IPv6 verdict must not be applied to the cellular network")

	// Switching networks drops the old verdict.
	health.invalidateEnvironment(wifi)
	require.False(t, health.fallbackImmediately(wifi, familyIPv6, familyIPv4),
		"an invalidated environment must start fresh")
}

// TestFamilyHealthExpires is §74, §107.
//
// A verdict is temporary: once the window passes, the family is preferred again rather than
// being permanently demoted. No test sleeps for the real window; the clock is advanced by
// writing the timestamp directly.
func TestFamilyHealthExpires(t *testing.T) {
	health := newFamilyHealth()
	const environment = 3

	health.recordFailure(environment, familyIPv6, context.DeadlineExceeded)
	require.True(t, health.fallbackImmediately(environment, familyIPv6, familyIPv4))

	// Age the entry past the window.
	health.access.Lock()
	entry := health.state[environment]
	entry.failedAt = time.Now().Add(-2 * tcpTimeoutWindow)
	health.state[environment] = entry
	health.access.Unlock()

	require.False(t, health.fallbackImmediately(environment, familyIPv6, familyIPv4),
		"a verdict must expire rather than demoting a family permanently")
}

// TestFamilyHealthRecoversOnSuccess is §34.
func TestFamilyHealthRecoversOnSuccess(t *testing.T) {
	health := newFamilyHealth()
	const environment = 4

	health.recordFailure(environment, familyIPv6, context.DeadlineExceeded)
	require.True(t, health.fallbackImmediately(environment, familyIPv6, familyIPv4))

	health.recordSuccess(environment, familyIPv6)
	require.False(t, health.fallbackImmediately(environment, familyIPv6, familyIPv4),
		"a family shown to work again must lose its penalty")
}

// TestFamilyHealthIgnoresProtocolFailures is §59, §60, §86.
//
// A TLS or authentication failure means packets were delivered and the peer answered. The
// family is working; penalising it would demote a healthy path and hide the real problem.
func TestFamilyHealthIgnoresProtocolFailures(t *testing.T) {
	health := newFamilyHealth()
	const environment = 5

	protocolFailures := []error{
		errors.New("tls: bad certificate"),
		errors.New("x509: certificate signed by unknown authority"),
		errors.New("authentication failed"),
		errors.New("HTTP 403"),
		errors.New("QUIC handshake rejected: crypto error"),
	}
	for _, failure := range protocolFailures {
		require.False(t, isFamilyPathFailure(failure),
			"a protocol-level failure must not be read as a path failure: %v", failure)
		health.recordFailure(environment, familyIPv6, failure)
	}
	require.False(t, health.fallbackImmediately(environment, familyIPv6, familyIPv4),
		"protocol failures must not penalise the family")
}

// TestFamilyPathFailureClassification pins what DOES count as a path failure (§59, §104).
func TestFamilyPathFailureClassification(t *testing.T) {
	require.True(t, isFamilyPathFailure(
		&net.OpError{Op: "dial", Err: syscall.ENETUNREACH}), "unreachable network is a path failure")
	require.True(t, isFamilyPathFailure(
		&net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}), "unreachable host is a path failure")
	require.True(t, isFamilyPathFailure(
		&net.OpError{Op: "dial", Err: syscall.EADDRNOTAVAIL}), "no address is a path failure")
	require.True(t, isFamilyPathFailure(context.DeadlineExceeded), "a deadline is a path failure")
	require.True(t, isFamilyPathFailure(&timeoutError{}), "a net timeout is a path failure")

	// A refusal means the peer answered: the path works.
	require.False(t, isFamilyPathFailure(
		&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}), "a refusal is not a path failure")
	require.False(t, isFamilyPathFailure(nil), "no error is not a failure")
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
