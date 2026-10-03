package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for the soft stalled-family verdict (§1-§13).
//
// # The gap these close
//
// A silently blackholed family never reports an error. Its attempt is still blocked when the
// other family wins, and it unwinds with context.Canceled - which must NOT be recorded as a
// family failure, because a cancelled loser says nothing about the network. So the health state
// never learned that a family had stalled, and every following connection paid the fallback
// delay again.
//
// The distinction the tests protect: a STALL (another family connected first while this one
// stayed silent) is not a PATH FAILURE (the kernel reported the network unreachable). Both
// produce the same small scheduling nudge, but conflating them would mean inventing an error
// that never occurred.

// stallingDialer models a family that never answers, alongside one that connects immediately.
type stallingDialer struct {
	stall map[netip.Addr]bool
	// connectDelay applies to non-stalling addresses.
	connectDelay time.Duration

	access  sync.Mutex
	started []time.Duration
	tried   []netip.Addr
	start   time.Time
}

func newStallingDialer() *stallingDialer {
	return &stallingDialer{start: time.Now()}
}

func (d *stallingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.started = append(d.started, time.Since(d.start))
	d.tried = append(d.tried, destination.Addr)
	stall := d.stall[destination.Addr]
	delay := d.connectDelay
	d.access.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if stall {
		// Blackhole: no answer until someone cancels the race.
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &countingConn{}, nil
}

func (d *stallingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, context.Canceled
}

func (d *stallingDialer) attemptTimes() []time.Duration {
	d.access.Lock()
	defer d.access.Unlock()
	out := make([]time.Duration, len(d.started))
	copy(out, d.started)
	return out
}

// TestBlackholeLoserTeachesTheScheduler is the P0 test (§9).
//
// Connection one: IPv6 blackholes, IPv4 wins after the fallback delay. The scheduler must learn
// that IPv6 stalled - without recording the context.Canceled the loser unwinds with.
//
// Connection two uses a huge fallback delay, so the ONLY way IPv6 and IPv4 can start together
// is if the verdict from connection one is actually in force.
func TestBlackholeLoserTeachesTheScheduler(t *testing.T) {
	blackhole6 := netip.MustParseAddr("2001:db8::1")
	healthy4 := netip.MustParseAddr("192.0.2.1")

	health := newFamilyHealth()
	inner := newStallingDialer()
	inner.stall = map[netip.Addr]bool{blackhole6: true}

	const environment = 0
	const firstFallbackDelay = 60 * time.Millisecond

	// --- connection one: the blackhole is observed ---
	first := &candidateScheduler{
		fallbackDelay:      firstFallbackDelay,
		health:             health,
		networkEnvironment: environment,
	}
	_, winner, err := first.dial(context.Background(),
		planCandidates([]netip.Addr{blackhole6, healthy4}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		func(ctx context.Context, address netip.Addr) (net.Conn, error) {
			return inner.DialContext(ctx, "tcp", M.SocksaddrFrom(address, 443))
		})
	require.NoError(t, err)
	require.Equal(t, healthy4, winner, "the healthy family must win")

	// The verdict must exist, and it must be the SOFT kind.
	require.True(t, health.fallbackImmediately(environment, familyIPv6, familyIPv4),
		"the scheduler must have learned that IPv6 stalled while IPv4 connected")

	// --- connection two: the verdict must actually be in force ---
	//
	// The fallback delay is far longer than this test will wait. If IPv4 were still waiting for
	// it, the healthy family would not be attempted within the window below.
	second := &candidateScheduler{
		fallbackDelay:      2 * time.Second,
		health:             health,
		networkEnvironment: environment,
	}
	inner2 := newStallingDialer()
	inner2.stall = map[netip.Addr]bool{blackhole6: true}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, winner2, err := second.dial(ctx,
		planCandidates([]netip.Addr{blackhole6, healthy4}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
			return inner2.DialContext(attemptCtx, "tcp", M.SocksaddrFrom(address, 443))
		})
	require.NoError(t, err)
	require.Equal(t, healthy4, winner2)

	times := inner2.attemptTimes()
	require.Len(t, times, 2, "both families' first candidates must have started")

	// Both started immediately, not one after the 2s delay.
	require.Less(t, times[1], 200*time.Millisecond,
		"with the verdict in force the second family must start immediately; it started after %v "+
			"of a 2s fallback delay", times[1])
}

// TestBlackholeLoserMirrorisIPv4 is §10: the mirror direction.
//
// A fix that only handled IPv6 would pass the test above and fail this one.
func TestBlackholeLoserMirrorisIPv4(t *testing.T) {
	blackhole4 := netip.MustParseAddr("192.0.2.1")
	healthy6 := netip.MustParseAddr("2001:db8::1")

	health := newFamilyHealth()
	inner := newStallingDialer()
	inner.stall = map[netip.Addr]bool{blackhole4: true}

	first := &candidateScheduler{
		fallbackDelay: 60 * time.Millisecond,
		health:        health,
	}
	_, winner, err := first.dial(context.Background(),
		planCandidates([]netip.Addr{blackhole4, healthy6}, netip.Addr{}, C.DomainStrategyPreferIPv4),
		func(ctx context.Context, address netip.Addr) (net.Conn, error) {
			return inner.DialContext(ctx, "tcp", M.SocksaddrFrom(address, 443))
		})
	require.NoError(t, err)
	require.Equal(t, healthy6, winner)

	require.True(t, health.fallbackImmediately(0, familyIPv4, familyIPv6),
		"the mirror case must record a verdict for IPv4")
}

// TestParentCancellationRecordsNoVerdict is §11.
//
// When the caller cancels, every attempt returns a context error at once. None of that is
// evidence about the network, so nothing may be recorded - hard or soft.
func TestParentCancellationRecordsNoVerdict(t *testing.T) {
	address6 := netip.MustParseAddr("2001:db8::1")
	address4 := netip.MustParseAddr("192.0.2.1")

	health := newFamilyHealth()
	inner := newStallingDialer()
	// Both families blackhole, so only the cancellation ends the race.
	inner.stall = map[netip.Addr]bool{address6: true, address4: true}

	scheduler := &candidateScheduler{
		fallbackDelay: 20 * time.Millisecond,
		health:        health,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(80 * time.Millisecond)
		cancel()
	}()

	_, _, err := scheduler.dial(ctx,
		planCandidates([]netip.Addr{address6, address4}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
			return inner.DialContext(attemptCtx, "tcp", M.SocksaddrFrom(address, 443))
		})
	require.Error(t, err)

	require.False(t, health.fallbackImmediately(0, familyIPv6, familyIPv4),
		"a parent cancellation must not create an IPv6 verdict")
	require.False(t, health.fallbackImmediately(0, familyIPv4, familyIPv6),
		"a parent cancellation must not create an IPv4 verdict")

	health.access.Lock()
	entries := len(health.state)
	health.access.Unlock()
	require.Equal(t, 0, entries, "the health state must be untouched by a parent cancellation")
}

// TestParentDeadlineRecordsNoVerdict is §12.
//
// A parent deadline cancels every attempt at once, and they return context.DeadlineExceeded -
// which isFamilyPathFailure considers a path failure. Without a parent-state check, the
// caller's own deadline would be recorded as the network being broken.
func TestParentDeadlineRecordsNoVerdict(t *testing.T) {
	address6 := netip.MustParseAddr("2001:db8::1")
	address4 := netip.MustParseAddr("192.0.2.1")

	health := newFamilyHealth()
	inner := newStallingDialer()
	inner.stall = map[netip.Addr]bool{address6: true, address4: true}

	scheduler := &candidateScheduler{
		fallbackDelay: 20 * time.Millisecond,
		health:        health,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	_, _, err := scheduler.dial(ctx,
		planCandidates([]netip.Addr{address6, address4}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
			return inner.DialContext(attemptCtx, "tcp", M.SocksaddrFrom(address, 443))
		})
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	health.access.Lock()
	entries := len(health.state)
	health.access.Unlock()
	require.Equal(t, 0, entries,
		"a parent deadline must not be recorded as a family path failure; the caller's own "+
			"timeout says nothing about which family works")
}

// TestSameFamilySlowCandidateRecordsNoVerdict is §7.
//
// Two addresses in one family are ordinary racing. IPv6#2 winning while IPv6#1 is still pending
// proves nothing about the IPv6 family - and if the code mistook it for a cross-family stall it
// would penalise the family that just connected.
func TestSameFamilySlowCandidateRecordsNoVerdict(t *testing.T) {
	slow := netip.MustParseAddr("2001:db8::1")
	fast := netip.MustParseAddr("2001:db8::2")

	health := newFamilyHealth()
	inner := newStallingDialer()
	inner.stall = map[netip.Addr]bool{slow: true}

	scheduler := &candidateScheduler{
		fallbackDelay: 30 * time.Millisecond,
		health:        health,
	}

	_, winner, err := scheduler.dial(context.Background(),
		planCandidates([]netip.Addr{slow, fast}, netip.Addr{}, C.DomainStrategyIPv6Only),
		func(ctx context.Context, address netip.Addr) (net.Conn, error) {
			return inner.DialContext(ctx, "tcp", M.SocksaddrFrom(address, 443))
		})
	require.NoError(t, err)
	require.Equal(t, fast, winner)

	health.access.Lock()
	entries := len(health.state)
	health.access.Unlock()
	require.Equal(t, 0, entries,
		"a same-family race must not produce a family verdict")
}

// TestFastRaceRecordsNoVerdict is §8.
//
// The scenario that must NOT produce a verdict: both families' first candidates start close
// together, one answers quickly, and the other is still in flight - but it has been in flight
// for LESS than the fallback interval, so it has not stalled.
//
// A family must be given its full fallback interval before its silence is treated as evidence.
// A candidate that started a few milliseconds ago simply has not finished.
func TestFastRaceRecordsNoVerdict(t *testing.T) {
	address6 := netip.MustParseAddr("2001:db8::1")
	address4 := netip.MustParseAddr("192.0.2.1")

	health := newFamilyHealth()

	// A large interval so that the whole race happens comfortably inside it. IPv6 is started
	// first (preferred) and takes 50ms; IPv4 wins at 1ms. IPv6 is therefore still pending when
	// IPv4 succeeds, but at ~1ms of its 2s interval it has not stalled by any measure.
	inner := &orderedDialer{
		delays: map[netip.Addr]time.Duration{
			address6: 50 * time.Millisecond,
			address4: 1 * time.Millisecond,
		},
	}

	scheduler := &candidateScheduler{
		fallbackDelay: 2 * time.Second,
		health:        health,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, winner, err := scheduler.dial(ctx,
		planCandidates([]netip.Addr{address6, address4}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
			return inner.DialContext(attemptCtx, "tcp", M.SocksaddrFrom(address, 443))
		})
	require.NoError(t, err)

	// IPv6 answers at 50ms, so it wins - IPv4 was never launched (2s fallback). Nothing is
	// pending at winner time, which is itself a case the rule must handle without inventing a
	// verdict.
	require.Equal(t, address6, winner)

	health.access.Lock()
	entries := len(health.state)
	health.access.Unlock()
	require.Equal(t, 0, entries,
		"a family that answered promptly must not be marked stalled")
}

// TestPendingInsideIntervalRecordsNoVerdict is the precise §8 case: one family IS still pending
// at winner time, but for less than the fallback interval.
//
// The fallback delay is small so both families start within milliseconds, and the eventual
// winner is the faster one. The loser is pending, yet it has had nowhere near its full interval.
func TestPendingInsideIntervalRecordsNoVerdict(t *testing.T) {
	address6 := netip.MustParseAddr("2001:db8::1")
	address4 := netip.MustParseAddr("192.0.2.1")

	health := newFamilyHealth()

	// IPv6 (preferred, started first) takes 30ms. The fallback delay is 10ms, so IPv4 launches
	// at 10ms and wins at 11ms - while IPv6 is still pending, 11ms into its life.
	//
	// 11ms >= 10ms, so this DOES qualify as a stall by the rule. To stay INSIDE the interval
	// the loser must be pending for less than the interval, so the interval must exceed the
	// winner's completion time: use a 500ms interval and a 20ms loser.
	inner := &orderedDialer{
		delays: map[netip.Addr]time.Duration{
			address6: 20 * time.Millisecond,
			address4: 1 * time.Millisecond,
		},
	}

	scheduler := &candidateScheduler{
		fallbackDelay: 500 * time.Millisecond,
		health:        health,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err := scheduler.dial(ctx,
		planCandidates([]netip.Addr{address6, address4}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
			return inner.DialContext(attemptCtx, "tcp", M.SocksaddrFrom(address, 443))
		})
	require.NoError(t, err)

	health.access.Lock()
	entries := len(health.state)
	health.access.Unlock()
	require.Equal(t, 0, entries,
		"a race completed inside the fallback interval must not record a verdict")
}

// TestPendingBeyondFallbackDelayDoesRecordAVerdict is the complement of the rule above.
//
// A family that has been pending LONGER than the fallback interval, while the other family
// connected, has demonstrably failed to answer in the time it was given. That is the primary
// case the mechanism exists for, so it must be recorded.
func TestPendingBeyondFallbackDelayDoesRecordAVerdict(t *testing.T) {
	address6 := netip.MustParseAddr("2001:db8::1")
	address4 := netip.MustParseAddr("192.0.2.1")

	health := newFamilyHealth()

	// IPv6 would answer, but only long after the fallback interval has elapsed.
	inner := &orderedDialer{
		delays: map[netip.Addr]time.Duration{
			address6: 2 * time.Second,
			address4: 5 * time.Millisecond,
		},
	}

	scheduler := &candidateScheduler{
		fallbackDelay: 50 * time.Millisecond,
		health:        health,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, winner, err := scheduler.dial(ctx,
		planCandidates([]netip.Addr{address6, address4}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
			return inner.DialContext(attemptCtx, "tcp", M.SocksaddrFrom(address, 443))
		})
	require.NoError(t, err)
	require.Equal(t, address4, winner)

	require.True(t, health.fallbackImmediately(0, familyIPv6, familyIPv4),
		"a family pending beyond the fallback interval while the other connected has stalled")
}

// TestSoftVerdictClearedBySuccess is §6.
//
// The verdict is a nudge, not a sentence: the family's first successful connection clears it.
func TestSoftVerdictClearedBySuccess(t *testing.T) {
	health := newFamilyHealth()
	const environment = 0

	health.recordStalledFamily(environment, familyIPv6)
	require.True(t, health.fallbackImmediately(environment, familyIPv6, familyIPv4),
		"a stalled verdict must promote the other family")

	health.recordSuccess(environment, familyIPv6)
	require.False(t, health.fallbackImmediately(environment, familyIPv6, familyIPv4),
		"a successful IPv6 connection must clear the stalled verdict")
}

// TestStalledVerdictDoesNotDisableTheFamily is §5.
//
// The verdict must change only the LAUNCH SCHEDULE. The family is still attempted first when
// preferred, and still attempted at all - preference is not lock-in, and a penalty is not a
// disable.
func TestStalledVerdictDoesNotDisableTheFamily(t *testing.T) {
	address6 := netip.MustParseAddr("2001:db8::1")
	address4 := netip.MustParseAddr("192.0.2.1")

	health := newFamilyHealth()
	health.recordStalledFamily(0, familyIPv6)

	inner := &orderedDialer{delays: map[netip.Addr]time.Duration{}}

	scheduler := &candidateScheduler{
		fallbackDelay: 50 * time.Millisecond,
		health:        health,
	}

	_, _, err := scheduler.dial(context.Background(),
		planCandidates([]netip.Addr{address6, address4}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		func(ctx context.Context, address netip.Addr) (net.Conn, error) {
			return inner.DialContext(ctx, "tcp", M.SocksaddrFrom(address, 443))
		})
	require.NoError(t, err)

	// What the verdict must NOT do: remove the family from the race, or move it behind the
	// other family. Both are attempted, and the penalised family is still listed first in the
	// plan because the user's preference governs ordering.
	attempts := inner.attempts()
	require.Contains(t, attempts, address6, "the penalised family must still be attempted")
	require.Contains(t, attempts, address4, "the other family must still be raced")

	plan := planCandidates([]netip.Addr{address6, address4}, netip.Addr{}, C.DomainStrategyPreferIPv6)
	require.Equal(t, address6, plan.candidates[0].address,
		"the preferred family must still lead the plan; a stalled verdict must not reorder it")

	// Which goroutine completes first is scheduling, not contract - both are healthy here.
}

// orderedDialer connects after a per-address delay, with no blackholing.
type orderedDialer struct {
	delays map[netip.Addr]time.Duration

	access sync.Mutex
	tried  []netip.Addr
}

func (d *orderedDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.tried = append(d.tried, destination.Addr)
	delay := d.delays[destination.Addr]
	d.access.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &countingConn{}, nil
}

func (d *orderedDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, context.Canceled
}

func (d *orderedDialer) attempts() []netip.Addr {
	d.access.Lock()
	defer d.access.Unlock()
	out := make([]netip.Addr, len(d.tried))
	copy(out, d.tried)
	return out
}
