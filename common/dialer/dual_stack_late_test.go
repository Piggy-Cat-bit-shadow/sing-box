package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Late-family join tests (§10, §11, §12, §20, §21, §26).
//
// # The failure being fixed
//
// A and AAAA resolve independently and one can answer far later than the other. Previously the
// connection path resolved completely and then raced a STATIC list, so a family answering at
// 200ms either delayed the connection until it arrived or was ignored once the race started.
// Either way the address that would have won could not participate.
//
// These tests assert the late family JOINS a race already in progress, and wins it.

// blackholeAddress models a path that accepts packets and never answers, reporting its own
// timeout. The timeout is short so a test does not wait for a real connect timeout, and it
// must stay below the fallback delay used by the tests for the failing attempt to report
// before the race ends.
func blackholeAttempt(ctx context.Context, address netip.Addr) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(blackholeTimeout):
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: timeoutBlackhole{}}
	}
}

// TestLatePreferredFamilyJoinsTheRace is §11 and §26, the most important case of this round.
//
//	IPv4 returns at 5ms and blackholes; IPv6 returns at 200ms and is healthy; prefer IPv6.
//
// The IPv4 attempt starts as soon as it is known - the connection is not held back waiting for
// AAAA. When the IPv6 candidate arrives it must join the SAME race and win, well before the
// IPv4 connect timeout would have expired.
func TestLatePreferredFamilyJoinsTheRace(t *testing.T) {
	const fallbackDelay = 300 * time.Millisecond

	blackhole4 := netip.MustParseAddr("192.0.2.1")
	late6 := netip.MustParseAddr("2001:db8::1")

	v4 := &countingConn{}
	lateCandidates := make(chan dualStackCandidate, 1)

	start := time.Now()
	var late6StartedAt time.Duration

	scheduler := &candidateScheduler{fallbackDelay: fallbackDelay}

	// Deliver the IPv6 candidate while the race is in progress.
	go func() {
		time.Sleep(200 * time.Millisecond)
		lateCandidates <- dualStackCandidate{address: late6, family: familyIPv6}
		close(lateCandidates)
	}()

	_, winner, err := scheduler.dialWithLateCandidates(context.Background(),
		planCandidates([]netip.Addr{blackhole4}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		lateCandidates,
		func(ctx context.Context, address netip.Addr) (net.Conn, error) {
			if address == late6 {
				late6StartedAt = time.Since(start)
				return &countingConn{}, nil
			}
			return blackholeAttempt(ctx, address)
		})

	require.NoError(t, err)
	require.Equal(t, late6, winner,
		"the late healthy preferred family must win the race it joined")
	require.NotZero(t, late6StartedAt, "the late candidate must have been attempted")

	// The decisive property: the late family did not have to wait for a full connect timeout,
	// and it was attempted after it arrived rather than being discarded.
	require.Less(t, late6StartedAt, fallbackDelay,
		"a late candidate with nothing pending ahead of it must start immediately")
	_ = v4
}

// TestLateMirrorFamilyJoinsTheRace is §12.
//
// The mirror: IPv6 returns first and blackholes, IPv4 returns late and is healthy. A fix that
// only handled the IPv6 direction would pass the previous test and fail this one.
func TestLateMirrorFamilyJoinsTheRace(t *testing.T) {
	const fallbackDelay = 300 * time.Millisecond

	blackhole6 := netip.MustParseAddr("2001:db8::1")
	late4 := netip.MustParseAddr("192.0.2.1")

	lateCandidates := make(chan dualStackCandidate, 1)
	var late4StartedAt time.Duration
	start := time.Now()

	scheduler := &candidateScheduler{fallbackDelay: fallbackDelay}

	go func() {
		time.Sleep(200 * time.Millisecond)
		lateCandidates <- dualStackCandidate{address: late4, family: familyIPv4}
		close(lateCandidates)
	}()

	_, winner, err := scheduler.dialWithLateCandidates(context.Background(),
		planCandidates([]netip.Addr{blackhole6}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		lateCandidates,
		func(ctx context.Context, address netip.Addr) (net.Conn, error) {
			if address == late4 {
				late4StartedAt = time.Since(start)
				return &countingConn{}, nil
			}
			return blackholeAttempt(ctx, address)
		})

	require.NoError(t, err)
	require.Equal(t, late4, winner, "the late healthy IPv4 family must win")
	require.NotZero(t, late4StartedAt)
	require.Less(t, late4StartedAt, fallbackDelay,
		"the late candidate must start immediately, not wait for a fallback interval")
}

// TestLateCandidateStartsImmediatelyWhenNothingPending is §21.
//
// A late arrival must not wait for a fallback interval that was scheduled before it existed.
// That interval's purpose is to stagger candidates that were all known at the start; a
// candidate appearing later has nothing to be staggered against.
func TestLateCandidateStartsImmediatelyWhenNothingPending(t *testing.T) {
	started := make(chan netip.Addr, 4)

	scheduler := &candidateScheduler{fallbackDelay: 5 * time.Second} // long: waiting would be obvious
	lateCandidates := make(chan dualStackCandidate, 2)

	first := netip.MustParseAddr("2001:db8::1")
	late := netip.MustParseAddr("192.0.2.1")

	go func() {
		time.Sleep(20 * time.Millisecond)
		lateCandidates <- dualStackCandidate{address: late, family: familyIPv4}
		close(lateCandidates)
	}()

	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		_, _, _ = scheduler.dialWithLateCandidates(context.Background(),
			planCandidates([]netip.Addr{first}, netip.Addr{}, C.DomainStrategyPreferIPv6),
			lateCandidates,
			func(ctx context.Context, address netip.Addr) (net.Conn, error) {
				started <- address
				if address == late {
					return &countingConn{}, nil
				}
				<-ctx.Done()
				return nil, ctx.Err()
			})
	}()

	select {
	case <-dialDone:
	case <-time.After(2 * time.Second):
		t.Fatal("a late candidate did not start despite a 5s fallback delay: it waited for an interval scheduled before it existed")
	}
}

// TestLateCandidatesDeduplicate is §20.
//
// A late candidate that is already known - including one that duplicates the original literal
// destination - must not be attempted twice. Duplicating an attempt means a duplicate
// connection to the same address and a wasted socket.
func TestLateCandidatesDeduplicate(t *testing.T) {
	address := netip.MustParseAddr("2001:db8::1")
	other := netip.MustParseAddr("2001:db8::2")

	var attempts atomic.Int32
	lateCandidates := make(chan dualStackCandidate, 3)

	scheduler := &candidateScheduler{fallbackDelay: 20 * time.Millisecond}

	go func() {
		// Already in the initial plan: must be ignored.
		lateCandidates <- dualStackCandidate{address: address, family: familyIPv6}
		// A genuinely new address.
		lateCandidates <- dualStackCandidate{address: other, family: familyIPv6}
		// A repeat of the first late arrival: must also be ignored.
		lateCandidates <- dualStackCandidate{address: other, family: familyIPv6}
		close(lateCandidates)
	}()

	_, _, err := scheduler.dialWithLateCandidates(context.Background(),
		planCandidates([]netip.Addr{address}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		lateCandidates,
		func(ctx context.Context, candidate netip.Addr) (net.Conn, error) {
			attempts.Add(1)
			if candidate == other {
				return &countingConn{}, nil
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})
	require.NoError(t, err)

	// Two distinct addresses means at most two attempts, never three.
	require.LessOrEqual(t, attempts.Load(), int32(2),
		"a duplicate late candidate must not produce a second attempt")
}

// TestLateCandidatesDeduplicateCanonicalForm is §20's IPv4-mapped rule.
//
// 192.0.2.1 and ::ffff:192.0.2.1 are the same destination. Attempting both would be a
// duplicate connection, so deduplication has to work on the canonical form.
func TestLateCandidatesDeduplicateCanonicalForm(t *testing.T) {
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	plain := netip.MustParseAddr("192.0.2.1")

	var attempts atomic.Int32
	lateCandidates := make(chan dualStackCandidate, 1)
	scheduler := &candidateScheduler{fallbackDelay: 20 * time.Millisecond}

	go func() {
		lateCandidates <- dualStackCandidate{address: plain, family: familyIPv4}
		close(lateCandidates)
	}()

	_, _, err := scheduler.dialWithLateCandidates(context.Background(),
		planCandidates([]netip.Addr{mapped}, netip.Addr{}, C.DomainStrategyIPv4Only),
		lateCandidates,
		func(ctx context.Context, candidate netip.Addr) (net.Conn, error) {
			attempts.Add(1)
			return &countingConn{}, nil
		})
	require.NoError(t, err)
	require.EqualValues(t, 1, attempts.Load(),
		"an IPv4-mapped form and its IPv4 form are the same destination")
}

// TestLateStreamCloseDoesNotStrandTheRace is §18's termination rule.
//
// Once resolution finishes and every attempt has failed, the race must conclude rather than
// waiting for candidates that can never arrive.
func TestLateStreamCloseDoesNotStrandTheRace(t *testing.T) {
	lateCandidates := make(chan dualStackCandidate)
	scheduler := &candidateScheduler{fallbackDelay: 10 * time.Millisecond}

	done := make(chan error, 1)
	go func() {
		_, _, err := scheduler.dialWithLateCandidates(context.Background(),
			planCandidates([]netip.Addr{netip.MustParseAddr("2001:db8::1")}, netip.Addr{}, C.DomainStrategyPreferIPv6),
			lateCandidates,
			func(ctx context.Context, candidate netip.Addr) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Err: timeoutBlackhole{}}
			})
		done <- err
	}()

	// Resolution finishes with nothing more to offer.
	time.Sleep(50 * time.Millisecond)
	close(lateCandidates)

	select {
	case err := <-done:
		require.Error(t, err, "every attempt failed, so the race must report an error")
	case <-time.After(2 * time.Second):
		t.Fatal("the race did not conclude after resolution finished and all attempts failed")
	}
}

var _ = M.Socksaddr{}

// --- end-to-end through resolveDialer (§43, §44, §45) ------------------------------

// TestEndToEndLateFamilyWins is this round's final gate (§43).
//
// It drives the whole production path:
//
//	resolveDialer -> DNS router family stream -> candidate scheduler -> fake TCP dialer
//
// with the failure model that matters:
//
//	IPv4 resolves at 5ms and BLACKHOLES
//	IPv6 resolves at 200ms and is HEALTHY
//	prefer IPv6
//
// The IPv4 attempt must start as soon as it is known - the connection is not held back waiting
// for AAAA. When IPv6 arrives it must join the SAME race and win, well before the IPv4 connect
// timeout would have expired. Under the previous static-list design the late family could not
// participate at all.
func TestEndToEndLateFamilyWins(t *testing.T) {
	const fallbackDelay = 100 * time.Millisecond

	blackhole4 := netip.MustParseAddr("192.0.2.1")
	late6 := netip.MustParseAddr("2001:db8::1")

	router := &fakeDomainRouter{
		addressesA:    []netip.Addr{blackhole4},
		delayA:        5 * time.Millisecond,
		addressesAAAA: []netip.Addr{late6},
		delayAAAA:     200 * time.Millisecond,
	}
	inner := &recordingDialer{failBlackhole: map[netip.Addr]bool{blackhole4: true}}
	dialer := newDomainTestDialer(router, inner, true, fallbackDelay)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, conn)

	// The gate: the late healthy family won, and it did so well inside the connect timeout.
	require.Less(t, elapsed, time.Second,
		"the late family must win promptly, not after the IPv4 connect timeout")
	require.Contains(t, inner.attempts(), blackhole4,
		"the fast family must start as soon as it is known, not wait for its sibling")
	require.Contains(t, inner.attempts(), late6,
		"the late family must join the race rather than being discarded")
}

// TestEndToEndLateFamilyWinsMirror is §44.
//
// The mirror direction. A fix that only handled the IPv6 case would pass the previous test and
// fail this one.
func TestEndToEndLateFamilyWinsMirror(t *testing.T) {
	const fallbackDelay = 100 * time.Millisecond

	blackhole6 := netip.MustParseAddr("2001:db8::1")
	late4 := netip.MustParseAddr("192.0.2.1")

	router := &fakeDomainRouter{
		addressesAAAA: []netip.Addr{blackhole6},
		delayAAAA:     5 * time.Millisecond,
		addressesA:    []netip.Addr{late4},
		delayA:        200 * time.Millisecond,
	}
	inner := &recordingDialer{failBlackhole: map[netip.Addr]bool{blackhole6: true}}
	dialer := newDomainTestDialer(router, inner, true, fallbackDelay)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, conn)
	require.Less(t, elapsed, time.Second,
		"the late IPv4 family must win promptly, not after the IPv6 connect timeout")
	require.Contains(t, inner.attempts(), blackhole6)
	require.Contains(t, inner.attempts(), late4,
		"the late IPv4 family must join the race rather than being discarded")
}

// TestEndToEndPreferredFirstHasNoAddedDelay is §23 and §46.
//
// When the preferred family answers first, the grace period must not delay it. An added 50ms on
// every healthy IPv6 connection would be a serious regression, and one that no correctness test
// would catch.
func TestEndToEndPreferredFirstHasNoAddedDelay(t *testing.T) {
	healthy6 := netip.MustParseAddr("2001:db8::1")
	healthy4 := netip.MustParseAddr("192.0.2.1")

	router := &fakeDomainRouter{
		addressesAAAA: []netip.Addr{healthy6},
		delayAAAA:     5 * time.Millisecond,
		addressesA:    []netip.Addr{healthy4},
		delayA:        500 * time.Millisecond,
	}
	inner := &recordingDialer{}
	dialer := newDomainTestDialer(router, inner, true, 100*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, conn)
	// The preferred family answered at 5ms and the other family is 500ms away. If the grace
	// period were applied to a preferred-first answer, this would take at least 50ms.
	require.Less(t, elapsed, preferredFamilyGrace,
		"a preferred-first answer must not be delayed by the grace period")
}
