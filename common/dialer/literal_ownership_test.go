package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// State-machine tests for literal recovery.
//
// # What this covers
//
// dialLiteralWithRecovery runs the application's own address and, while it is still pending, a set
// of recovered candidates. Both halves must have exactly one owner, the original must not be
// dialled twice, and every outcome - original wins, recovery wins, both fail, parent cancelled -
// must terminate without leaving a worker or a connection behind.

// attemptLog records every dial with its address and start time.
type attemptLog struct {
	access  sync.Mutex
	entries []attemptEntry
	start   time.Time
}

type attemptEntry struct {
	address netip.Addr
	at      time.Duration
}

func (l *attemptLog) record(address netip.Addr) {
	l.access.Lock()
	defer l.access.Unlock()
	l.entries = append(l.entries, attemptEntry{address: address, at: time.Since(l.start)})
}

func (l *attemptLog) countFor(address netip.Addr) int {
	l.access.Lock()
	defer l.access.Unlock()
	count := 0
	for _, entry := range l.entries {
		if entry.address == address {
			count++
		}
	}
	return count
}

func (l *attemptLog) snapshot() []attemptEntry {
	l.access.Lock()
	defer l.access.Unlock()
	return append([]attemptEntry(nil), l.entries...)
}

// scriptedDialer answers per address on a schedule and records every attempt.
type scriptedDialer struct {
	log     *attemptLog
	answers map[netip.Addr]scriptedAnswer
}

type scriptedAnswer struct {
	delay   time.Duration
	success bool
	// block waits for cancellation instead of a delay.
	block bool
}

func (d *scriptedDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	address := destination.Addr
	d.log.record(address)

	answer, configured := d.answers[address]
	if !configured {
		return nil, errUnconfigured
	}
	if answer.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if answer.delay > 0 {
		select {
		case <-time.After(answer.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if !answer.success {
		return nil, errScriptedFailure
	}
	return &countingConn{}, nil
}

func (d *scriptedDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, context.Canceled
}

var (
	errUnconfigured    = scriptedErr("address not configured")
	errScriptedFailure = scriptedErr("scripted failure")
)

type scriptedErr string

func (e scriptedErr) Error() string { return string(e) }

// newRecoveryFixture builds a resolveDialer with recovery enabled.
func newRecoveryFixture(t *testing.T, link string, answers map[netip.Addr]scriptedAnswer, fallbackDelay time.Duration) (*resolveDialer, *attemptLog) {
	t.Helper()
	log := &attemptLog{start: time.Now()}
	return &resolveDialer{
		router:        &staticStreamingRouter{},
		dialer:        &scriptedDialer{log: log, answers: answers},
		parallel:      true,
		fallbackDelay: fallbackDelay,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}, log
}

// staticStreamingRouter answers a recovery lookup with fixed addresses.
type staticStreamingRouter struct {
	adapter.DNSRouter
	addresses []netip.Addr
}

func (r *staticStreamingRouter) LookupFamilies(ctx context.Context, domain string, options adapter.DNSQueryOptions, publish func(adapter.DNSFamilyResult)) error {
	for _, address := range r.addresses {
		publish(adapter.DNSFamilyResult{
			IPv6:      address.Is6() && !address.Is4In6(),
			Addresses: []netip.Addr{address},
		})
	}
	return nil
}

func (r *staticStreamingRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return r.addresses, nil
}

// TestLiteralRecoveryDoesNotDialTheOriginalTwice is §29 and §30.
//
// The original already runs as its own attempt. Merging it back into the recovered candidate list
// dials it a second time, which wastes an attempt and - because the recovered plan is staggered -
// delays the healthy family behind a duplicate of the address that is already failing.
func TestLiteralRecoveryDoesNotDialTheOriginalTwice(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	recovered := netip.MustParseAddr("192.0.2.2")

	dialer, log := newRecoveryFixture(t, "sniffed.example", map[netip.Addr]scriptedAnswer{
		// The original never answers: it holds until the race is decided.
		original: {block: true},
		// The recovered family is healthy and answers promptly.
		recovered: {delay: 5 * time.Millisecond, success: true},
	}, 20*time.Millisecond)
	dialer.router = &staticStreamingRouter{addresses: []netip.Addr{recovered}}

	ctx, cancel := context.WithTimeout(recoveryContext(), 5*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	require.NoError(t, err)
	require.NotNil(t, conn)

	require.Equal(t, 1, log.countFor(original),
		"the original must be dialled exactly once; the recovered plan already has the original "+
			"running as its own attempt, so merging it back dials it twice")
	require.Equal(t, 1, log.countFor(recovered),
		"the recovered address must be dialled exactly once")
}

// TestLiteralRecoveryUsesTheRecoveredFamilyPromptly is the timing half of §30.
//
// With the original duplicated into the recovered plan, the healthy family is pushed behind it in
// the stagger, so recovery takes about twice the fallback delay instead of the delay itself.
func TestLiteralRecoveryUsesTheRecoveredFamilyPromptly(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	recovered := netip.MustParseAddr("192.0.2.2")
	const fallbackDelay = 60 * time.Millisecond

	dialer, log := newRecoveryFixture(t, "sniffed.example", map[netip.Addr]scriptedAnswer{
		original:  {block: true},
		recovered: {delay: 5 * time.Millisecond, success: true},
	}, fallbackDelay)
	dialer.router = &staticStreamingRouter{addresses: []netip.Addr{recovered}}

	ctx, cancel := context.WithTimeout(recoveryContext(), 5*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, conn)

	// The recovered candidate should start around one fallback delay after the original, not two.
	require.Less(t, elapsed, fallbackDelay*2,
		"recovery took %v, which is more than two fallback delays (%v): the healthy family is "+
			"being delayed behind a duplicate of the original", elapsed, fallbackDelay)

	for _, entry := range log.snapshot() {
		if entry.address == recovered {
			require.Less(t, entry.at, fallbackDelay*2,
				"the recovered candidate started at %v, which is behind a duplicated original",
				entry.at)
		}
	}
}

// TestLiteralRecoveryFastOriginalFailureStillTriesRecovery is §31.
//
// The original fails almost immediately, before the recovery lookup has finished. Recovery must
// still get its chance: the previous logic read the recovery channel non-blockingly and, finding
// it empty, returned the original's error without ever trying the recovered candidate.
func TestLiteralRecoveryFastOriginalFailureStillTriesRecovery(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	recovered := netip.MustParseAddr("192.0.2.2")

	dialer, log := newRecoveryFixture(t, "sniffed.example", map[netip.Addr]scriptedAnswer{
		// Fails immediately.
		original: {delay: time.Millisecond, success: false},
		// Healthy, but the lookup that reveals it takes longer than the original's failure.
		recovered: {delay: time.Millisecond, success: true},
	}, 20*time.Millisecond)
	dialer.router = &slowStreamingRouter{
		addresses: []netip.Addr{recovered},
		delay:     20 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(recoveryContext(), 5*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))

	require.NoError(t, err,
		"the original failed fast but a healthy recovered candidate existed; returning the "+
			"original's error without trying it discards the whole point of recovery")
	require.NotNil(t, conn)
	require.Equal(t, 1, log.countFor(recovered),
		"the recovered candidate must have been attempted")
}

// slowStreamingRouter reveals its answers only after a delay, so recovery completes after the
// original attempt has already failed.
type slowStreamingRouter struct {
	adapter.DNSRouter
	addresses []netip.Addr
	delay     time.Duration
}

func (r *slowStreamingRouter) LookupFamilies(ctx context.Context, domain string, options adapter.DNSQueryOptions, publish func(adapter.DNSFamilyResult)) error {
	select {
	case <-time.After(r.delay):
	case <-ctx.Done():
		return ctx.Err()
	}
	for _, address := range r.addresses {
		publish(adapter.DNSFamilyResult{Addresses: []netip.Addr{address}})
	}
	return nil
}

func (r *slowStreamingRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	select {
	case <-time.After(r.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return r.addresses, nil
}
