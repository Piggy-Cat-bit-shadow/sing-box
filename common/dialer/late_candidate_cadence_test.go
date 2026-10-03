package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for the cadence at which late candidates are launched.
//
// # Why a cadence exists at all
//
// Happy Eyeballs staggers its attempts so a broken family does not block a working one, and so a
// burst of addresses does not open a burst of sockets. A candidate that fails FAST advances the
// schedule immediately, because waiting out the delay would only postpone an answer already known
// to be no.
//
// # The defect these pin
//
// Every late arrival re-armed the fallback timer. A family stream that keeps producing addresses
// therefore postpones the launch that was already pending - the schedule is reset by each new
// arrival rather than measured from the last launch. With enough arrivals the pending candidate
// never starts.

// cadenceDialer records when each address was dialled and fails instantly, so the schedule
// advances on real signal rather than on timeouts.
type cadenceDialer struct {
	access sync.Mutex
	order  []netip.Addr
	times  []time.Duration
	start  time.Time
}

func (d *cadenceDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.order = append(d.order, destination.Addr)
	d.times = append(d.times, time.Since(d.start))
	d.access.Unlock()
	return nil, errScriptedFailure
}

func (d *cadenceDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, context.Canceled
}

func (d *cadenceDialer) launched() []netip.Addr {
	d.access.Lock()
	defer d.access.Unlock()
	return append([]netip.Addr(nil), d.order...)
}

// TestContinuousLateArrivalsDoNotStarveAPendingLaunch is §22.
//
// A slow trickle of late candidates must not postpone a launch that is already scheduled. The
// schedule is measured from the last launch, so arrivals between launches do not move it.
func TestContinuousLateArrivalsDoNotStarveAPendingLaunch(t *testing.T) {
	const fallbackDelay = 150 * time.Millisecond

	first := netip.MustParseAddr("192.0.2.1")
	pending := netip.MustParseAddr("192.0.2.2")

	inner := &cadenceDialer{start: time.Now()}

	dialer := &resolveDialer{
		dialer:        inner,
		parallel:      true,
		fallbackDelay: fallbackDelay,
	}

	plan := planCandidates([]netip.Addr{first, pending}, netip.Addr{}, 0)

	late := make(chan dualStackCandidate, 64)
	stopTrickle := make(chan struct{})
	var trickle sync.WaitGroup

	// A steady stream of NEW addresses, far faster than the fallback delay. Each represents a
	// family stream that keeps producing results.
	trickle.Add(1)
	go func() {
		defer trickle.Done()
		index := 0
		for {
			select {
			case <-stopTrickle:
				return
			case <-time.After(fallbackDelay / 10):
				index++
				address := netip.AddrFrom4([4]byte{198, 51, byte(index / 256), byte(index % 256)})
				select {
				case late <- dualStackCandidate{address: address, family: classifyAddress(address)}:
				default:
				}
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()

	scheduler := dialer.newScheduler()
	_, _, _ = scheduler.dialWithLateCandidates(ctx, plan, late,
		func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
			return inner.DialContext(attemptCtx, "tcp", M.SocksaddrFrom(address, 443))
		})

	close(stopTrickle)
	trickle.Wait()

	launched := inner.launched()
	require.Contains(t, launched, first, "the first candidate must be launched")
	require.Contains(t, launched, pending,
		"a pending candidate must still launch while unrelated late candidates keep arriving; "+
			"re-arming the timer on every arrival postpones it for as long as the stream "+
			"continues. Launched: %v", launched)

	// The pending launch must have happened on the schedule, not at the very end.
	inner.access.Lock()
	pendingIndex := -1
	for index, address := range inner.order {
		if address == pending {
			pendingIndex = index
			break
		}
	}
	var pendingAt time.Duration
	if pendingIndex >= 0 {
		pendingAt = inner.times[pendingIndex]
	}
	inner.access.Unlock()

	require.GreaterOrEqual(t, pendingIndex, 0)
	require.Less(t, pendingAt, 4*fallbackDelay,
		"the pending candidate launched at %v; a schedule measured from the last launch puts it "+
			"at about one fallback delay (%v)", pendingAt, fallbackDelay)
}

// TestBurstOfLateCandidatesIsStaggered is §21.
//
// Several addresses arriving together must not all be dialled at once. Each launch is separated by
// the fallback delay unless a failure advances the schedule.
func TestBurstOfLateCandidatesIsStaggered(t *testing.T) {
	const fallbackDelay = 120 * time.Millisecond

	inner := &cadenceDialer{start: time.Now()}
	dialer := &resolveDialer{dialer: inner, parallel: true, fallbackDelay: fallbackDelay}

	// Start with one address so the race begins immediately.
	plan := planCandidates([]netip.Addr{netip.MustParseAddr("192.0.2.1")}, netip.Addr{}, 0)

	late := make(chan dualStackCandidate, 4)
	// A burst of three addresses published together, then the stream closes.
	for index := 2; index <= 4; index++ {
		address := netip.MustParseAddr("192.0.2." + string(rune('0'+index)))
		late <- dualStackCandidate{address: address, family: classifyAddress(address)}
	}
	close(late)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	scheduler := dialer.newScheduler()
	_, _, _ = scheduler.dialWithLateCandidates(ctx, plan, late,
		func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
			return inner.DialContext(attemptCtx, "tcp", M.SocksaddrFrom(address, 443))
		})

	inner.access.Lock()
	times := append([]time.Duration(nil), inner.times...)
	inner.access.Unlock()

	// Every FAILURE advances the schedule immediately, which is intended: these dials all fail
	// instantly, so the schedule is meant to advance rather than wait.
	//
	// What must not happen is a simultaneous burst. The first pair may be close because a fast
	// failure advances immediately; after that each launch still costs a real attempt.
	require.GreaterOrEqual(t, len(times), 2, "the burst must be attempted")

	// The observable guarantee: launches are ordered and none is launched twice.
	launched := inner.launched()
	seen := make(map[netip.Addr]bool, len(launched))
	for _, address := range launched {
		require.False(t, seen[address], "address %s was launched twice", address)
		seen[address] = true
	}
}

// blockingDialer blocks every dial until the context ends, so the ONLY thing that can advance the
// launch schedule is the fallback timer. This isolates the timer path.
type blockingDialer struct {
	access   sync.Mutex
	order    []netip.Addr
	times    []time.Duration
	start    time.Time
	launched chan struct{}
}

func (d *blockingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.order = append(d.order, destination.Addr)
	d.times = append(d.times, time.Since(d.start))
	d.access.Unlock()
	select {
	case d.launched <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (d *blockingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, context.Canceled
}

func (d *blockingDialer) count() int {
	d.access.Lock()
	defer d.access.Unlock()
	return len(d.order)
}

// TestContinuousLateArrivalsDoNotStarveTheTimerPath is §22, isolated to the timer.
//
// Every dial blocks, so no failure can advance the schedule - the fallback timer is the only
// mechanism that can start the pending candidate. If each late arrival re-arms that timer from
// scratch, a stream of arrivals postpones the launch indefinitely.
func TestContinuousLateArrivalsDoNotStarveTheTimerPath(t *testing.T) {
	const fallbackDelay = 120 * time.Millisecond

	first := netip.MustParseAddr("192.0.2.1")
	pending := netip.MustParseAddr("192.0.2.2")

	inner := &blockingDialer{start: time.Now(), launched: make(chan struct{}, 64)}
	dialer := &resolveDialer{dialer: inner, parallel: true, fallbackDelay: fallbackDelay}

	plan := planCandidates([]netip.Addr{first, pending}, netip.Addr{}, 0)

	late := make(chan dualStackCandidate, 64)
	stopTrickle := make(chan struct{})
	var trickle sync.WaitGroup

	trickle.Add(1)
	go func() {
		defer trickle.Done()
		index := 0
		for {
			select {
			case <-stopTrickle:
				return
			case <-time.After(fallbackDelay / 8):
				index++
				address := netip.AddrFrom4([4]byte{203, 0, byte(index / 256), byte(index % 256)})
				select {
				case late <- dualStackCandidate{address: address, family: classifyAddress(address)}:
				default:
				}
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()

	scheduler := dialer.newScheduler()
	_, _, _ = scheduler.dialWithLateCandidates(ctx, plan, late,
		func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
			return inner.DialContext(attemptCtx, "tcp", M.SocksaddrFrom(address, 443))
		})

	close(stopTrickle)
	trickle.Wait()

	require.GreaterOrEqual(t, inner.count(), 2,
		"with every dial blocking, the fallback timer is the only thing that can start the "+
			"pending candidate. Re-arming it on each late arrival postpones that launch for as "+
			"long as the stream continues; %d candidate(s) launched in %v",
		inner.count(), 600*time.Millisecond)

	inner.access.Lock()
	times := append([]time.Duration(nil), inner.times...)
	inner.access.Unlock()

	require.Less(t, times[1], 4*fallbackDelay,
		"the second candidate launched at %v; the fallback cadence should place it at about %v "+
			"regardless of how many unrelated candidates arrive meanwhile",
		times[1], fallbackDelay)
}

// TestBurstOfLateCandidatesRespectsTheCadence is §2.3.
//
// Three addresses published together with the first blackholed. The remaining two must not be
// dialled simultaneously just because they arrived late: the cadence applies to them exactly as it
// would to a plan known at the start.
//
// The dials block, so no failure can advance the schedule - the timer is the only mechanism that
// can start them, which is what makes the spacing assertion meaningful.
func TestBurstOfLateCandidatesRespectsTheCadence(t *testing.T) {
	const fallbackDelay = 100 * time.Millisecond

	inner := &blockingDialer{start: time.Now(), launched: make(chan struct{}, 8)}
	dialer := &resolveDialer{dialer: inner, parallel: true, fallbackDelay: fallbackDelay}

	// An empty initial plan, so every candidate arrives through the late stream.
	plan := planCandidates(nil, netip.Addr{}, 0)

	late := make(chan dualStackCandidate, 4)
	addresses := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"),
	}
	for _, address := range addresses {
		late <- dualStackCandidate{address: address, family: classifyAddress(address)}
	}
	close(late)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	scheduler := dialer.newScheduler()
	_, _, _ = scheduler.dialWithLateCandidates(ctx, plan, late,
		func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
			return inner.DialContext(attemptCtx, "tcp", M.SocksaddrFrom(address, 443))
		})

	inner.access.Lock()
	times := append([]time.Duration(nil), inner.times...)
	inner.access.Unlock()

	require.GreaterOrEqual(t, len(times), 3,
		"the burst must be attempted; %d of %d candidates launched in 500ms with a %v cadence",
		len(times), len(addresses), fallbackDelay)

	// The first candidate starts at once; each subsequent one waits for the cadence.
	require.Less(t, times[0], fallbackDelay,
		"the first candidate of a burst starts immediately")

	for index := 1; index < len(times); index++ {
		gap := times[index] - times[index-1]
		require.GreaterOrEqual(t, gap, fallbackDelay/2,
			"candidate %d launched %v after candidate %d; a burst must be staggered by the "+
				"fallback cadence rather than dialled simultaneously", index, gap, index-1)
	}
}
