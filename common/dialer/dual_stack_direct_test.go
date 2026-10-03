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

// Tests for family-health binding on the exported DialParallelNetwork path (§27-§33).
//
// # The gap these close
//
// The exported DialParallelNetwork - which the direct outbound reaches for an actionResolve
// candidate list and for flow-route candidates - passed health: nil. It therefore never shared
// the verdict the hostname path accumulates, and the two paths learned about a broken family
// independently: a literal destination could not benefit from what a hostname connection had
// already discovered.
//
// The fix discovers the owner from the dialer chain instead of taking it as a parameter, so the
// public signature is unchanged and no caller has to know the concept exists.

// ownerDialer is a real DefaultDialer whose connection attempts are delegated to a fake, so the
// test exercises the production type and the production scheduler factory.
type ownerDialer struct {
	owner *DefaultDialer
	inner *stallingDialer

	// counters let a test observe that the owner's factory was actually used.
	factoryCalls atomic.Int32
}

func (d *ownerDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.inner.DialContext(ctx, network, destination)
}

func (d *ownerDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.inner.ListenPacket(ctx, destination)
}

func (d *ownerDialer) newDualStackScheduler(fallbackDelay time.Duration) *candidateScheduler {
	d.factoryCalls.Add(1)
	return d.owner.newDualStackScheduler(fallbackDelay)
}

// DialParallelInterface satisfies ParallelInterfaceDialer. The scheduler only uses it to route
// the per-attempt connect, so delegating to the fake is enough.
func (d *ownerDialer) DialParallelInterface(ctx context.Context, network string, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	return d.inner.DialContext(ctx, network, destination)
}

func (d *ownerDialer) ListenSerialInterfacePacket(ctx context.Context, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, error) {
	return nil, context.Canceled
}

// TestExportedDialParallelBindsTheOwner is §31.
//
// The exported function must find the owner in the chain and use its scheduler, so the verdict
// survives across calls.
func TestExportedDialParallelBindsTheOwner(t *testing.T) {
	blackhole6 := netip.MustParseAddr("2001:db8::1")
	healthy4 := netip.MustParseAddr("192.0.2.1")

	owner := &DefaultDialer{familyHealth: newFamilyHealth()}
	inner := newStallingDialer()
	inner.stall = map[netip.Addr]bool{blackhole6: true}
	bound := &ownerDialer{owner: owner, inner: inner}

	// First call: IPv6 blackholes, IPv4 wins, and the owner's health learns it.
	_, err := DialParallelNetwork(context.Background(), bound, "tcp",
		M.SocksaddrFrom(healthy4, 443),
		[]netip.Addr{blackhole6, healthy4},
		true, nil, nil, nil, 60*time.Millisecond)
	require.NoError(t, err)

	require.Greater(t, bound.factoryCalls.Load(), int32(0),
		"the exported path must build its scheduler through the owner, not a health-less one")
	require.True(t, owner.familyHealth.fallbackImmediately(owner.networkEnvironment(), familyIPv6, familyIPv4),
		"the direct path must record what it observed into the long-lived owner")
}

// TestExportedDialParallelReusesHealthAcrossCalls is the decisive §31 assertion: the SECOND
// call benefits from the first.
func TestExportedDialParallelReusesHealthAcrossCalls(t *testing.T) {
	blackhole6 := netip.MustParseAddr("2001:db8::1")
	healthy4 := netip.MustParseAddr("192.0.2.1")

	owner := &DefaultDialer{familyHealth: newFamilyHealth()}

	firstInner := newStallingDialer()
	firstInner.stall = map[netip.Addr]bool{blackhole6: true}
	firstBound := &ownerDialer{owner: owner, inner: firstInner}

	// --- call one: learn that IPv6 stalls ---
	_, err := DialParallelNetwork(context.Background(), firstBound, "tcp",
		M.SocksaddrFrom(healthy4, 443),
		[]netip.Addr{blackhole6, healthy4},
		true, nil, nil, nil, 60*time.Millisecond)
	require.NoError(t, err)

	// --- call two: the verdict must be in force ---
	//
	// The fallback delay is two seconds. If the verdict were not shared, IPv4 would be launched
	// only after that delay and this assertion could not pass.
	secondInner := newStallingDialer()
	secondInner.stall = map[netip.Addr]bool{blackhole6: true}
	secondBound := &ownerDialer{owner: owner, inner: secondInner}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = DialParallelNetwork(ctx, secondBound, "tcp",
		M.SocksaddrFrom(healthy4, 443),
		[]netip.Addr{blackhole6, healthy4},
		true, nil, nil, nil, 2*time.Second)
	require.NoError(t, err)

	times := secondInner.attemptTimes()
	require.Len(t, times, 2, "both families' first candidates must have started")
	require.Less(t, times[1], 200*time.Millisecond,
		"the second call must reuse the health learned by the first; the other family started "+
			"after %v of a 2s fallback delay", times[1])
}

// TestExportedDialParallelWithoutOwnerStillRaces is §33.
//
// A caller-supplied dialer has no owner. Racing must still work, must not panic, and must not
// invent a per-call health.
func TestExportedDialParallelWithoutOwnerStillRaces(t *testing.T) {
	slow6 := netip.MustParseAddr("2001:db8::1")
	fast4 := netip.MustParseAddr("192.0.2.1")

	inner := &orderedDialer{
		delays: map[netip.Addr]time.Duration{
			slow6: 2 * time.Second,
			fast4: 5 * time.Millisecond,
		},
	}

	// A bare dialer with no owner anywhere in the chain.
	bare := &bareParallelDialer{inner: inner}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := DialParallelNetwork(ctx, bare, "tcp",
		M.SocksaddrFrom(fast4, 443),
		[]netip.Addr{slow6, fast4},
		true, nil, nil, nil, 20*time.Millisecond)
	require.NoError(t, err, "a dialer without an owner must still race successfully")
	require.NotNil(t, conn)
	require.Contains(t, inner.attempts(), fast4)
}

// TestFindFamilyHealthOwnerWalksTheChain is §28.
//
// The discovery must see through the wrappers the production chain actually uses, and must stop
// cleanly at an unknown dialer rather than guessing.
func TestFindFamilyHealthOwnerWalksTheChain(t *testing.T) {
	owner := &DefaultDialer{familyHealth: newFamilyHealth()}
	wrapped := &ownerDialer{owner: owner, inner: newStallingDialer()}

	// Directly.
	found, ok := findFamilyHealthOwner(wrapped)
	require.True(t, ok, "a direct owner must be found")
	require.NotNil(t, found)

	// Through a resolveDialer.
	resolver := &resolveDialer{dialer: wrapped, parallel: true}
	found, ok = findFamilyHealthOwner(resolver)
	require.True(t, ok, "the owner must be found through a resolveDialer")
	require.NotNil(t, found)

	// Through the parallel resolve variant.
	parallel := &resolveParallelNetworkDialer{resolveDialer: resolveDialer{dialer: wrapped}, dialer: wrapped}
	found, ok = findFamilyHealthOwner(parallel)
	require.True(t, ok, "the owner must be found through a resolveParallelNetworkDialer")
	require.NotNil(t, found)

	// A dialer with no owner must report not-found rather than a bogus owner.
	_, ok = findFamilyHealthOwner(&orderedDialer{})
	require.False(t, ok, "a dialer without an owner must not be reported as one")

	// And a nil dialer must not panic.
	_, ok = findFamilyHealthOwner(nil)
	require.False(t, ok)
}

// TestExportedDialParallelIsRaceClean exercises the direct path under the race detector with
// concurrent calls, since each builds a scheduler from the shared owner.
func TestExportedDialParallelIsRaceClean(t *testing.T) {
	address4A := netip.MustParseAddr("192.0.2.1")
	address4B := netip.MustParseAddr("192.0.2.2")

	owner := &DefaultDialer{familyHealth: newFamilyHealth()}

	const workers = 6
	done := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			inner := &orderedDialer{delays: map[netip.Addr]time.Duration{}}
			bound := &ownerDialer{owner: owner, inner: newStallingDialer()}
			_ = inner
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err := DialParallelNetwork(ctx, bound, "tcp",
				M.SocksaddrFrom(address4A, 443),
				[]netip.Addr{address4A, address4B},
				false, nil, nil, nil, 10*time.Millisecond)
			done <- err
		}()
	}
	for i := 0; i < workers; i++ {
		require.NoError(t, <-done)
	}
}

// bareParallelDialer is a ParallelInterfaceDialer with NO familyHealthOwner anywhere in its
// chain, which is what §33 requires to prove the generic caller path still works.
type bareParallelDialer struct {
	inner *orderedDialer
}

func (d *bareParallelDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.inner.DialContext(ctx, network, destination)
}

func (d *bareParallelDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.inner.ListenPacket(ctx, destination)
}

func (d *bareParallelDialer) DialParallelInterface(ctx context.Context, network string, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	return d.inner.DialContext(ctx, network, destination)
}

func (d *bareParallelDialer) ListenSerialInterfacePacket(ctx context.Context, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, error) {
	return nil, context.Canceled
}

var _ = C.DomainStrategyPreferIPv6
