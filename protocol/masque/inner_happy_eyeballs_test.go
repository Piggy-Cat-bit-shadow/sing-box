package masque

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// errTestNoRoute stands in for a dial failure. The concrete error does not matter
// to these tests, only whether an attempt failed.
var errTestNoRoute = errors.New("test: no route")

// These tests prove the properties that make the family race WORTH having, using a
// fake dialer rather than real sockets so they are deterministic and fast.
//
// The failure they exist to catch is a SERIAL stall: if the race were not in place,
// a dual-stack target whose first-family path is blackholed would take the whole
// per-attempt timeout before the second family was tried. That is the real-world
// symptom (a page that hangs for seconds on a broken IPv6 network), and it is
// invisible to a test that only checks "a connection was eventually made".

// unreachableDialer models a blackholed address family: dialling it blocks until
// the context is done, exactly as a dropped packet does. It records how long each
// attempt was allowed to run so the test can show the race cut it short.
type unreachableDialer struct {
	mu       sync.Mutex
	attempts []string
	// release, when set, unblocks blackholed dials early so a failing test cannot
	// hang the suite.
	release chan struct{}
}

func (d *unreachableDialer) note(address string) {
	d.mu.Lock()
	d.attempts = append(d.attempts, address)
	d.mu.Unlock()
}

func (d *unreachableDialer) attempted() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.attempts...)
}

func (d *unreachableDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.note("blackhole:" + destination.Addr.String())
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.release:
		return nil, errTestNoRoute
	}
}

func (d *unreachableDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.note("blackhole-udp:" + destination.Addr.String())
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.release:
		return nil, errTestNoRoute
	}
}

func (d *unreachableDialer) ListenSerialPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	return nil, netip.Addr{}, errTestNoRoute
}

// reachableDialer accepts immediately and records that it was reached.
type reachableDialer struct {
	accepted chan string
}

func (d *reachableDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	select {
	case d.accepted <- destination.Addr.String():
	default:
	}
	client, server := net.Pipe()
	go func() {
		// Keep the far end alive until the client closes, so the returned conn is
		// usable for the duration of the assertion.
		_, _ = server.Read(make([]byte, 1))
		_ = server.Close()
	}()
	return client, nil
}

func (d *reachableDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errTestNoRoute
}

func (d *reachableDialer) ListenSerialPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	return nil, netip.Addr{}, errTestNoRoute
}

// TestTCPRaceDoesNotWaitForABlackholedFirstFamily is the core assertion.
//
// The preferred family is blackholed and the other family answers. The connection
// must be made in roughly ONE fallback delay, not after the blackholed attempt
// exhausts its own timeout.
func TestTCPRaceDoesNotWaitForABlackholedFirstFamily(t *testing.T) {
	t.Parallel()

	const fallbackDelay = 100 * time.Millisecond

	blackhole := &unreachableDialer{release: make(chan struct{})}
	defer close(blackhole.release)
	reachable := &reachableDialer{accepted: make(chan string, 1)}

	// A dialer that routes by family: IPv6 is blackholed, IPv4 answers. This is
	// the "broken IPv6 network" shape.
	mixed := &familyDialer{ipv6: blackhole, ipv4: reachable}

	addresses := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"), // preferred, unreachable
		netip.MustParseAddr("1.2.3.4"),     // fallback, healthy
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := N.DialParallel(ctx, mixed, N.NetworkTCP, M.Socksaddr{}, addresses, true, fallbackDelay)
	elapsed := time.Since(start)

	require.NoError(t, err, "the healthy family must be reached")
	require.NotNil(t, conn)
	defer conn.Close()

	// The whole point: the healthy family is reached at about the fallback delay,
	// not after the blackholed attempt's own timeout (which is the 10s context).
	require.Less(t, elapsed, 3*time.Second,
		"connecting took %s; the race did not cut the blackholed family short. "+
			"A serial dial would block on the blackholed address until the context "+
			"expired, which is the exact user-visible symptom this race prevents", elapsed)

	select {
	case got := <-reachable.accepted:
		require.Equal(t, "1.2.3.4", got, "the IPv4 address must be the one that connected")
	default:
		t.Fatal("the healthy family recorded no accepted connection")
	}
	t.Logf("OBSERVED: blackholed IPv6 + healthy IPv4 connected in %s (fallback delay %s)",
		elapsed.Round(time.Millisecond), fallbackDelay)
}

// TestTCPRaceDoesNotWaitForABlackholedIPv4 is the mirror image, so the test cannot
// pass by always preferring one family.
func TestTCPRaceDoesNotWaitForABlackholedIPv4(t *testing.T) {
	t.Parallel()

	const fallbackDelay = 100 * time.Millisecond

	blackhole := &unreachableDialer{release: make(chan struct{})}
	defer close(blackhole.release)
	reachable := &reachableDialer{accepted: make(chan string, 1)}

	mixed := &familyDialer{ipv6: reachable, ipv4: blackhole}

	addresses := []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),     // preferred (IPv4-first), unreachable
		netip.MustParseAddr("2001:db8::1"), // fallback, healthy
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := N.DialParallel(ctx, mixed, N.NetworkTCP, M.Socksaddr{}, addresses, false, fallbackDelay)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()
	require.Less(t, elapsed, 3*time.Second, "took %s; the race did not cut IPv4 short", elapsed)

	select {
	case got := <-reachable.accepted:
		require.Equal(t, "2001:db8::1", got)
	default:
		t.Fatal("the healthy family recorded no accepted connection")
	}
	t.Logf("OBSERVED: blackholed IPv4 + healthy IPv6 connected in %s", elapsed.Round(time.Millisecond))
}

// TestSingleFamilyAnswerDoesNotRace proves a single-stack target pays nothing for
// this feature: with one family there is no race and no added delay.
func TestSingleFamilyAnswerDoesNotRace(t *testing.T) {
	t.Parallel()

	reachable := &reachableDialer{accepted: make(chan string, 1)}
	mixed := &familyDialer{ipv4: reachable, ipv6: &unreachableDialer{}}

	addresses := []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := N.DialParallel(ctx, mixed, N.NetworkTCP, M.Socksaddr{}, addresses, true, 100*time.Millisecond)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()
	require.Less(t, elapsed, time.Second,
		"a single-family answer must not be delayed by the fallback timer")
}

// familyDialer routes a dial to one of two dialers by address family.
type familyDialer struct {
	ipv4 N.Dialer
	ipv6 N.Dialer
}

func (d *familyDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.Addr.Is4() || destination.Addr.Is4In6() {
		return d.ipv4.DialContext(ctx, network, destination)
	}
	return d.ipv6.DialContext(ctx, network, destination)
}

func (d *familyDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if destination.Addr.Is4() || destination.Addr.Is4In6() {
		return d.ipv4.ListenPacket(ctx, destination)
	}
	return d.ipv6.ListenPacket(ctx, destination)
}

func (d *familyDialer) ListenSerialPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	return nil, netip.Addr{}, errTestNoRoute
}
