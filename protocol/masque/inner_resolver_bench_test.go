package masque

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// These benchmarks measure WALL-CLOCK connection time for the inner path, which is
// what a user actually experiences. They are not CPU benchmarks: the question is
// "how long until the tunnel carries my traffic", not "how many ns does the race
// cost the scheduler".
//
// They are written as tests (run with -bench) over the same fake dialers as the
// behavioural tests, so the numbers are directly comparable to the mutation
// measurement recorded in the commit: 102ms raced versus 10.0s serial.

func benchmarkRace(b *testing.B, ipv6Blackholed bool, fallbackDelay time.Duration) {
	blackhole := &unreachableDialer{release: make(chan struct{})}
	defer close(blackhole.release)
	reachable := &reachableDialer{accepted: make(chan string, 1)}

	var dialer N.Dialer
	var addresses []netip.Addr
	var preferV6 bool
	if ipv6Blackholed {
		dialer = &familyDialer{ipv6: blackhole, ipv4: reachable}
		addresses = []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("1.2.3.4")}
		preferV6 = true
	} else {
		dialer = &familyDialer{ipv6: reachable, ipv4: blackhole}
		addresses = []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("2001:db8::1")}
		preferV6 = false
	}

	b.ResetTimer()
	for range b.N {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		conn, err := N.DialParallel(ctx, dialer, N.NetworkTCP, M.Socksaddr{}, addresses, preferV6, fallbackDelay)
		cancel()
		if err != nil {
			b.Fatalf("dial failed: %v", err)
		}
		if conn != nil {
			_ = conn.Close()
		}
	}
}

// BenchmarkInnerTCPRaceBrokenIPv6 is the headline case: a dual-stack target on a
// network whose IPv6 path is blackholed. This is the scenario the race exists for.
func BenchmarkInnerTCPRaceBrokenIPv6(b *testing.B) {
	benchmarkRace(b, true, N.DefaultFallbackDelay)
}

// BenchmarkInnerTCPRaceBrokenIPv4 is the mirror, so neither family is special.
func BenchmarkInnerTCPRaceBrokenIPv4(b *testing.B) {
	benchmarkRace(b, false, N.DefaultFallbackDelay)
}

// BenchmarkInnerTCPSerialBaseline measures the PREVIOUS behaviour under identical
// conditions, so the comparison is available in-tree rather than only in a commit
// message. It dials the same blackholed-first address list serially.
func BenchmarkInnerTCPSerialBaseline(b *testing.B) {
	blackhole := &unreachableDialer{release: make(chan struct{})}
	defer close(blackhole.release)
	reachable := &reachableDialer{accepted: make(chan string, 1)}
	dialer := &familyDialer{ipv6: blackhole, ipv4: reachable}
	addresses := []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("1.2.3.4")}

	b.ResetTimer()
	for range b.N {
		// The serial path blocks on the blackholed address until the context ends, so
		// this context is deliberately short (500ms) to keep the benchmark runnable.
		// That makes this number a LOWER BOUND rather than a measurement: with a
		// realistic 10s dial timeout the serial attempt blocks for 10s, which the
		// mutation test in inner_happy_eyeballs_test.go records (10.001s serial
		// against 102ms raced). Read this as "at least 1.7x worse here, about 98x
		// under a real timeout", not as an exact figure.
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		conn, err := N.DialSerial(ctx, dialer, N.NetworkTCP, M.Socksaddr{}, addresses)
		cancel()
		if err == nil && conn != nil {
			_ = conn.Close()
		}
	}
}

// BenchmarkInnerTCPSingleFamily proves a single-stack answer costs nothing: no
// fallback timer is started, so the time matches a plain dial.
func BenchmarkInnerTCPSingleFamily(b *testing.B) {
	reachable := &reachableDialer{accepted: make(chan string, 1)}
	dialer := &familyDialer{ipv4: reachable, ipv6: &unreachableDialer{}}
	addresses := []netip.Addr{netip.MustParseAddr("1.2.3.4")}

	b.ResetTimer()
	for range b.N {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := N.DialParallel(ctx, dialer, N.NetworkTCP, M.Socksaddr{}, addresses, true, N.DefaultFallbackDelay)
		cancel()
		if err != nil {
			b.Fatalf("dial failed: %v", err)
		}
		if conn != nil {
			_ = conn.Close()
		}
	}
}

var _ net.Conn = (net.Conn)(nil)
