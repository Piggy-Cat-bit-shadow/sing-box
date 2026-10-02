package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
)

// Benchmarks for candidate planning and the single-candidate fast path (§90, §91).
//
// # What matters here
//
// A single candidate is the most frequent case in the process - a literal IP with no
// recovery - so the architecture must not cost a goroutine, a timer or a channel there. The
// allocs/op for that case is the number to watch: if adding dual-stack support made the
// ordinary path allocate, that is a regression on every connection.

func benchAddresses(tb testing.TB, count int) []netip.Addr {
	tb.Helper()
	addresses := make([]netip.Addr, 0, count)
	for i := 0; i < count; i++ {
		if i%2 == 0 {
			addresses = append(addresses, netip.MustParseAddr(fmt.Sprintf("2001:db8::%d", i+1)))
		} else {
			addresses = append(addresses, netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", (i%250)+1)))
		}
	}
	return addresses
}

func BenchmarkPlanCandidates(b *testing.B) {
	for _, count := range []int{2, 4, 8} {
		b.Run(fmt.Sprintf("candidates-%d", count), func(b *testing.B) {
			addresses := benchAddresses(b, count)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				plan := planCandidates(addresses, netip.Addr{}, C.DomainStrategyPreferIPv6)
				if len(plan.candidates) == 0 {
					b.Fatal("empty plan")
				}
			}
		})
	}
}

func BenchmarkPlanCandidatesWithOriginal(b *testing.B) {
	addresses := benchAddresses(b, 6)
	original := netip.MustParseAddr("240e:1::1")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plan := planCandidates(addresses, original, C.DomainStrategyAsIS)
		if len(plan.candidates) == 0 {
			b.Fatal("empty plan")
		}
	}
}

// BenchmarkSchedulerSingleCandidate is the hot path: it must not spawn anything.
func BenchmarkSchedulerSingleCandidate(b *testing.B) {
	scheduler := &candidateScheduler{fallbackDelay: time.Millisecond}
	plan := planCandidates([]netip.Addr{netip.MustParseAddr("192.0.2.1")}, netip.Addr{}, C.DomainStrategyPreferIPv4)
	conn := &countingConn{}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		held, _, err := scheduler.dial(ctx, plan, func(context.Context, netip.Addr) (net.Conn, error) {
			return conn, nil
		})
		if err != nil || held == nil {
			b.Fatal("dial failed")
		}
	}
}

// BenchmarkSchedulerDualStackPrimaryWins measures the racing path when the preferred family
// answers first.
func BenchmarkSchedulerDualStackPrimaryWins(b *testing.B) {
	scheduler := &candidateScheduler{fallbackDelay: 50 * time.Millisecond}
	plan := planCandidates([]netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.0.2.1"),
	}, netip.Addr{}, C.DomainStrategyPreferIPv6)
	conn := &countingConn{}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		held, _, err := scheduler.dial(ctx, plan, func(context.Context, netip.Addr) (net.Conn, error) {
			return conn, nil
		})
		if err != nil || held == nil {
			b.Fatal("dial failed")
		}
	}
}
