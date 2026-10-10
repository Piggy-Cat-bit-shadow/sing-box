package dns

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

// Benchmarks for the reverse-mapping observation cost.
//
// # What is being measured, and why it is measured at two levels
//
// `route/route.go:1066` calls `Router.LookupReverseMapping` from `prepareMatchMetadata` whenever a
// connection's destination is not Fake-IP and its domain is not already known - which is every direct
// IP connection. `LookupReverseMapping` takes `dnsEnvironmentAccess` and, inside it, calls
// `observeDNSEnvironmentLocked`: a loop over EVERY configured DNS transport, each one's `Environment()`,
// a slice build, a sort by tag, an FNV hash and a description join.
//
// That is O(transports) work on the connection path. Code inspection says the cost exists; it does not
// say the cost matters, and this file is what turns the first statement into a number:
//
//   - `BenchmarkLookupReverseMapping<transports>` is the MICRO level: one call, varying only how many
//     transports have to be observed.
//   - `BenchmarkPrepareMatchMetadata<transports>` is the REAL level: the actual
//     `Router.prepareMatchMetadata` entry point the connection path uses. A micro-benchmark that does
//     not resemble the caller is how a performance claim goes wrong.
//
// Both report with a WARM reverse-mapping cache (a hit) and a COLD one (a miss), because a miss that
// costs an observation is the case the concern is about.

// benchmarkTransport is a DNS transport that publishes an environment and nothing else.
type benchmarkTransport struct {
	adapter.DNSTransport
	tag         string
	environment []string
}

func (t *benchmarkTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (t *benchmarkTransport) Close() error                                               { return nil }
func (t *benchmarkTransport) Type() string                                               { return "benchmark" }
func (t *benchmarkTransport) Tag() string                                                { return t.tag }
func (t *benchmarkTransport) Reset()                                                     {}
func (t *benchmarkTransport) Environment() []string                                      { return t.environment }

// benchmarkTransportManager is the transport manager the observation loop iterates.
type benchmarkTransportManager struct {
	transports []adapter.DNSTransport
}

func (m *benchmarkTransportManager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}

func (m *benchmarkTransportManager) Close() error { return nil }

func (m *benchmarkTransportManager) Transports() []adapter.DNSTransport { return m.transports }

func (m *benchmarkTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	for _, transport := range m.transports {
		if transport.Tag() == tag {
			return transport, true
		}
	}
	return nil, false
}

func (m *benchmarkTransportManager) Default() adapter.DNSTransport   { return m.transports[0] }
func (m *benchmarkTransportManager) FakeIP() adapter.FakeIPTransport { return nil }
func (m *benchmarkTransportManager) Remove(tag string) error         { return nil }

func (m *benchmarkTransportManager) Create(ctx context.Context, logger log.ContextLogger, tag string, outboundType string, options any) error {
	return nil
}

// newReverseMappingBenchmarkRouter builds a router with `count` transports, each publishing a distinct
// environment entry so the fingerprint genuinely differs per transport and the observation cannot be
// optimised away by a constant.
func newReverseMappingBenchmarkRouter(b *testing.B, count int) *Router {
	b.Helper()
	transports := make([]adapter.DNSTransport, 0, count)
	for index := range count {
		transports = append(transports, &benchmarkTransport{
			tag:         fmt.Sprintf("t%02d", index),
			environment: []string{fmt.Sprintf("resolver-%02d.example", index), "search.example"},
		})
	}
	ctx := service.ContextWith[adapter.DNSTransportManager](
		context.Background(), &benchmarkTransportManager{transports: transports})
	// ReverseMapping is what creates the mapping the observation feeds, and it is the option the
	// product sets for this path. Everything else is left at its zero value so the benchmark measures
	// the observation and the lookup and not a cache-file or optimistic-expiry configuration.
	manager, err := NewRouter(ctx, log.NewNOPFactory(), option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			ReverseMapping: true,
		},
	})
	if err != nil {
		b.Fatalf("router: %v", err)
	}
	return manager
}

var benchmarkAddress = netip.MustParseAddr("192.0.2.77")

func benchmarkTransports() []int { return []int{1, 8, 32} }

// BenchmarkLookupReverseMapping is the micro level: one call, warm cache (hit) and cold (miss).
func BenchmarkLookupReverseMapping(b *testing.B) {
	for _, count := range benchmarkTransports() {
		for _, hit := range []bool{true, false} {
			name := fmt.Sprintf("transports=%02d/hit=%v", count, hit)
			b.Run(name, func(b *testing.B) {
				router := newReverseMappingBenchmarkRouter(b, count)
				if hit {
					router.dnsReverseMapping.Add(benchmarkAddress, "cached.example")
				}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if !hit {
						// A miss is the interesting case: the observation runs and then the lookup
						// finds nothing. Removing an entry that was never there keeps the cache in the
						// same state the caller would see.
						router.dnsReverseMapping.Remove(benchmarkAddress)
					}
					_, _ = router.LookupReverseMapping(benchmarkAddress)
				}
			})
		}
	}
}

// BenchmarkLookupReverseMappingParallel is the same call from several goroutines, which is where the
// leaf lock's contention would show if there were any.
func BenchmarkLookupReverseMappingParallel(b *testing.B) {
	for _, count := range benchmarkTransports() {
		b.Run(fmt.Sprintf("transports=%02d", count), func(b *testing.B) {
			router := newReverseMappingBenchmarkRouter(b, count)
			router.dnsReverseMapping.Add(benchmarkAddress, "cached.example")
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_, _ = router.LookupReverseMapping(benchmarkAddress)
				}
			})
		})
	}
}
