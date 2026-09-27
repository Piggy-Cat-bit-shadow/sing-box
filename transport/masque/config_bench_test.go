package masque

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
)

// Benchmarks for the configuration read on the packet hot path.
//
// # The pattern under test
//
// session configuration is written RARELY - only when an ADDRESS_ASSIGN or
// ROUTE_ADVERTISEMENT capsule arrives - and read on EVERY packet:
//
//	// TX, once per packet batch
//	current.access.Lock()
//	configuration := current.configuration
//	ready := current.ready
//	current.access.Unlock()
//
//	// RX, once per received packet
//	s.access.Lock()
//	configuration := s.configuration
//	s.access.Unlock()
//
// That is the textbook "read very often, write rarely" shape, so the question is
// whether a mutex on it costs anything measurable. These benchmarks answer that
// before any change is made to it, because the alternative (an immutable snapshot
// behind atomic.Pointer) is more code and is only worth it if the contention is
// real.
//
// # Why both a single-goroutine and a contended benchmark
//
// An uncontended sync.Mutex is a single atomic CAS on the fast path, which is a
// few nanoseconds and may well be noise next to the packet parsing that surrounds
// it. Uncontended benchmarks therefore cannot justify the change on their own.
// The contended ones model the case that could: the ingress loop reading
// configuration concurrently with the control path, or several flows writing
// packets at once, which is when a mutex turns into futex traffic.

// configReader models the session's access to the configuration field. It is a
// separate type so the benchmark measures the SYNCHRONISATION and not the whole
// session, which would swamp the difference the same way the per-iteration
// ingress benchmark originally did.
type configReader struct {
	access        sync.Mutex
	configuration Configuration
	ready         bool
}

// BenchmarkSessionConfigReadUncontended measures the mutex read on one goroutine.
func BenchmarkSessionConfigReadUncontended(b *testing.B) {
	reader := &configReader{
		configuration: Configuration{
			Address:          []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
			Routes:           []AddressRange{{Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.255.255.255")}},
			RoutesAdvertised: true,
		},
		ready: true,
	}
	sink := 0
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		local := 0
		for pb.Next() {
			reader.access.Lock()
			configuration := reader.configuration
			//nolint:staticcheck // the read is the point of the benchmark
			local += len(configuration.Address)
			reader.access.Unlock()
		}
		sink += local
	})
	_ = sink
}

// BenchmarkSessionConfigSnapshotRead measures the same read through an immutable
// snapshot behind an atomic pointer, which is the proposed replacement.
func BenchmarkSessionConfigSnapshotRead(b *testing.B) {
	snapshot := &configSnapshot{
		address:          []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
		routes:           []AddressRange{{Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.255.255.255")}},
		routesAdvertised: true,
		ready:            true,
	}
	var holder configSnapshotHolder
	holder.state.Store(snapshot)
	sink := 0
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		local := 0
		for pb.Next() {
			current := holder.state.Load()
			local += len(current.address)
		}
		sink += local
	})
	_ = sink
}

// configSnapshot is the immutable published state. Every field is read-only after
// publication, and the slices are never mutated in place: a new snapshot is built
// and swapped in.
type configSnapshot struct {
	address          []netip.Prefix
	routes           []AddressRange
	routesAdvertised bool
	ready            bool
}

type configSnapshotHolder struct {
	state atomic.Pointer[configSnapshot]
}

// BenchmarkSessionConfigReadContended pits readers against a writer, which is the
// shape that turns an uncontended mutex into a contended one.
func BenchmarkSessionConfigReadContended(b *testing.B) {
	reader := &configReader{
		configuration: Configuration{Address: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}},
		ready:         true,
	}
	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Model the control path publishing a configuration update, which in
			// production happens on an ADDRESS_ASSIGN or ROUTE_ADVERTISEMENT
			// capsule rather than per packet.
			reader.access.Lock()
			reader.ready = !reader.ready
			reader.access.Unlock()
		}
	}()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reader.access.Lock()
			configuration := reader.configuration
			//nolint:staticcheck // the read is the point of the benchmark
			_ = configuration
			reader.access.Unlock()
		}
	})
	close(stop)
	writer.Wait()
}
