package physicalpath

// The allocation and contention measurement for SnapshotStatus.
//
// Two questions are asked here, and they are different:
//
//	allocations   a read-only diagnostic that is called from a control-plane read path must not
//	              allocate per hop beyond the report it returns. A containment added for the panic
//	              policy, or a status query added for the teardown rule, must not turn into a per-hop
//	              heap allocation - that is the kind of cost that is invisible in a test and obvious in
//	              a profile.
//	contention    the view used to hold a mutex across the WHOLE snapshot, so N concurrent snapshots
//	              of one view serialised. The parallel benchmark is what makes that measurable, and it
//	              is the number that has to move when the lock is removed.

import (
	"testing"

	N "github.com/sagernet/sing/common/network"
)

// benchmarkResolver is the fixture both benchmarks drive: two hops in a chain, the outer one carrying
// every reporter capability this package declares.
func benchmarkResolver() (*Resolver, *StatusView) {
	exit := &reportingLeaf{
		testLeaf:           *dualLeaf("exit"),
		reportsState:       true,
		state:              LifecycleStateReady,
		reportsGenerations: true,
	}
	entry := &reportingLeaf{
		testLeaf:               *dualLeaf("entry", "exit"),
		reportsState:           true,
		state:                  LifecycleStateReady,
		reportsError:           true,
		lastError:              errTest("dial tcp 10.0.0.1:443: connect: connection refused"),
		errorPhase:             PhaseConnect,
		reportsGenerations:     true,
		publishesMTU:           1408,
		publishesEncapOverhead: true,
		encapOverhead:          32,
	}
	registry := newReportingRegistry(exit, entry)
	return registry.resolver(), NewStatusView()
}

// BenchmarkSnapshotStatus reports B/op and allocs/op for one snapshot of a two-hop path.
func BenchmarkSnapshotStatus(b *testing.B) {
	resolver, view := benchmarkResolver()
	root := TagOrOutbound{Tag: "entry"}
	options := Options{Network: N.NetworkTCP}

	// The fixture has to be able to fail: a benchmark of a call that returns nothing measures the
	// return, not the work.
	if status := view.SnapshotStatus(resolver, root, options); len(status.Hops) != 2 || status.HasUnknown() {
		b.Fatalf("the benchmark fixture must produce a two-hop path; it produced %d hops, unknowns %v",
			len(status.Hops), status.Unknowns)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		status := view.SnapshotStatus(resolver, root, options)
		if len(status.Hops) != 2 {
			b.Fatalf("a snapshot returned %d hops, want 2", len(status.Hops))
		}
	}
}

// BenchmarkSnapshotStatusParallel is the contention measurement: the SAME view, driven from several
// goroutines. It is the number the walk lock used to serialise.
func BenchmarkSnapshotStatusParallel(b *testing.B) {
	resolver, view := benchmarkResolver()
	root := TagOrOutbound{Tag: "entry"}
	options := Options{Network: N.NetworkTCP}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(probe *testing.PB) {
		for probe.Next() {
			status := view.SnapshotStatus(resolver, root, options)
			if len(status.Hops) != 2 {
				b.Fatalf("a snapshot returned %d hops, want 2", len(status.Hops))
			}
		}
	})
}
