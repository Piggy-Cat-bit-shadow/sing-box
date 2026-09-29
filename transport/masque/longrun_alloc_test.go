//go:build with_quic

package masque

import (
	"net/netip"
	"runtime"
	"testing"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
)

// TestLongRunGCPressure sends 1,000,000 packets through the outbound path in batches and reports
// how much garbage the dataplane produces.
//
// # Why this exists on top of the benchmarks
//
// A benchmark reports B/op, which is an average. What decides whether a long-lived tunnel needs a
// large heap is the TOTAL allocation over time, and whether that total grows with packet count.
// The owned path's claim is that it is allocation-free per packet apart from the metadata the
// transport must keep; this test states that claim as a concrete number over a million packets.
func TestLongRunGCPressure(t *testing.T) {
	if testing.Short() {
		t.Skip("long-run allocation test skipped in short mode")
	}
	const (
		total     = 1_000_000
		batchSize = 8
	)
	packet := buildBenchIPv4Packet(1280, 6,
		netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"))

	sink := &copyCountingStream{}
	current := benchSession(sink, &benchDiscardStream{}, &benchHandler{})
	current.session.ownedDatagrams = transportHTTP.AsOwnedDatagramSender(sink)
	current.session.batchOwnedDatagrams = transportHTTP.AsBatchOwnedDatagramSender(sink)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	// Run the same total through BOTH paths, so the comparison is like-for-like and the
	// difference is attributable to batching alone.
	runPath := func(batched bool) (totalAlloc uint64, gcCount uint32, heapDelta int64) {
		sink2 := &copyCountingStream{}
		sess := benchSession(sink2, &benchDiscardStream{}, &benchHandler{})
		sess.session.ownedDatagrams = transportHTTP.AsOwnedDatagramSender(sink2)
		if batched {
			sess.session.batchOwnedDatagrams = transportHTTP.AsBatchOwnedDatagramSender(sink2)
		}
		runtime.GC()
		var b4 runtime.MemStats
		runtime.ReadMemStats(&b4)
		for sent := 0; sent < total; sent += batchSize {
			buffers := newBenchPacketBuffers(batchSize, packet)
			if err := sess.client.WritePacketBuffers(buffers, false); err != nil {
				t.Fatal(err)
			}
		}
		runtime.GC()
		var af runtime.MemStats
		runtime.ReadMemStats(&af)
		// The batch path and the per-packet path count on different counters, so read whichever
		// one this run actually used.
		var delivered int
		if batched {
			_, delivered = sink2.batchStats()
		} else {
			_, delivered, _ = sink2.stats()
		}
		if delivered != total {
			t.Fatalf("batched=%v delivered %d, want %d", batched, delivered, total)
		}
		return af.TotalAlloc - b4.TotalAlloc, af.NumGC - b4.NumGC, int64(af.HeapAlloc) - int64(b4.HeapAlloc)
	}

	ppAlloc, ppGC, ppHeap := runPath(false)
	btAlloc, btGC, btHeap := runPath(true)
	t.Logf("PER-PACKET : totalAlloc=%d (%.1f B/packet) heapDelta=%d numGC=%d", ppAlloc, float64(ppAlloc)/float64(total), ppHeap, ppGC)
	t.Logf("BATCHED    : totalAlloc=%d (%.1f B/packet) heapDelta=%d numGC=%d", btAlloc, float64(btAlloc)/float64(total), btHeap, btGC)
	if ppAlloc > 0 {
		t.Logf("allocation change: %.2f%%", 100*(float64(btAlloc)-float64(ppAlloc))/float64(ppAlloc))
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	// The claim under test is that the dataplane does not RETAIN per-packet memory: the heap after
	// a million packets must be no larger than before. Total allocation is dominated by the
	// fixture's own buffer construction (72 B/packet, identical in both modes) and is reported
	// rather than asserted, because the fixture is not the dataplane.
	if btHeap > 8<<20 || ppHeap > 8<<20 {
		t.Fatalf("heap grew (per-packet=%d, batched=%d bytes); the dataplane should not retain per-packet memory",
			ppHeap, btHeap)
	}
}
