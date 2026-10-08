package bufgeom

import (
	"net"
	"runtime"
	"testing"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// TestGeometryReport states which geometry this binary was built with.
//
// It asserts nothing about which one SHOULD have been chosen; it exists so that a benchmark
// table can be labelled with the constants that produced it. A performance number whose
// geometry is only known from the command line is one shell-history loss away from being
// uninterpretable, and the two geometries differ by exactly 2x in every buffer.
func TestGeometryReport(t *testing.T) {
	t.Logf("HOST GEOMETRY: buf.BufferSize=%d buf.UDPBufferSize=%d buf.MaxPooledBufferSize=%d common.LowMemory=%v",
		buf.BufferSize, buf.UDPBufferSize, buf.MaxPooledBufferSize, common.LowMemory)
}

// TestGeometryIsOneOfTheShippedValues pins the tag-to-constant relation.
//
// with_low_memory is not itself a constant anything can read; the only observable effect is
// these numbers. If a future edit changes what the tag selects - or changes the default - the
// label a benchmark carries becomes a lie unless this fails. The set is closed to the two
// geometries the fork defines, so a third value is a decision that has to be made deliberately
// rather than acquired by accident.
func TestGeometryIsOneOfTheShippedValues(t *testing.T) {
	switch buf.BufferSize {
	case 32 * 1024:
		if common.LowMemory {
			t.Fatalf("default geometry (BufferSize=%d) built with common.LowMemory=true: the tag "+
				"selects both, so the fork's build-tag files have diverged", buf.BufferSize)
		}
	case 16 * 1024:
		if !common.LowMemory {
			t.Fatalf("low-memory geometry (BufferSize=%d) built with common.LowMemory=false: the tag "+
				"selects both, so the fork's build-tag files have diverged", buf.BufferSize)
		}
	default:
		t.Fatalf("buf.BufferSize=%d is neither shipped geometry; every benchmark label in this "+
			"package is derived from that assumption", buf.BufferSize)
	}
	if buf.UDPBufferSize*2 != buf.BufferSize {
		t.Fatalf("UDPBufferSize=%d is not half of BufferSize=%d: the two geometries no longer move "+
			"together, so a table indexed by one does not describe the other",
			buf.UDPBufferSize, buf.BufferSize)
	}
}

// TestGeometryBuffersAreExactlyPoolable is the property that decides whether the geometry is a
// memory saving or a memory DISASTER.
//
// The pooled allocator only accepts a slice back when its capacity is exactly a power of two in
// [64, 65536] (or MaxPooledBufferSize). A BufferSize that is not one of those makes every
// allocator.Put return an error and every buffer a fresh heap allocation, so a smaller nominal
// buffer could allocate MORE total bytes than a larger pooled one. The test drives the real
// allocator rather than re-deriving the rule, because the rule lives in a dependency.
func TestGeometryBuffersAreExactlyPoolable(t *testing.T) {
	for _, size := range []int{buf.BufferSize, buf.UDPBufferSize} {
		data := buf.Get(size)
		if data == nil {
			t.Fatalf("buf.Get(%d) returned nil: the geometry is above the pooled ceiling (%d) and "+
				"every buffer is a fresh allocation", size, buf.MaxPooledBufferSize)
		}
		if cap(data) != size {
			t.Fatalf("buf.Get(%d) returned capacity %d: the allocator rounds to a size class, so a "+
				"Put of the exact buffer would be rejected and the buffer dropped on the floor",
				size, cap(data))
		}
		if err := buf.Put(data); err != nil {
			t.Fatalf("buf.Put of a %d-byte pooled buffer failed: %v", size, err)
		}
	}
}

// TestBufferAcquireNeverReallocatesThePayload is the assertion that the geometry stays POOLED,
// measured rather than inferred.
//
// # Why this is not an AllocsPerRun == 0 test
//
// The obvious assertion - "acquiring and releasing a buffer allocates zero times" - is not stable,
// and the reason is worth recording because it looks like a passing test either way. buf.New()
// returns &buf.Buffer{...}; whether that header is stack-allocated depends on whether the compiler
// inlines Release at that particular call site. Measured in this tree, the SAME code reports 0.00
// allocations per run when the closure is inlined into the test function and 1.00 (64 B) when it
// is compiled as a helper. An assertion of 0 therefore passes or fails on an inlining decision,
// and a future Go release could flip it without anything about buffers changing.
//
// So the contract is stated the way it is actually true: the pooled DATA is never reallocated.
// That is measured as bytes rather than as a count, because a reallocated payload costs
// BufferSize bytes per acquire whatever the inlining does. The bound is far below the smallest
// shipped geometry (UDPBufferSize 8192), so it cannot be satisfied by a geometry that stopped
// pooling - while the 64-byte header, if it is heap-allocated at all, fits under it comfortably.
func TestBufferAcquireNeverReallocatesThePayload(t *testing.T) {
	const acquires = 20000

	bytesPerAcquire := func(f func()) float64 {
		runtime.GC()
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		for range acquires {
			f()
		}
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		return float64(after.TotalAlloc-before.TotalAlloc) / float64(acquires)
	}

	streamBytes := bytesPerAcquire(func() {
		buffer := buf.New()
		buffer.Release()
	})
	packetBytes := bytesPerAcquire(func() {
		buffer := buf.NewPacket()
		buffer.Release()
	})
	// The data path on its own, with no Buffer header in the picture at all.
	dataBytes := bytesPerAcquire(func() {
		data := buf.Get(buf.BufferSize)
		_ = buf.Put(data)
	})

	// Reported, not asserted: this is the inlining-sensitive figure described above, and it is
	// recorded so the two instruments can be compared rather than one being trusted blindly.
	headerAllocs := testing.AllocsPerRun(1000, func() {
		buffer := buf.New()
		buffer.Release()
	})

	t.Logf("HOST POOLING: geometry BufferSize=%d UDPBufferSize=%d; bytes/acquire "+
		"stream=%.2f packet=%.2f data-only=%.2f (all must be far below %d); "+
		"New+Release allocs/acquire=%.2f (inlining-dependent, informational)",
		buf.BufferSize, buf.UDPBufferSize, streamBytes, packetBytes, dataBytes,
		buf.UDPBufferSize, headerAllocs)

	// Under -race the figures above are the detector's shadow memory, not the program's, so the
	// ceiling below is not asserted. The structural contract in
	// TestGeometryBuffersAreExactlyPoolable still runs under both builds, so a geometry that
	// stopped being poolable cannot pass this file just because it was instrumented. See the
	// race-tagged file for the measured size of the instrument.
	if raceDetectorEnabled {
		t.Log("built with -race: the byte ceiling is reported above but NOT asserted, because the " +
			"race detector's shadow memory is counted in TotalAlloc and dwarfs the payload")
		return
	}

	const payloadFreeCeiling = 1024
	for name, measured := range map[string]float64{
		"stream buffer (buf.New/Release)": streamBytes,
		"packet buffer (buf.NewPacket)":   packetBytes,
		"pooled data (buf.Get/Put)":       dataBytes,
	} {
		if measured >= payloadFreeCeiling {
			t.Fatalf("%s averaged %.0f bytes per acquire, at or above the %d-byte ceiling that "+
				"separates a pooled header from a reallocated payload (BufferSize=%d, "+
				"UDPBufferSize=%d): the geometry has stopped being pooled and every acquire is now a "+
				"fresh allocation of the whole buffer",
				name, measured, payloadFreeCeiling, buf.BufferSize, buf.UDPBufferSize)
		}
	}
}

// TestSteadyFlowHeapFootprint measures the LIVE heap held by the steady-state buffers of N
// concurrent flows, which is the quantity the Android decision is actually about.
//
// # Why it holds buffers rather than copying bytes
//
// A throughput benchmark measures the allocator's churn; this measures what stays resident. The
// two are different questions and the second is the one a memory budget is spent on. Each active
// stream flow holds one buffer per direction while a read is outstanding, so the model here is
// two buffers per flow - the same two the copy loop would hand to the two directions.
//
// The measurement is a GC-observed heap delta, not an accounting estimate: the buffers are
// allocated from the real pool, kept reachable, and the runtime is asked what is live. Nothing
// is read from a constant, so a change in how buffers are pooled moves this number.
func TestSteadyFlowHeapFootprint(t *testing.T) {
	const buffersPerFlow = 2

	for _, flows := range []int{32, 128, 512} {
		held := make([]*buf.Buffer, 0, flows*buffersPerFlow)

		// Warm the pool before the baseline so the delta measures the RETAINED working set and
		// not the first-touch allocation of pool buckets.
		warm := make([]*buf.Buffer, 0, flows*buffersPerFlow)
		for range flows * buffersPerFlow {
			warm = append(warm, buf.New())
		}
		for _, buffer := range warm {
			buffer.Release()
		}
		warm = nil

		runtime.GC()
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		for range flows * buffersPerFlow {
			held = append(held, buf.New())
		}

		runtime.GC()
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)

		heapDelta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
		perFlow := float64(heapDelta) / float64(flows)
		t.Logf("HOST HEAP: geometry BufferSize=%d flows=%d heap-delta=%d bytes (%.1f KiB) "+
			"per-flow=%.0f bytes (%.1f KiB) theoretical-per-flow=%d bytes",
			buf.BufferSize, flows, heapDelta, float64(heapDelta)/1024,
			perFlow, perFlow/1024, buf.BufferSize*buffersPerFlow)

		for _, buffer := range held {
			buffer.Release()
		}
		held = nil
		runtime.GC()
	}
}

// TestSocketPathsDoNotConsultCommonLowMemory documents the confound the socket benchmarks rely
// on being absent.
//
// with_low_memory turns on common.LowMemory, which changes which copy loop copyExtended enters -
// but only when the read waiter reports that it needs a copy. A real socket's waiter reports
// needCopy=false, so the socket benchmarks in this package measure the buffer size and nothing
// else. If a dependency change ever makes a socket waiter report true, the TCP and UDP
// throughput numbers stop isolating the geometry and this fails instead of the report quietly
// becoming wrong.
func TestSocketPathsDoNotConsultCommonLowMemory(t *testing.T) {
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := server.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	serverSide := <-accepted
	defer serverSide.Close()

	readWaiter, isReadWaiter := bufio.CreateReadWaiter(client)
	if !isReadWaiter {
		t.Skip("the stream reader exposes no read waiter on this platform; the copy loop takes the " +
			"pooled buffer path unconditionally, so the confound cannot arise")
	}
	needCopy := readWaiter.InitializeReadWaiter(N.NewReadWaitOptions(client, serverSide))
	t.Logf("HOST PATH: geometry LowMemory=%v socket read waiter needCopy=%v", common.LowMemory, needCopy)
	if needCopy {
		t.Fatalf("a real TCP socket now reports needCopy=true, so copyExtended consults "+
			"common.LowMemory on the socket path and this package's socket benchmarks no longer "+
			"isolate the buffer geometry (LowMemory=%v)", common.LowMemory)
	}
}
