// Package bufgeom measures the buffer geometry a binary was built with, and what that
// geometry costs and buys on the real copy paths.
//
// # What "geometry" means here
//
// with_low_memory is not a memory limit and not a switch on a data structure. It selects a
// different set of compile-time constants in github.com/sagernet/sing/common/buf:
//
//	default            BufferSize 32 KiB   UDPBufferSize 16 KiB
//	with_low_memory    BufferSize 16 KiB   UDPBufferSize  8 KiB
//
// Every steady-state buffer on the data path is sized from one of those two numbers, because
// ReadWaitOptions.NewBuffer starts at buf.BufferSize and NewPacketBuffer starts at
// buf.UDPBufferSize. So halving them halves the per-flow working set and, at the same time,
// halves the payload each read syscall can carry - which is why the tag cannot be adopted on
// the strength of the memory number alone.
//
// The tag also flips github.com/sagernet/sing/common.LowMemory, which changes which copy loop
// copyExtended enters when a source exposes a read waiter AND that waiter needs a copy. A plain
// TCP or UDP socket exposes one whose InitializeReadWaiter reports needCopy=false, so the
// socket paths take copyWaitWithPool in BOTH geometries and this package's socket benchmarks
// therefore isolate the buffer size. The confound is real for other sources and is called out
// in the report rather than hidden.
//
// # Why this is a package of its own
//
// The geometry is a property of the WHOLE binary, not of the Shadowsocks writer that first
// exposed it. protocol/shadowsocks already carries the decision benchmarks for its own MTU
// boundary, and memmatrix drives those. What was missing is the cross-cutting measurement:
// heap per concurrent flow, allocations per buffer, and real-socket TCP/UDP throughput and
// latency under each geometry. Putting it here keeps it usable by any package that needs to
// know what geometry it is running under, without those packages importing each other.
//
// # What these numbers are, and what they are not
//
// Every figure this package produces is a HOST BENCHMARK: it is measured on the machine running
// `go test`, over the loopback interface, in the Go process under test. It is NOT a device
// measurement, NOT a battery measurement, and NOT a statement about any handset's memory
// pressure or thermal envelope. Loopback has no radio, no modem, no kernel network stack of a
// phone, and no other process competing for the CPU. The absolute MB/s figures are therefore
// bounded by this host and are not portable.
//
// What IS portable is the RATIO between the two geometries, because both are measured on the
// same host, in the same process, with only the constants differing - and the heap arithmetic,
// which follows from the constants rather than from the machine.
//
// # Running it
//
// Both geometries are separate builds, so each is a separate invocation:
//
//	TAGS=$(cat release/DEFAULT_BUILD_TAGS)
//	go test -tags "$TAGS"                  -run 'TestGeometry|TestBufferAcquire|TestSteadyFlow|TestSocketPaths|TestSustainedCopy' -v ./common/bufgeom
//	go test -tags "$TAGS,with_low_memory"  -run 'TestGeometry|TestBufferAcquire|TestSteadyFlow|TestSocketPaths|TestSustainedCopy' -v ./common/bufgeom
//
//	go test -tags "$TAGS"                  -run '^$' -bench 'TCPCopyThroughput|FirstByteLatency' -benchtime 300x -count 5 -benchmem ./common/bufgeom
//	go test -tags "$TAGS"                  -run '^$' -bench 'UDPCopyThroughput'                -benchtime 150x -count 5 -benchmem ./common/bufgeom
//	go test -tags "$TAGS"                  -run '^$' -bench 'BufferAcquireRelease'            -benchtime 3000000x -count 5 -benchmem ./common/bufgeom
//	go test -tags "$TAGS"                  -run '^$' -bench 'ConcurrentTCPCopy'               -benchtime 2x -count 3 -benchmem ./common/bufgeom
//
// (and the same four with -tags "$TAGS,with_low_memory")
//
// # Why the benchmark time is an ITERATION COUNT, not a duration
//
// Most stream benchmarks here open a fresh loopback connection per iteration, because bufio.Copy
// runs until EOF and cannot be restarted on the same connection. Time-based -benchtime therefore
// creates connections as fast as the loop can run - measured at roughly 14000 per second - and
// loopback has on the order of 16000 ephemeral ports with a 15-second TIME_WAIT. A duration-based
// run exhausts them partway through and every subsequent iteration fails with
// "connect: can't assign requested address", which looks like a network problem and is really an
// accounting one. An iteration count keeps the number of connections bounded and known.
//
// The test names carry the geometry, so the two raw outputs cannot be mixed up after the fact.
// The benchmark names do not, which is why the report must record the command line next to the
// table.
package bufgeom
