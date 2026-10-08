package bufgeom

import (
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// countingSink is the destination of every stream benchmark: it accepts the bytes the copy loop
// hands over and counts them, and nothing else.
//
// It deliberately does NOT implement the extended capability interfaces. A destination that did
// would move the measurement onto a different copy loop, and the point of these benchmarks is the
// loop that ships for an ordinary outbound - buffer in, plain Write out.
type countingSink struct {
	bytes atomic.Int64
}

func (s *countingSink) Write(p []byte) (int, error) {
	s.bytes.Add(int64(len(p)))
	return len(p), nil
}

// observingSink is countingSink plus the extended capability, so the copy loop performs its real
// WriteBuffer hand-off and this fixture can record WHAT it handed over - how many buffers and how
// large the largest was.
//
// # Why the capacity is the number that matters
//
// The throughput of a bulk transfer is bounded below by how many times the loop must go around, and
// that is decided by the buffer capacity, not by the geometry constants directly. Recording the
// capacity turns "bulk transfers should be geometry-independent because copyExtended grows the
// buffer" from an argument about dependency source into a measurement about this binary: if the
// largest buffer for an 8 MiB transfer is the same constant in both geometries, then the only
// remaining difference for those bytes is the first 512 KiB.
type observingSink struct {
	countingSink
	writes atomic.Int64
	maxCap atomic.Int64
}

func (s *observingSink) WriteBuffer(buffer *buf.Buffer) error {
	s.writes.Add(1)
	capacity := int64(buffer.Cap())
	for {
		previous := s.maxCap.Load()
		if capacity <= previous || s.maxCap.CompareAndSwap(previous, capacity) {
			break
		}
	}
	s.bytes.Add(int64(buffer.Len()))
	buffer.Release()
	return nil
}

// tuneTCP removes the two kernel behaviours that would otherwise dominate a loopback measurement.
//
// Nagle would coalesce small writes and make the latency benchmark measure the timer instead of
// the path. The default socket buffers are small enough that the sender blocks on window
// availability rather than on the receiver, which would make every geometry look identical for a
// reason that has nothing to do with buffers. Both ends are widened so the copy loop is the
// bottleneck being measured.
func tuneTCP(tb testing.TB, conn net.Conn, socketBuffer int) {
	tb.Helper()
	tcpConn, isTCP := conn.(*net.TCPConn)
	if !isTCP {
		return
	}
	_ = tcpConn.SetNoDelay(true)
	if socketBuffer > 0 {
		_ = tcpConn.SetReadBuffer(socketBuffer)
		_ = tcpConn.SetWriteBuffer(socketBuffer)
	}
}

// tcpPairs returns count connected loopback pairs from ONE listener.
//
// # Why not tcpPair in a loop
//
// Creating a listener per flow means an accept goroutine per listener, and at 512 flows the
// scheduler does not always run them fast enough: new connects then wait in a SYN queue that is
// not being drained and fail with "connect: operation timed out", which is a property of the test
// fixture rather than of any datapath. One listener with a single sequential accept loop drains
// the queue for every connection.
func tcpPairs(tb testing.TB, count, socketBuffer int) (clients, servers []net.Conn) {
	tb.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, count)
	go func() {
		for range count {
			conn, acceptErr := listener.Accept()
			accepted <- acceptResult{conn, acceptErr}
			if acceptErr != nil {
				return
			}
		}
	}()

	clients = make([]net.Conn, count)
	for index := range count {
		client, dialErr := net.Dial("tcp", listener.Addr().String())
		if dialErr != nil {
			tb.Fatalf("dial %d of %d: %v", index, count, dialErr)
		}
		tuneTCP(tb, client, socketBuffer)
		clients[index] = client
	}
	for range count {
		result := <-accepted
		if result.err != nil {
			tb.Fatalf("accept: %v", result.err)
		}
		tuneTCP(tb, result.conn, socketBuffer)
		servers = append(servers, result.conn)
	}
	return clients, servers
}

// loopbackSocketBuffer is the per-socket kernel buffer the single-flow benchmarks request.
//
// # Why the concurrency benchmark requests NONE
//
// A kernel socket buffer is per socket, not per process: 512 flows at 4 MiB each direction is
// some 8 GiB of mbuf requests, and the host refuses the connection with "no buffer space
// available" long before the flows are interesting. The concurrency benchmark therefore runs on
// the system defaults, where the aggregate is CPU-bound anyway - which is the axis it is there to
// measure. Making it run at all is worth more than making each individual flow generous.
const loopbackSocketBuffer = 1 << 20

// tcpPair returns the two ends of one loopback TCP connection: the end the copy loop reads from,
// and the end the blaster writes to.
func tcpPair(tb testing.TB, socketBuffer int) (client, server net.Conn) {
	tb.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		accepted <- acceptResult{conn, acceptErr}
	}()

	client, err = net.Dial("tcp", listener.Addr().String())
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	result := <-accepted
	if result.err != nil {
		tb.Fatalf("accept: %v", result.err)
	}
	tuneTCP(tb, client, socketBuffer)
	tuneTCP(tb, result.conn, socketBuffer)
	return client, result.conn
}

// closeTCP tears a benchmark connection down WITHOUT leaving it in TIME_WAIT.
//
// # Why this is not just Close
//
// Every stream benchmark here opens a fresh connection per iteration, because bufio.Copy runs to
// EOF and cannot be restarted. A normal close leaves the initiator in TIME_WAIT for 15 seconds, and
// loopback has on the order of 16000 ephemeral ports: a few thousand iterations exhaust them, and
// the next connection fails with "can't assign requested address". That failure looks like a
// network defect and is really benchmark bookkeeping, and - worse - it degrades the HOST partway
// through a run, so whichever geometry runs second measures a sicker machine. That is exactly the
// confound that made an earlier version of this table report a uniform 2-5x "regression" that
// vanished when the buffer sizes were provably identical.
//
// SO_LINGER with a zero timeout makes close() send RST instead of a FIN, so no TIME_WAIT state is
// created. The payload assertion has already run by the time this is called - every byte the
// benchmark sent has been received and counted - so discarding unsent data cannot hide a short
// read. It only discards the orderly-teardown handshake, which nothing here measures.
func closeTCP(conn net.Conn) {
	if tcpConn, isTCP := conn.(*net.TCPConn); isTCP {
		_ = tcpConn.SetLinger(0)
	}
	_ = conn.Close()
}

// blastTCP writes total bytes and then half-closes, so the copy loop's source reaches EOF exactly
// when the payload is complete.
//
// The half close matters: closing the connection outright can discard what the sender has already
// buffered, which would turn a throughput measurement into a measurement of how much a socket
// tolerates being closed under load.
func blastTCP(conn net.Conn, total int64, chunk []byte, done chan<- error) {
	go func() {
		remaining := total
		for remaining > 0 {
			length := int64(len(chunk))
			if remaining < length {
				length = remaining
			}
			written, err := conn.Write(chunk[:length])
			remaining -= int64(written)
			if err != nil {
				done <- err
				return
			}
		}
		if closeWriter, isCloseWriter := conn.(interface{ CloseWrite() error }); isCloseWriter {
			_ = closeWriter.CloseWrite()
		}
		done <- nil
	}()
}

// ---------------------------------------------------------------------------
// Stream receive path
// ---------------------------------------------------------------------------

// BenchmarkTCPCopyThroughput measures the receive copy loop over a real loopback socket.
//
// # Why there are two regimes
//
// The copy loop does not use buf.BufferSize forever. copyExtended grows the read buffer once
// IncreaseBufferAfter (bufio.DefaultIncreaseBufferAfter, 512000 bytes) has been copied: setting
// options.IncreaseBuffer makes ReadWaitOptions.NewBuffer return 65535 bytes regardless of the
// pooled size. A bulk transfer therefore stops consulting the geometry after its first ~512 KiB.
//
// A benchmark that only ran 64 MiB transfers would report "no difference" for a reason that has
// nothing to do with the geometry: 99.2% of the bytes would have been copied under a size no
// geometry selects. So the pre-growth regime is measured explicitly - it is the regime every SHORT
// flow lives in, and short flows are what a phone runs most of.
//
// # What is being compared
//
// The two geometries run the same source, the same loop and the same destination. Only the
// compile-time buffer size differs, so the MB/s ratio is attributable to it. The absolute MB/s is
// a HOST number over loopback and is not portable to a handset.
func BenchmarkTCPCopyThroughput(b *testing.B) {
	for _, regime := range []struct {
		name  string
		total int64
	}{
		{"pre-growth-256KiB", 256 << 10},
		{"post-growth-4MiB", 4 << 20},
	} {
		b.Run(regime.name, func(b *testing.B) {
			runTCPCopy(b, regime.total)
		})
	}
}

func runTCPCopy(b *testing.B, total int64) {
	chunk := make([]byte, 1<<16)
	b.SetBytes(total)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		client, server := tcpPair(b, loopbackSocketBuffer)
		senderDone := make(chan error, 1)
		blastTCP(server, total, chunk, senderDone)
		sink := &observingSink{}
		b.StartTimer()

		copied, err := bufio.Copy(sink, client)

		b.StopTimer()
		if err != nil {
			b.Fatalf("copy: %v", err)
		}
		if senderErr := <-senderDone; senderErr != nil {
			b.Fatalf("sender: %v", senderErr)
		}
		// A benchmark that runs without error can still have carried nothing. Both counters are
		// checked, so a fixture that silently produces no payload is a failure rather than a very
		// fast, very allocation-light "result".
		if copied != total || sink.bytes.Load() != total {
			b.Fatalf("copy loop reported %d bytes and the destination accepted %d, expected %d: the "+
				"datapath did not carry the payload, so this measurement is invalid",
				copied, sink.bytes.Load(), total)
		}
		closeTCP(client)
		closeTCP(server)
		// The evidence that this measurement is comparable across geometries: how many buffers the
		// loop handed over and how large the largest was. These are the structural facts the
		// throughput number is explained BY, and they belong next to it rather than in prose.
		b.ReportMetric(float64(sink.writes.Load()), "writes/op")
		b.ReportMetric(float64(sink.maxCap.Load()), "max-buffer-cap")
		// b.Loop requires the timer to be RUNNING when the next iteration begins; the setup above
		// stopped it, so it is put back before the loop wraps.
		b.StartTimer()
	}
}

// firstByteSink closes its channel on the first Write the copy loop performs.
type firstByteSink struct {
	once sync.Once
	ch   chan struct{}
}

func (s *firstByteSink) Write(p []byte) (int, error) {
	s.once.Do(func() { close(s.ch) })
	return len(p), nil
}

// BenchmarkTCPFirstByteLatency measures one small request's trip from the sender's Write into the
// copy loop's destination.
//
// # Why first byte rather than a round trip
//
// The copy loop is a stream loop, not a request/response protocol: it runs until EOF and has no
// notion of a reply. What it does have is a latency-visible startup - acquire a buffer, issue a
// read, hand the result to the destination - and that startup is exactly what a user feels on a
// short interactive flow. The measurement therefore covers the whole path the first packet takes,
// including the buffer acquisition, and per-iteration connection setup is excluded by the timer.
func BenchmarkTCPFirstByteLatency(b *testing.B) {
	request := make([]byte, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		client, server := tcpPair(b, loopbackSocketBuffer)
		sink := &firstByteSink{ch: make(chan struct{})}
		copyDone := make(chan struct{})
		go func() {
			_, _ = bufio.Copy(sink, client)
			close(copyDone)
		}()
		b.StartTimer()

		if _, err := server.Write(request); err != nil {
			b.Fatalf("request write: %v", err)
		}
		select {
		case <-sink.ch:
		case <-time.After(10 * time.Second):
			b.Fatal("the copy loop never delivered a byte: the datapath did not execute")
		}

		b.StopTimer()
		closeTCP(client)
		<-copyDone
		closeTCP(server)
		b.StartTimer()
	}
}

// ---------------------------------------------------------------------------
// Concurrent flows
// ---------------------------------------------------------------------------

// BenchmarkConcurrentTCPCopy runs N independent stream flows at once and reports aggregate
// throughput and the allocation churn of holding them.
//
// # Why concurrency is a separate axis
//
// A single flow's throughput says nothing about the memory decision: what a handset runs out of is
// the per-flow working set multiplied by the number of flows. Running the same copy loop at 32, 128
// and 512 concurrent flows exposes both halves of that - whether the smaller buffer costs
// aggregate throughput when the CPU is contended, and how much live heap N flows actually cost.
//
// The 512 case is the largest number this host was measured to sustain reliably; it is a HOST
// figure and is not a claim about what a phone should run.
func BenchmarkConcurrentTCPCopy(b *testing.B) {
	// 256 KiB per flow keeps the 512-flow case inside this host's socket memory: 512 flows at
	// 1 MiB needed more kernel buffers than the host would hand out and failed on the FIXTURE, not
	// on the datapath. The per-flow volume is the same for both geometries, so the comparison is
	// unaffected by the reduction.
	const perFlow = 256 << 10
	for _, flows := range []int{32, 128, 512} {
		b.Run(strconv.Itoa(flows), func(b *testing.B) {
			runConcurrentTCP(b, flows, perFlow)
		})
	}
}

func runConcurrentTCP(b *testing.B, flows int, perFlow int64) {
	chunk := make([]byte, 1<<16)
	total := int64(flows) * perFlow
	b.SetBytes(total)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		type stream struct {
			client net.Conn
			server net.Conn
			done   chan error
		}
		clients, servers := tcpPairs(b, flows, 0)
		streams := make([]stream, 0, flows)
		for index := range flows {
			one := stream{client: clients[index], server: servers[index], done: make(chan error, 1)}
			blastTCP(servers[index], perFlow, chunk, one.done)
			streams = append(streams, one)
		}
		sink := &countingSink{}
		copyErrors := make([]error, flows)
		var waitGroup sync.WaitGroup
		b.StartTimer()

		for index := range streams {
			waitGroup.Add(1)
			go func(index int) {
				defer waitGroup.Done()
				_, copyErrors[index] = bufio.Copy(sink, streams[index].client)
			}(index)
		}
		waitGroup.Wait()

		b.StopTimer()
		for _, one := range streams {
			if senderErr := <-one.done; senderErr != nil {
				b.Fatalf("sender: %v", senderErr)
			}
			closeTCP(one.client)
			closeTCP(one.server)
		}
		for _, copyErr := range copyErrors {
			if copyErr != nil {
				b.Fatalf("copy: %v", copyErr)
			}
		}
		if got := sink.bytes.Load(); got != total {
			b.Fatalf("the %d flows carried %d bytes, expected %d: the datapath did not carry the "+
				"payload, so this measurement is invalid", flows, got, total)
		}
		b.StartTimer()
	}
}

// ---------------------------------------------------------------------------
// Datagram receive path
// ---------------------------------------------------------------------------

// packetSink counts datagrams and closes complete once the expected number has arrived.
type packetSink struct {
	expected int64
	packets  atomic.Int64
	bytes    atomic.Int64
	batches  atomic.Int64
	once     sync.Once
	complete chan struct{}
}

func (s *packetSink) account(length int) {
	s.bytes.Add(int64(length))
	if s.packets.Add(1) >= s.expected {
		s.once.Do(func() { close(s.complete) })
	}
}

func (s *packetSink) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	s.account(buffer.Len())
	buffer.Release()
	return nil
}

// batchPacketSink adds the batch capability on top of the single-packet one, so the same sink can
// drive both branches of the packet copy loop.
type batchPacketSink struct {
	*packetSink
}

func (s *batchPacketSink) WritePacketBatch(buffers []*buf.Buffer, _ []M.Socksaddr) error {
	s.batches.Add(1)
	for _, buffer := range buffers {
		s.account(buffer.Len())
	}
	for _, buffer := range buffers {
		buffer.Release()
	}
	return nil
}

// BenchmarkUDPCopyThroughput measures the datagram copy loop over a real loopback socket, in both
// of its branches.
//
// # Why there is no flow control, and what makes that safe
//
// UDP has no backpressure: a sender that outruns the receiver gets datagrams DROPPED by the kernel,
// silently, and the copy loop would then measure a shorter stream while looking successful. An
// earlier draft therefore made the sink hand a credit back per datagram, which is correct but
// expensive - two channel operations per datagram, charged identically to both geometries, and
// enough scheduling noise to swamp the difference being measured.
//
// What makes the credit machinery unnecessary here is that the volume is bounded and small: 2048
// datagrams of 1200 bytes is 2.4 MiB, the receive buffer is asked for 8 MiB, and the receiver
// drains concurrently on a host with no other load. Nothing is silently averaged over: the
// delivered count is asserted to EQUAL the sent count, so a single dropped datagram fails the
// benchmark instead of quietly shortening the measurement.
//
// # Why the loop is stopped by closing the socket
//
// CopyPacket runs until its source errors, and a UDP socket has no EOF. Once every expected
// datagram has been accounted for, the receiving socket is closed to abort the loop. The resulting
// error is the ABORT MECHANISM, not a datapath failure - and the payload assertion has already
// passed by the time it is produced - so it is required to be present (an early nil would mean the
// loop exited before the payload arrived) and is not otherwise inspected.
//
// # What the two sub-benchmarks isolate
//
// `single` and `batch` differ only in whether the destination implements WritePacketBatch. Both
// run under both geometries, so the batch path's own geometry sensitivity is visible instead of
// being averaged into one number. The batches/op metric records which branch actually ran; a
// platform where the batch reader is unavailable would otherwise look like a result rather than a
// fallback.
func BenchmarkUDPCopyThroughput(b *testing.B) {
	const (
		datagramSize  = 1200
		datagramCount = 2048
	)
	for _, batch := range []bool{false, true} {
		name := "single"
		if batch {
			name = "batch"
		}
		b.Run(name, func(b *testing.B) {
			runUDPCopy(b, datagramSize, datagramCount, batch)
		})
	}
}

func runUDPCopy(b *testing.B, datagramSize, datagramCount int, batch bool) {
	payload := make([]byte, datagramSize)
	total := int64(datagramSize) * int64(datagramCount)
	b.SetBytes(total)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			b.Fatalf("listen udp: %v", err)
		}
		client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
		if err != nil {
			b.Fatalf("dial udp: %v", err)
		}
		_ = server.SetReadBuffer(8 << 20)
		_ = client.SetWriteBuffer(8 << 20)

		source := bufio.NewBindPacketConn(server, client.LocalAddr())
		sink := &packetSink{expected: int64(datagramCount), complete: make(chan struct{})}
		var destination N.PacketWriter = sink
		if batch {
			destination = &batchPacketSink{sink}
		}

		senderDone := make(chan error, 1)
		go func() {
			for range datagramCount {
				if _, writeErr := client.Write(payload); writeErr != nil {
					senderDone <- writeErr
					return
				}
			}
			senderDone <- nil
		}()

		copyDone := make(chan error, 1)
		b.StartTimer()
		go func() {
			_, copyErr := bufio.CopyPacket(destination, source)
			copyDone <- copyErr
		}()

		select {
		case <-sink.complete:
		case copyErr := <-copyDone:
			// The loop returned before the payload was complete. Report WHY rather than waiting
			// out the timeout, because the two look identical to a reader of the failure and only
			// one of them is a datapath problem.
			b.Fatalf("the packet copy loop exited after %d of %d datagrams: %v",
				sink.packets.Load(), datagramCount, copyErr)
		case <-time.After(30 * time.Second):
			b.Fatalf("timed out after %d of %d datagrams: the copy loop did not consume the payload",
				sink.packets.Load(), datagramCount)
		}
		server.Close()
		copyErr := <-copyDone
		b.StopTimer()

		if copyErr == nil {
			b.Fatal("the packet copy loop returned before the socket was closed: it exited before " +
				"the payload was complete, so the measurement does not describe a full run")
		}
		if senderErr := <-senderDone; senderErr != nil {
			b.Fatalf("sender: %v", senderErr)
		}
		if received := sink.packets.Load(); received != int64(datagramCount) {
			b.Fatalf("received %d of %d datagrams: the delivered count is not deterministic, so the "+
				"throughput figure is not comparable", received, datagramCount)
		}
		if bytes := sink.bytes.Load(); bytes != total {
			b.Fatalf("received %d bytes, expected %d", bytes, total)
		}
		client.Close()
		b.ReportMetric(float64(sink.batches.Load()), "batches/op")
		b.StartTimer()
	}
}

// ---------------------------------------------------------------------------
// Per-buffer cost and allocation totals
// ---------------------------------------------------------------------------

// BenchmarkBufferAcquireRelease is the floor under every other benchmark here: what one buffer
// costs before any byte moves.
//
// A benchmark of the whole copy loop cannot separate "the geometry made each read carry half as
// much" from "the geometry made each buffer more expensive to obtain". This one can, because it
// does nothing else. If the two geometries differ here, the difference propagates to every path
// that acquires a buffer, and the report has to account for it.
func BenchmarkBufferAcquireRelease(b *testing.B) {
	b.Run("stream", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(buf.BufferSize))
		for b.Loop() {
			buffer := buf.New()
			buffer.Release()
		}
	})
	b.Run("packet", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(buf.UDPBufferSize))
		for b.Loop() {
			buffer := buf.NewPacket()
			buffer.Release()
		}
	})
}

// TestCopyLoopGrowsPastTheGeometry is the structural reason a bulk TCP transfer is NOT bounded by
// with_low_memory, stated as a measurement rather than as an argument about dependency code.
//
// # The mechanism
//
// copyExtended grows the read buffer once IncreaseBufferAfter (bufio.DefaultIncreaseBufferAfter,
// 512000 bytes) has been copied: setting options.IncreaseBuffer makes ReadWaitOptions.NewBuffer
// return 65535 bytes regardless of the pooled BufferSize. Everything after the first ~512 KiB of a
// flow therefore uses the same buffer size in both geometries, and the geometry's effect on that
// flow is confined to its first 512 KiB.
//
// # Why this test exists
//
// Without it, the throughput table's post-growth row is an assertion about a dependency's internals
// that a dependency upgrade could silently falsify - the benchmark would keep printing numbers and
// the explanation above it would quietly stop being true. Asserting the observed capacity makes the
// explanation part of the build: if upstream ever stops growing the buffer, this fails and the
// geometry decision has to be re-derived instead of inherited.
func TestCopyLoopGrowsPastTheGeometry(t *testing.T) {
	const total = 8 << 20
	chunk := make([]byte, 1<<16)

	client, server := tcpPair(t, loopbackSocketBuffer)
	senderDone := make(chan error, 1)
	blastTCP(server, total, chunk, senderDone)
	sink := &observingSink{}

	copied, err := bufio.Copy(sink, client)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if senderErr := <-senderDone; senderErr != nil {
		t.Fatalf("sender: %v", senderErr)
	}
	closeTCP(client)
	closeTCP(server)

	if copied != total || sink.bytes.Load() != total {
		t.Fatalf("copy loop reported %d bytes and the destination accepted %d, expected %d",
			copied, sink.bytes.Load(), total)
	}

	maxCap := sink.maxCap.Load()
	writes := sink.writes.Load()
	t.Logf("HOST COPY-LOOP GEOMETRY: BufferSize=%d UDPBufferSize=%d copied=%d bytes in %d WriteBuffer "+
		"calls, largest handed-over buffer capacity=%d (grown from the %d-byte pre-growth size)",
		buf.BufferSize, buf.UDPBufferSize, total, writes, maxCap, buf.BufferSize)

	// 65535 is ReadWaitOptions.NewBuffer's grown size when the destination advertises no MTU. It is
	// asserted as a floor rather than an equality so that a future change making the loop grow
	// LARGER does not fail a test whose point is that it grows at all.
	const grownBufferSize = 65535
	if maxCap < grownBufferSize {
		t.Fatalf("the largest buffer the copy loop handed over for an 8 MiB transfer was %d bytes, "+
			"below the %d-byte grown size. The loop is no longer growing past buf.BufferSize (%d), so "+
			"bulk transfer throughput is now bounded by the geometry and every bulk figure in this "+
			"package's report has to be re-derived rather than inherited",
			maxCap, grownBufferSize, buf.BufferSize)
	}
	// The write count is the other half: ~8 MiB / 65535 plus the pre-growth calls. A tolerance of
	// 2x around the grown-size estimate would still catch a loop that reverted to BufferSize-sized
	// buffers when BufferSize is 16384 (which would need ~512 writes).
	grownWrites := int64(total / grownBufferSize)
	if writes > 2*grownWrites {
		t.Fatalf("the copy loop made %d WriteBuffer calls for %d bytes; a loop using the grown "+
			"%d-byte buffer needs about %d. The pre-growth size (buf.BufferSize=%d) is still in use "+
			"past the growth threshold", writes, total, grownBufferSize, grownWrites, buf.BufferSize)
	}
}

// TestSustainedCopyMemStats reports the process-wide allocation totals the runtime itself counted
// for a fixed stream copy, which is a different instrument from the testing framework's
// allocations-per-operation counter.
//
// # Why both instruments
//
// testing.AllocsPerRun (TestAllocsPerRunBufferAcquire) counts the allocation the compiler inserted
// at one call site. runtime.MemStats.TotalAlloc and Mallocs count every allocation the runtime
// performed, including the ones inside dependency code the benchmark does not control - the copy
// session, the waiter, the unwrapping helpers. A geometry whose own buffers are free but whose
// smaller size makes the loop iterate twice as often would be visible here and invisible at the
// single call site. That is exactly the failure this pair of measurements is arranged to catch.
func TestSustainedCopyMemStats(t *testing.T) {
	const total = 8 << 20
	chunk := make([]byte, 1<<16)

	runs := 3
	var totalAllocDelta, mallocDelta uint64
	for range runs {
		client, server := tcpPair(t, loopbackSocketBuffer)
		senderDone := make(chan error, 1)
		blastTCP(server, total, chunk, senderDone)
		sink := &countingSink{}

		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		copied, err := bufio.Copy(sink, client)
		var after runtime.MemStats
		runtime.ReadMemStats(&after)

		if err != nil {
			t.Fatalf("copy: %v", err)
		}
		if senderErr := <-senderDone; senderErr != nil {
			t.Fatalf("sender: %v", senderErr)
		}
		if copied != total || sink.bytes.Load() != total {
			t.Fatalf("copy loop reported %d bytes and the destination accepted %d, expected %d",
				copied, sink.bytes.Load(), total)
		}
		closeTCP(client)
		closeTCP(server)

		totalAllocDelta += after.TotalAlloc - before.TotalAlloc
		mallocDelta += after.Mallocs - before.Mallocs
	}

	t.Logf("HOST MEMSTATS: geometry BufferSize=%d UDPBufferSize=%d copied-per-run=%d bytes; "+
		"TotalAlloc=%.0f bytes/run (%.2f bytes/KiB-copied); Mallocs=%.1f allocs/run",
		buf.BufferSize, buf.UDPBufferSize, total,
		float64(totalAllocDelta)/float64(runs),
		float64(totalAllocDelta)/float64(runs)/(float64(total)/1024),
		float64(mallocDelta)/float64(runs))
}
