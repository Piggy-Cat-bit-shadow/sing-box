package route

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Benchmarks for the layers a literal-IP direct flow can travel through.
//
// # What each layer costs, and what is measurable in-process
//
// L1 is the platform's own routing. The connection is never created in this process, so its per-byte
// cost here is exactly zero and the only cost it has is the decision that produced it. That is what
// the decision benchmarks measure, and it is the entire reason the layer exists.
//
// L2 and L3 both move the bytes through this process and differ in where the copy happens: L2 hands
// a socket pair to the kernel (splice, sendfile, or the platform's equivalent) and L3 copies through
// userspace buffers. Both are measured over real loopback TCP sockets, because the syscalls are most
// of the cost and a benchmark that skipped them would rank the two layers by the smaller half of the
// difference. Each one asserts which path it is measuring, so they cannot silently converge.
//
// # What these numbers are not
//
// They are not an end-to-end TUN measurement. A TUN device would add the platform's packet path to
// every layer equally and needs a kernel device to run, so the differences reported here are the ones
// this change is actually responsible for. Loopback is also the friendliest case for the userspace
// copy and the least favourable for a zero-copy one: nothing has to cross a bus either way.

// --- the decision -------------------------------------------------------------------------

// BenchmarkBypassDecision measures the whole eligibility decision: every router condition and then
// the outbound's own profile. This is the cost L1 pays per flow.
func BenchmarkBypassDecision(b *testing.B) {
	router, outbound := offloadRouter(false)
	chain := []adapter.Outbound{outbound}
	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)

	b.ReportAllocs()
	for b.Loop() {
		if !router.canFastBypass(&metadata, destination, chain, outbound).BypassAllowed() {
			b.Fatal("expected eligible")
		}
	}
}

// BenchmarkBypassDecisionRefusedEarly is the cheapest refusal: the inbound type alone decides. Most
// traffic in a real configuration is proxied and never reaches even this far.
func BenchmarkBypassDecisionRefusedEarly(b *testing.B) {
	router, outbound := offloadRouter(false)
	chain := []adapter.Outbound{outbound}
	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	metadata.InboundType = C.TypeMixed

	b.ReportAllocs()
	for b.Loop() {
		if router.canFastBypass(&metadata, destination, chain, outbound).BypassAllowed() {
			b.Fatal("expected refused")
		}
	}
}

// BenchmarkBypassDecisionRefusedLate is the worst case: every cheap condition passes and the
// outbound's profile is consulted before the flow is refused. It is the most a miss can cost.
func BenchmarkBypassDecisionRefusedLate(b *testing.B) {
	router, outbound := offloadRouter(false)
	chain := []adapter.Outbound{outbound}
	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	metadata.FakeIP = true

	b.ReportAllocs()
	for b.Loop() {
		if router.canFastBypass(&metadata, destination, chain, outbound).BypassAllowed() {
			b.Fatal("expected refused")
		}
	}
}

// BenchmarkOutboundBypassProfile isolates the half this round rewrote. It is a map-free,
// allocation-free bitmask lookup, and the benchmark is what keeps it that way.
func BenchmarkOutboundBypassProfile(b *testing.B) {
	production := newProductionDirectOutbound()
	address := netip.MustParseAddr("93.184.216.34")

	b.ReportAllocs()
	for b.Loop() {
		if !production.CanBypass(N.NetworkTCP, address) {
			b.Fatal("expected eligible")
		}
	}
}

// --- per-flow setup -----------------------------------------------------------------------

// BenchmarkFlowSetupBypassed measures what a bypassed flow costs to set up here: the decision and
// nothing else. No Connection, no scheduler gate, no copy loop, no goroutine.
func BenchmarkFlowSetupBypassed(b *testing.B) {
	router, outbound := offloadRouter(false)
	chain := []adapter.Outbound{outbound}
	destination := M.ParseSocksaddr("93.184.216.34:443")

	b.ReportAllocs()
	for b.Loop() {
		metadata := fastBypassMetadata(N.NetworkTCP, destination)
		if !router.canFastBypass(&metadata, destination, chain, outbound).BypassAllowed() {
			b.Fatal("expected eligible")
		}
	}
}

// BenchmarkFlowSetupUserspace measures what the same flow costs when it is NOT bypassed: the upload
// gate is installed the way the connection manager installs it, with the production predicate, and
// the flow is registered with the scheduler. It is the per-flow half of what a bypass saves,
// independent of how many bytes the flow then carries.
//
// The socket pair is built outside the timed region, for the same reason the copy benchmark below
// builds its pair that way: net.Pipe allocates a pipe and starts a goroutine per side, which is
// fixture cost, not the cost of the gate. Measured inside the loop it WAS the whole number - the
// benchmark reported 26 allocations and 2856 B per operation, and the code under test was none of
// them. A benchmark whose number describes its own fixture is worse than no benchmark, because it
// is quoted.
func BenchmarkFlowSetupUserspace(b *testing.B) {
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	defer manager.Close()

	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		local, localPeer := net.Pipe()
		remote, remotePeer := net.Pipe()
		b.StartTimer()
		gate, flow := manager.uploadStreamGate(local, remote, 0)
		_ = gate
		_ = flow.Close()
		b.StopTimer()
		_ = localPeer.Close()
		_ = remotePeer.Close()
		b.StartTimer()
	}
}

// --- per-byte cost of the two userspace layers ---------------------------------------------

// benchmarkCopyThroughput moves `size` bytes through a real socket pair and reports the rate.
//
// Each iteration builds a fresh pair, outside the timed region, because the producer closes its end
// to signal EOF and a closed socket cannot be reused. Closing it is what makes io.Copy terminate on
// its own: a socket has no end, so the bound has to come from somewhere, and handing the source a
// LimitedReader would defeat the kernel path being measured here.
//
// The path is verified rather than assumed. A pair of benchmarks that quietly ran the same code
// would be worse than no benchmark at all.
func benchmarkCopyThroughput(b *testing.B, size int, expectKernel bool, wrapDestination func(io.Writer) io.Writer) {
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		transferSource, transferSink, producerChannel, consumerChannel := splicePair(b)
		// The check is made against the destination the copy is actually given, not against the
		// socket underneath it: verifying the unwrapped one would assert the wrong path.
		copyDestination := wrapDestination(transferSink)
		require.Equal(b, expectKernel, syscallAvailable(transferSource, copyDestination),
			"the benchmark must measure the path it claims")

		consumerDone := make(chan struct{})
		go func() {
			defer close(consumerDone)
			_, _ = io.Copy(io.Discard, consumerChannel)
		}()

		payload := make([]byte, 64*1024)
		producerDone := make(chan struct{})
		go func() {
			defer close(producerDone)
			defer producerChannel.Close()
			for remaining := size; remaining > 0; {
				chunk := min(len(payload), remaining)
				if _, err := producerChannel.Write(payload[:chunk]); err != nil {
					return
				}
				remaining -= chunk
			}
		}()
		b.StartTimer()

		copied, err := io.Copy(copyDestination, transferSource)
		if err != nil {
			b.Fatal(err)
		}
		if copied != int64(size) {
			b.Fatalf("copied %d bytes, expected %d", copied, size)
		}

		b.StopTimer()
		<-producerDone
		transferSource.Close()
		transferSink.Close()
		consumerChannel.Close()
		<-consumerDone
		producerChannel.Close()
		b.StartTimer()
	}
}

// splicePair returns four connected endpoints in two chains:
//
//	producerChannel -> transferSource   (the bytes to move)
//	transferSink    -> consumerChannel  (where they must arrive)
//
// The copy under test is transferSource -> transferSink, which is the shape of the connection
// manager's copy loop: two real TCP sockets with the kernel on both sides.
func splicePair(b *testing.B) (transferSource, transferSink net.Conn, producerChannel, consumerChannel net.Conn) {
	b.Helper()
	transferSource, producerChannel = benchmarkTCPPair(b)
	transferSink, consumerChannel = benchmarkTCPPair(b)
	return
}

func benchmarkTCPPair(b *testing.B) (client net.Conn, server net.Conn) {
	b.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(b, err)
	defer listener.Close()
	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptedChannel := make(chan accepted, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		acceptedChannel <- accepted{conn, acceptErr}
	}()
	dialed, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	require.NoError(b, err)
	serverResult := <-acceptedChannel
	require.NoError(b, serverResult.err)
	return dialed, serverResult.conn
}

// syscallAvailable is the same predicate the connection copy loop uses to decide whether the kernel
// can carry the bytes itself.
func syscallAvailable(source io.Reader, destination io.Writer) bool {
	return N.SyscallAvailableForRead(source) && N.SyscallAvailableForWrite(destination)
}

// writerOnly hides ReadFrom, which is the method that turns io.Copy into a kernel copy. Hiding it is
// how the generic userspace layer is expressed without reimplementing it.
type writerOnly struct {
	io.Writer
}

// BenchmarkDirectCopyKernel is L2: the kernel moves the bytes between the two sockets, which is what
// the copy loop does whenever it can.
func BenchmarkDirectCopyKernel(b *testing.B) {
	for _, size := range []int{4 << 20, 32 << 20} {
		b.Run(strconv.Itoa(size>>20)+"MiB", func(b *testing.B) {
			benchmarkCopyThroughput(b, size, true, func(destination io.Writer) io.Writer { return destination })
		})
	}
}

// BenchmarkDirectCopyUserspace is L3: every byte is copied through this process.
func BenchmarkDirectCopyUserspace(b *testing.B) {
	for _, size := range []int{4 << 20, 32 << 20} {
		b.Run(strconv.Itoa(size>>20)+"MiB", func(b *testing.B) {
			benchmarkCopyThroughput(b, size, false, func(destination io.Writer) io.Writer {
				return writerOnly{destination}
			})
		})
	}
}

// singlePacketSource offers single packets only, so the copy engine takes the generic per-datagram
// path this benchmark is about.
//
// The scheduler tests' packetSource also implements the batch read waiter, which is what they need
// and what would make this measure a different path - and with no batch size configured, a source
// that advertises batching makes the engine ask for zero packets forever.
type singlePacketSource struct {
	remaining int
	payload   []byte
}

func (s *singlePacketSource) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if s.remaining <= 0 {
		return M.Socksaddr{}, io.EOF
	}
	s.remaining--
	if _, err := buffer.Write(s.payload); err != nil {
		return M.Socksaddr{}, err
	}
	return M.Socksaddr{}, nil
}

// BenchmarkDirectPacketCopyUserspace measures the UDP layer's per-datagram cost.
//
// There is no kernel-copy alternative here at all: bufio.CopyPacket reads a datagram, copies it and
// writes it, once per packet, and a bypassed flow's datagrams never enter this loop. The endpoints
// are in-memory rather than real sockets on purpose - the network cost is identical for a bypassed
// and a proxied flow, and it would swamp the difference this measures.
func BenchmarkDirectPacketCopyUserspace(b *testing.B) {
	const datagram = 1400
	payload := make([]byte, datagram)

	for _, packets := range []int{1024, 8192} {
		b.Run(strconv.Itoa(packets)+"packets", func(b *testing.B) {
			b.SetBytes(int64(packets * datagram))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				source := &singlePacketSource{remaining: packets, payload: payload}
				sink := &packetSink{}
				b.StartTimer()

				// CopyPacket reports the source's EOF as its error, which is how the copy ends
				// normally rather than a failure.
				if _, err := bufio.CopyPacket(sink, source); err != nil && !errors.Is(err, io.EOF) {
					b.Fatal(err)
				}
				if sink.packets.Load() != int64(packets) {
					b.Fatalf("copied %d packets, expected %d", sink.packets.Load(), packets)
				}
			}
		})
	}
}

// --- the hard requirement -------------------------------------------------------------------

// TestBypassDecisionUsesNoAllocations asserts the property the benchmarks measure, so that a
// regression fails the suite instead of waiting for someone to read a benchmark.
func TestBypassDecisionUsesNoAllocations(t *testing.T) {
	router, outbound := offloadRouter(false)
	chain := []adapter.Outbound{outbound}
	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)

	allocations := testing.AllocsPerRun(1000, func() {
		router.canFastBypass(&metadata, destination, chain, outbound)
	})
	require.Zero(t, allocations,
		"the eligibility decision runs for every routed connection, including every proxied one")

	allocations = testing.AllocsPerRun(1000, func() {
		outbound.CanBypass(N.NetworkTCP, destination.Addr)
	})
	require.Zero(t, allocations)

	// A refusal must not allocate either, which is the case most likely to reach for a string. The
	// verdict is an integer and the attribution is a separate call, and this is what keeps that
	// separation honest.
	metadata.FakeIP = true
	allocations = testing.AllocsPerRun(1000, func() {
		router.canFastBypass(&metadata, destination, chain, outbound)
	})
	require.Zero(t, allocations)

	production := newProductionDirectOutbound()
	allocations = testing.AllocsPerRun(1000, func() {
		production.BypassBlockers(N.NetworkTCP, destination.Addr)
	})
	require.Zero(t, allocations, "the profile lookup is where a map or a slice would show up")
}

// TestBypassRefusalAttributionAllocatesDeliberately pins the asymmetry: the decision never builds a
// string and the attribution does, which is why they are two methods.
func TestBypassRefusalAttributionAllocatesDeliberately(t *testing.T) {
	production := newProductionDirectOutbound()
	address := netip.MustParseAddr("93.184.216.34")

	// BlockerNone.String() is a constant and does not allocate; a non-empty set does.
	require.Equal(t, "none", production.BypassBlockers(N.NetworkTCP, address).String())

	refusing := &productionDirectOutbound{semantics: boundDirectSemantics()}
	require.Contains(t, refusing.BypassBlockers(N.NetworkTCP, address).String(), "bind_interface")

	// The cost is bounded and only paid when something asks for it.
	start := time.Now()
	for range 1000 {
		_ = refusing.BypassBlockers(N.NetworkTCP, address).String()
	}
	require.Less(t, time.Since(start), time.Second,
		"attribution is for diagnostics, not for the data path")
}
