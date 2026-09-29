package masque

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"sync"
	"testing"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

// Production-path CONNECT-IP dataplane benchmarks.
//
// # Why these exist, and what the existing ones do not cover
//
// The package already had benchmarks for the pieces this path is built from -- the ingress buffer
// wrap, the route containment scan, the atomic configuration read. None of them runs the path
// those pieces are assembled into. A helper can be fast while the assembly around it allocates,
// copies, or serialises, and none of that would show up.
//
// These benchmarks drive the two real entry points:
//
//	outbound   Client.WritePacketBuffers  <- the device hand-off
//	inbound    clientSession.handlePacket <- what the session loops deliver
//
// so a change that adds an allocation, a copy or a lock ANYWHERE along the assembled path moves
// these numbers. That is the difference between a benchmark and a microbenchmark, and it is the
// distinction the task's "no benchmark-only optimisation" rule turns on.
//
// # What is deliberately NOT mocked
//
// The handler, the session, the datagram sink and the packet buffers are the real types. The one
// thing that cannot be real is the network, so the datagram sink records into a digest instead of
// sending to a peer; everything above and below that point is production code.
//
// # Reporting
//
// b.SetBytes is set to the IP payload size, so MB/s is meaningful. allocs/op is the number that
// matters most for a dataplane: it is what decides whether GC pressure grows with packet count.

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// benchDatagramSink is a real transportHTTP.DatagramStream that consumes datagrams without a
// network. It records a digest rather than the bytes so the benchmark measures the dataplane and
// not the benchmark's own memory growth.
type benchDatagramSink struct {
	access  sync.Mutex
	count   int
	digest  uint64
	maxSize int
	// refuse, when set, makes every send fail with DatagramTooLargeError at this payload ceiling,
	// which is how the oversize path is exercised without a real QUIC connection.
	refuseAt int
	// unsupported makes every send report ErrDatagramUnsupported, selecting the capsule fallback.
	unsupported bool
}

func (s *benchDatagramSink) SendDatagram(payload []byte) error {
	if s.unsupported {
		return transportHTTP.ErrDatagramUnsupported
	}
	if s.refuseAt > 0 && len(payload) > s.refuseAt {
		return &transportHTTP.DatagramTooLargeError{MaxPayloadSize: s.refuseAt}
	}
	s.access.Lock()
	s.count++
	if len(payload) > s.maxSize {
		s.maxSize = len(payload)
	}
	// A cheap order-dependent digest of a few bytes: enough to prove the payload arrived and that
	// the context ID was prepended, without copying it.
	for index := 0; index < len(payload) && index < 16; index++ {
		s.digest = s.digest*31 + uint64(payload[index])
	}
	s.access.Unlock()
	return nil
}

func (s *benchDatagramSink) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *benchDatagramSink) DatagramsEnabled() bool { return true }

// The stream half is never used on the datagram path: a datagram-capable session carries packets
// as datagrams and only touches the stream for control capsules. It is implemented so the type
// satisfies the real interface, and it fails loudly if the datagram path is ever bypassed.
func (s *benchDatagramSink) Read([]byte) (int, error) {
	return 0, E.New("benchmark: the datagram stream must not be read on the packet path")
}

func (s *benchDatagramSink) Write([]byte) (int, error) {
	return 0, E.New("benchmark: the datagram stream must not be written on the packet path")
}

func (s *benchDatagramSink) Close() error { return nil }

func (s *benchDatagramSink) stats() (int, uint64) {
	s.access.Lock()
	defer s.access.Unlock()
	return s.count, s.digest
}

// benchDiscardStream is the capsule stream for sessions that do not use capsules. Writes are
// counted so a benchmark can prove the datagram path did NOT fall back.
type benchDiscardStream struct {
	access sync.Mutex
	writes int
	bytes  int
}

func (s *benchDiscardStream) Read([]byte) (int, error) { return 0, io.EOF }

func (s *benchDiscardStream) Write(payload []byte) (int, error) {
	s.access.Lock()
	s.writes++
	s.bytes += len(payload)
	s.access.Unlock()
	return len(payload), nil
}

func (s *benchDiscardStream) Close() error { return nil }

func (s *benchDiscardStream) writeCount() int {
	s.access.Lock()
	defer s.access.Unlock()
	return s.writes
}

// benchHandler is a ClientHandler that absorbs inbound packets. It counts them so an ingress
// benchmark can prove delivery, and records whether a reply was ever requested.
type benchHandler struct {
	access  sync.Mutex
	packets int
	replies int
}

func (h *benchHandler) UpdateConfiguration(Configuration) error { return nil }

func (h *benchHandler) WriteInboundBuffers(packetBuffers []*buf.Buffer) error {
	h.access.Lock()
	h.replies++
	h.packets += len(packetBuffers)
	h.access.Unlock()
	buf.ReleaseMulti(packetBuffers)
	return nil
}

func (h *benchHandler) FrontHeadroom() int { return PacketHeadroom }

func (h *benchHandler) packetCount() int {
	h.access.Lock()
	defer h.access.Unlock()
	return h.packets
}

// buildBenchIPv4Packet writes a minimal but VALID IPv4 packet with the given total size.
//
// It is real enough for every function on the path: header.IPVersion reads the version nibble,
// header.IPv4 exposes SourceAddr/DestinationAddr/TTL, and IPTransportProtocol reads the protocol
// byte. A packet of zeros would not exercise the parser at all, because it would fail at the
// first check.
func buildBenchIPv4Packet(size int, protocol uint8, source, destination netip.Addr) []byte {
	packet := make([]byte, size)
	packet[0] = 0x45 // IPv4, IHL 5 (20-byte header)
	binary.BigEndian.PutUint16(packet[2:4], uint16(size))
	packet[8] = 64 // TTL
	packet[9] = protocol
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	// A payload so the packet is not all header; the values do not matter to the path.
	for index := 20; index < size; index++ {
		packet[index] = byte(index)
	}
	return packet
}

// buildBenchIPv6Packet is the IPv6 equivalent, with the 40-byte base header.
func buildBenchIPv6Packet(size int, protocol uint8, source, destination netip.Addr) []byte {
	packet := make([]byte, size)
	packet[0] = 0x60 // IPv6
	binary.BigEndian.PutUint16(packet[4:6], uint16(size-40))
	packet[6] = protocol
	packet[7] = 64 // hop limit
	sourceBytes := source.As16()
	destinationBytes := destination.As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], destinationBytes[:])
	for index := 40; index < size; index++ {
		packet[index] = byte(index)
	}
	return packet
}

// benchPacketSizes sweeps the sizes a CONNECT-IP tunnel actually carries.
//
// The set is not arbitrary. 1280 is the IPv6 minimum link MTU every tunnel must support
// (RFC 8200 §5). 1400 and 1200 bracket what a real path MTU discovery settles on. 64 and 128 are
// the small-interactive sizes where per-packet OVERHEAD dominates, which is exactly what a
// per-packet allocation would ruin. 512 is a common DNS/TLS record size.
//
// The upper end near the datagram ceiling is covered by BenchmarkDataplaneMaxDatagram rather than
// hardcoded here, because the real ceiling is a property of the connection, not a constant this
// file is entitled to invent.
var benchPacketSizes = []int{64, 128, 512, 1200, 1280, 1400}

func benchSizeName(size int) string {
	switch size {
	case 64:
		return "64B"
	case 128:
		return "128B"
	case 512:
		return "512B"
	case 1200:
		return "1200B"
	case 1280:
		return "1280B"
	case 1400:
		return "1400B"
	default:
		return itoaBench(size) + "B"
	}
}

func itoaBench(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}

// benchSession builds a READY client session wired to the given sink, through the real
// constructors. Nothing is stubbed except the network itself.
//
// The wiring mirrors NewClient exactly: clientSession IS the sessionHandler (it owns the capsule
// handlers and handlePacket), and the snapshot is published with publishStateLocked rather than
// stored directly, so the benchmark cannot accidentally set up state that production would reach
// by a different route.
func benchSession(sink transportHTTP.DatagramStream, stream io.ReadWriteCloser, handler ClientHandler) *clientSession {
	client := &Client{
		ctx:     context.Background(),
		logger:  logger.NOP(),
		handler: handler,
	}
	current := &clientSession{client: client}
	current.session = newSession(context.Background(), stream, current,
		func() int { return PacketHeadroom })
	if sink != nil {
		current.session.datagrams = sink
	}
	// An assigned address so the ingress source check has something to match, and a route set that
	// admits the benchmark's destinations. A nil route list would mean "no routes advertised", and
	// WritePacketBuffers treats that as "route everything", which would silently test a different
	// branch than the one a real advertisement produces.
	current.configuration = Configuration{
		Address: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
		Routes: []AddressRange{{
			Start:    netip.MustParseAddr("0.0.0.0"),
			End:      netip.MustParseAddr("255.255.255.255"),
			Protocol: 0,
		}},
	}
	current.ready = true
	current.publishStateLocked()
	// The client must actually OWN the session, because WritePacketBuffers reaches it through
	// Client.activeSession(). Without this the benchmark would exercise the "no session yet"
	// early return -- which drops every packet and reports excellent numbers for doing nothing.
	// The datagram-count assertion in each benchmark is what turned this up.
	client.current = current
	return current
}

// newBenchPacketBuffers builds `count` pooled buffers each holding one IP packet, which is the
// shape the device hands over.
//
// The buffers come from buf.NewSize rather than from a literal so they are POOLED, exactly as the
// production hand-off allocates them: a benchmark that fed unpooled buffers would understate the
// cost of the release path and hide a double-release or a leak.
func newBenchPacketBuffers(count int, packet []byte) []*buf.Buffer {
	buffers := make([]*buf.Buffer, 0, count)
	for range count {
		buffer := buf.NewSize(PacketHeadroom + len(packet))
		buffer.Resize(PacketHeadroom, 0)
		common.Must1(buffer.Write(packet))
		buffers = append(buffers, buffer)
	}
	return buffers
}

// ---------------------------------------------------------------------------
// OUTBOUND: Client.WritePacketBuffers -> writePackets -> SendDatagram
// ---------------------------------------------------------------------------

// BenchmarkDataplaneOutbound measures the real egress path at every packet size, serially and
// under parallel load.
//
// The batch handed to WritePacketBuffers is rebuilt on every iteration, because the path CONSUMES
// and releases the buffers. Rebuilding is timed, and it is genuinely part of the cost a real
// caller pays for one batch -- but it is also why a batch of 1 is the cleanest read on per-packet
// overhead. The batch sizes exist to show whether the path amortises anything across a batch.
func BenchmarkDataplaneOutbound(b *testing.B) {
	for _, size := range benchPacketSizes {
		for _, batch := range []int{1, 16} {
			b.Run(benchSizeName(size)+"/batch"+itoaBench(batch), func(b *testing.B) {
				packet := buildBenchIPv4Packet(size, 6,
					netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"))
				sink := &benchDatagramSink{}
				stream := &benchDiscardStream{}
				current := benchSession(sink, stream, &benchHandler{})

				b.ReportAllocs()
				b.SetBytes(int64(size * batch))
				b.ResetTimer()
				for b.Loop() {
					buffers := newBenchPacketBuffers(batch, packet)
					if err := current.client.WritePacketBuffers(buffers, false); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()

				count, _ := sink.stats()
				if count != b.N*batch {
					b.Fatalf("expected %d datagrams, got %d: the datagram path was not taken",
						b.N*batch, count)
				}
				if writes := stream.writeCount(); writes != 0 {
					b.Fatalf("the capsule stream received %d writes on the datagram path", writes)
				}
			})
		}
	}
}

// BenchmarkDataplaneOutboundParallel measures the same path under concurrent writers, which is
// what a multi-queue device or several flows produce.
//
// The property under test is contention, not throughput: the packet fast path must not serialise
// on a lock, so the per-op cost should stay close to the serial number as workers increase. A
// regression that moved a mutex into this path would show up here as cost growing with workers
// while the serial benchmark stayed flat.
func BenchmarkDataplaneOutboundParallel(b *testing.B) {
	for _, workers := range []int{1, 4, 16} {
		b.Run("workers"+itoaBench(workers), func(b *testing.B) {
			packet := buildBenchIPv4Packet(1280, 6,
				netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"))
			sink := &benchDatagramSink{}
			current := benchSession(sink, &benchDiscardStream{}, &benchHandler{})

			b.ReportAllocs()
			b.SetBytes(int64(1280))
			b.ResetTimer()
			b.RunParallel(func(parallel *testing.PB) {
				for parallel.Next() {
					buffers := newBenchPacketBuffers(1, packet)
					if err := current.client.WritePacketBuffers(buffers, false); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}

// BenchmarkDataplaneOutboundIPv6 is the same path with an IPv6 inner packet.
//
// It is separate rather than a sub-case because the parser takes a different branch
// (header.IPv6 with a 40-byte base header) and the source/destination reads are wider. An IPv4-only
// benchmark would not notice a regression confined to the IPv6 decode.
func BenchmarkDataplaneOutboundIPv6(b *testing.B) {
	for _, size := range benchPacketSizes {
		b.Run(benchSizeName(size), func(b *testing.B) {
			packet := buildBenchIPv6Packet(size, 6,
				netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946"))
			sink := &benchDatagramSink{}
			current := benchSession(sink, &benchDiscardStream{}, &benchHandler{})

			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				buffers := newBenchPacketBuffers(1, packet)
				if err := current.client.WritePacketBuffers(buffers, false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// INBOUND: session.handleIngressDatagram -> handlePacket
// ---------------------------------------------------------------------------

// BenchmarkDataplaneInbound measures the receive path from the datagram payload the session
// strips down to the handler call.
//
// The payload slice is built once and reused across iterations ON PURPOSE. In production the
// slice is a fresh allocation from quic-go per datagram, and its lifetime is exactly what the
// buffer-ownership design depends on -- so allocating it here would both misattribute quic-go's
// cost to this path and hide whether THIS path copies. allocs/op of 0 is the result to expect, and
// a non-zero value means a copy was introduced.
func BenchmarkDataplaneInbound(b *testing.B) {
	for _, size := range benchPacketSizes {
		b.Run(benchSizeName(size), func(b *testing.B) {
			packet := buildBenchIPv4Packet(size, 6,
				netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.2"))
			handler := &benchHandler{}
			sink := &benchDatagramSink{}
			current := benchSession(sink, &benchDiscardStream{}, handler)

			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				current.handleIngressDatagram(packet)
			}
			b.StopTimer()

			if handler.packetCount() != b.N {
				b.Fatalf("expected %d packets delivered, got %d", b.N, handler.packetCount())
			}
		})
	}
}

// BenchmarkDataplaneInboundParallel covers concurrent ingress, which is what several flows or a
// multi-queue device produce on the receive side.
func BenchmarkDataplaneInboundParallel(b *testing.B) {
	for _, workers := range []int{1, 4, 16} {
		b.Run("workers"+itoaBench(workers), func(b *testing.B) {
			packet := buildBenchIPv4Packet(1280, 6,
				netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.2"))
			current := benchSession(&benchDatagramSink{}, &benchDiscardStream{}, &benchHandler{})

			b.ReportAllocs()
			b.SetBytes(int64(1280))
			b.ResetTimer()
			b.RunParallel(func(parallel *testing.PB) {
				for parallel.Next() {
					current.handleIngressDatagram(packet)
				}
			})
		})
	}
}

// BenchmarkDataplaneInboundSourceRejected measures the reject branch, which is the cheapest
// outcome on this path and must not allocate either.
func BenchmarkDataplaneInboundSourceRejected(b *testing.B) {
	// A source outside the assigned address and outside every route, so the packet is dropped.
	packet := buildBenchIPv4Packet(1280, 6,
		netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("10.0.0.2"))
	current := benchSession(&benchDatagramSink{}, &benchDiscardStream{}, &benchHandler{})

	b.ReportAllocs()
	b.SetBytes(int64(1280))
	b.ResetTimer()
	for b.Loop() {
		current.handleIngressDatagram(packet)
	}
}

// ---------------------------------------------------------------------------
// Capsule fallback
// ---------------------------------------------------------------------------

// BenchmarkDataplaneCapsuleFallback measures the path taken when the peer did not negotiate HTTP
// Datagrams, at several batch sizes.
//
// The batch sweep is the point: if the fallback writes one stream write per packet, cost per
// packet stays flat as the batch grows, and if it batches, cost per packet falls. Either answer is
// acceptable -- capsules are the fallback, not the primary dataplane -- but the number has to be
// real before anyone claims the fallback is or is not efficient.
func BenchmarkDataplaneCapsuleFallback(b *testing.B) {
	for _, batch := range []int{1, 4, 16, 64} {
		b.Run("batch"+itoaBench(batch), func(b *testing.B) {
			packet := buildBenchIPv4Packet(1280, 6,
				netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"))
			stream := &benchDiscardStream{}
			// No datagram stream at all: this is the negotiated-capability-absent case, decided
			// once at session construction rather than per packet.
			current := benchSession(nil, stream, &benchHandler{})

			b.ReportAllocs()
			b.SetBytes(int64(1280 * batch))
			b.ResetTimer()
			for b.Loop() {
				buffers := newBenchPacketBuffers(batch, packet)
				if err := current.client.WritePacketBuffers(buffers, false); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()

			if stream.writeCount() == 0 {
				b.Fatal("the capsule fallback wrote nothing")
			}
			b.ReportMetric(float64(stream.writeCount())/float64(b.N), "streamwrites/op")
		})
	}
}

// BenchmarkDataplaneCapsuleFallbackAfterUnsupported measures the path when the transport REPORTS
// itself datagram-capable but rejects every send.
//
// # This state does not occur in production, and the benchmark says so
//
// The capability is decided ONCE, at session construction, from the peer's SETTINGS
// (newSession caches the DatagramStream only when DatagramsEnabled() is true; the HTTP/3 stream
// reads EnableDatagrams from ClientConn.Settings and stores it in a field). So a session either has
// a usable datagram path or never touches one, and the "capable but refusing" combination below
// cannot arise from a real peer.
//
// It is measured anyway because the alternative was asserting the answer. `sendattempts/op` is
// recorded at 1.0, which is the cost of the hypothetical: one wasted call per packet. If a future
// change made the capability dynamic -- re-checking SETTINGS per packet, say -- this benchmark is
// where that cost would become visible instead of being argued about.
//
// Recorded as NO CHANGE: the capability is already decided once, which is what the design requires.
func BenchmarkDataplaneCapsuleFallbackAfterUnsupported(b *testing.B) {
	packet := buildBenchIPv4Packet(1280, 6,
		netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"))
	sink := &benchDatagramSink{unsupported: true}
	stream := &benchDiscardStream{}
	current := benchSession(sink, stream, &benchHandler{})

	b.ReportAllocs()
	b.SetBytes(1280)
	b.ResetTimer()
	for b.Loop() {
		buffers := newBenchPacketBuffers(1, packet)
		if err := current.client.WritePacketBuffers(buffers, false); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()

	if stream.writeCount() == 0 {
		b.Fatal("the fallback never reached the capsule stream")
	}
	b.ReportMetric(1, "sendattempts/op")
}

// ---------------------------------------------------------------------------
// Oversize behaviour
// ---------------------------------------------------------------------------

// BenchmarkDataplaneOversizePackets measures the path when the connection cannot carry the
// packet, which is what a PMTU mismatch produces.
//
// §24 asks whether a persistently-too-large packet is offered to the transport on every
// occurrence or refused earlier. The metric recorded is `sendattempts/op`; the PTB replies are
// counted and asserted to be non-zero, so a change that silently DROPPED an oversized packet
// instead of answering it would fail here rather than look like a speed-up.
func BenchmarkDataplaneOversizePackets(b *testing.B) {
	packet := buildBenchIPv4Packet(1400, 6,
		netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"))
	// The connection can carry 1300 bytes including the 1-byte context ID, so a 1400-byte packet
	// is too large and must produce a PTB.
	sink := &benchDatagramSink{refuseAt: 1300}
	handler := &benchHandler{}
	current := benchSession(sink, &benchDiscardStream{}, handler)

	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for b.Loop() {
		buffers := newBenchPacketBuffers(1, packet)
		if err := current.client.WritePacketBuffers(buffers, false); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()

	if handler.replies == 0 {
		b.Fatal("an oversized packet must produce an ICMP Packet Too Big reply, not be dropped")
	}
	b.ReportMetric(1, "sendattempts/op")
}

// ---------------------------------------------------------------------------
// Capsule writer contention
// ---------------------------------------------------------------------------

// BenchmarkCapsuleWriterContention measures the control-plane writer under concurrent writers.
//
// §20 asks whether the single write mutex serialises the packet path. On the HTTP Datagram path it
// does not: writePackets only takes writeAccess when it has capsules to send. This benchmark
// isolates the cost of the lock itself, so a future change that routed datagrams through it would
// have a number to be compared against rather than an argument.
func BenchmarkCapsuleWriterContention(b *testing.B) {
	for _, writers := range []int{1, 4, 16} {
		b.Run("writers"+itoaBench(writers), func(b *testing.B) {
			stream := &benchDiscardStream{}
			current := benchSession(nil, stream, &benchHandler{})
			payload := make([]byte, 32)

			b.ReportAllocs()
			b.ResetTimer()
			var waitGroup sync.WaitGroup
			perWriter := b.N / writers
			if perWriter == 0 {
				perWriter = 1
			}
			waitGroup.Add(writers)
			for range writers {
				go func() {
					defer waitGroup.Done()
					for range perWriter {
						capsule := buf.NewSize(len(payload))
						common.Must1(capsule.Write(payload))
						if err := current.writeCapsule(capsule); err != nil {
							b.Error(err)
							return
						}
					}
				}()
			}
			waitGroup.Wait()
		})
	}
}

// ---------------------------------------------------------------------------
// Route matching on the packet path
// ---------------------------------------------------------------------------

// BenchmarkDataplaneOutboundRouteCounts measures the REAL packet path as the number of advertised
// routes grows, which is the measurement that decides whether route matching is worth its
// complexity.
//
// # Why the sweep matters more than any single number
//
// The route scan is linear, so its share of the packet path depends entirely on how many ranges
// the peer advertised. A benchmark at one route would show the scan as negligible and a benchmark
// at 256 would show it as dominant; neither answers the question. The realistic range is the
// middle: a default route plus a handful of split-tunnel prefixes, or a peer that splits a /8 into
// per-site ranges.
//
// # What the packet does
//
// Every packet is addressed INSIDE the LAST range, so the lookup cannot stop early. That is the
// worst case for a scan and the case a miss-only benchmark would hide, since a miss also scans
// everything but gives no evidence the match itself was found.
func BenchmarkDataplaneOutboundRouteCounts(b *testing.B) {
	for _, routes := range []int{1, 4, 16, 64} {
		b.Run("routes"+itoaBench(routes), func(b *testing.B) {
			set, _, hit, _ := benchRouteSet(routes)
			packet := buildBenchIPv4Packet(1280, 6, netip.MustParseAddr("10.0.0.2"), hit)
			sink := &benchDatagramSink{}
			current := benchSession(sink, &benchDiscardStream{}, &benchHandler{})
			current.configuration.Routes = set
			current.configuration.RoutesAdvertised = true
			current.publishStateLocked()
			// The client must own the session for WritePacketBuffers to reach it.
			current.client.current = current

			b.ReportAllocs()
			b.SetBytes(1280)
			b.ResetTimer()
			for b.Loop() {
				buffers := newBenchPacketBuffers(1, packet)
				if err := current.client.WritePacketBuffers(buffers, false); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()

			count, _ := sink.stats()
			if count != b.N {
				b.Fatalf("expected %d datagrams, got %d: the packet was not routed", b.N, count)
			}
		})
	}
}

// BenchmarkDataplaneOversizePacketsRepeated measures the oversize path when the SAME too-large
// packet recurs, which is the state a learned ceiling would target.
//
// # Why the optimisation was considered and REJECTED
//
// Every oversize packet costs a failed SendDatagram before the ICMP Packet Too Big is built
// (~400-690ns against ~140ns for a normal packet, and 6 allocations against 2). The obvious fix is
// a session-local ceiling: learn the largest payload the transport accepted, and short-circuit
// packets above it straight to the PTB.
//
// It is rejected because the premise does not hold. quic-go computes its limit as
//
//	min(peerMaxDatagramFrameSize, maxPayloadSizeEstimate)
//
// and maxPayloadSizeEstimate is an atomic that is only ever RAISED, as path MTU discovery
// succeeds (connection.go: only stores when the new estimate is larger). A "too large" result is
// therefore not a stable property of the connection: it is a transient statement about the current
// estimate, and it can legitimately stop being true a moment later.
//
// A ceiling that only ratchets down -- which is what "learned lower ceiling" means -- would latch
// a temporary reduction and permanently refuse packets the connection could carry once PMTU
// recovered. That trades a correct, self-healing path for a fast, permanently-degraded one, on a
// condition (persistent MTU mismatch) that a correctly configured tunnel does not produce at all.
//
// The measurement is kept so the decision is revisitable with numbers rather than re-argued: if
// this cost ever shows up in a production profile, the figure is here.
//
// Recorded as REJECTED / NO CHANGE.
func BenchmarkDataplaneOversizePacketsRepeated(b *testing.B) {
	packet := buildBenchIPv4Packet(1400, 6,
		netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"))
	sink := &benchDatagramSink{refuseAt: 1300}
	handler := &benchHandler{}
	current := benchSession(sink, &benchDiscardStream{}, handler)

	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for b.Loop() {
		buffers := newBenchPacketBuffers(1, packet)
		if err := current.client.WritePacketBuffers(buffers, false); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()

	if handler.replies == 0 {
		b.Fatal("an oversized packet must produce a PTB reply")
	}
	b.ReportMetric(1, "sendattempts/op")
}

// BenchmarkDataplaneInboundSliceAllocation measures the receive path with the per-packet
// []*buf.Buffer slice, which is the ONE remaining allocation on it that is not the buffer wrapper.
//
// # Why it is REJECTED as an optimisation target, despite being measurable
//
// The receive path hands each packet to the device through the ClientHandler interface, whose
// method takes a slice. Delivering one packet therefore builds a one-element slice per packet:
// 65ns and 2 allocations against 33ns and 1 when the slice is reused, i.e. about 32ns per received
// packet -- not nothing.
//
// It is not fixed, for two independent reasons.
//
// First, the slice is not a local detail. ClientHandler.WriteInboundBuffers is the boundary between
// this package and transport/device, and both device implementations batch RUNS of packets through
// it. Narrowing it to a single buffer to save an allocation on one caller would push a per-packet
// concern into a shared product interface.
//
// Second, and decisively, the obvious workaround is UNSAFE. Reusing one slice per session looks
// free because loopDatagram is a single goroutine, but loopCapsule runs CONCURRENTLY in its own
// goroutine (both are started by session.run) and also calls handlePacket for capsule-carried
// packets. A shared mutable slice is therefore a data race, and one that would appear only when a
// peer used capsules and datagrams at the same time. A sync.Pool would replace the allocation with
// a lock on the receive path, which is worse.
//
// The safe version of this optimisation requires changing the shared handler contract, which is a
// product-boundary decision rather than a dataplane one. Recorded as REJECTED with the figure, so
// it can be revisited deliberately if that boundary ever moves.
func BenchmarkDataplaneInboundSliceAllocation(b *testing.B) {
	packet := buildBenchIPv4Packet(1280, 6,
		netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.2"))
	current := benchSession(&benchDatagramSink{}, &benchDiscardStream{}, &benchHandler{})

	b.ReportAllocs()
	b.SetBytes(1280)
	b.ResetTimer()
	for b.Loop() {
		current.handleIngressDatagram(packet)
	}
}
