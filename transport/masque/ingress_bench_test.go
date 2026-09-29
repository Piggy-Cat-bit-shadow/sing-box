package masque

import (
	"context"
	"net/netip"
	"testing"
	"time"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common/buf"
)

// Benchmarks for the HTTP/3 datagram INGRESS path in session.loopDatagram.
//
// # What is being measured
//
// The ingress path is:
//
//	quic-go ReceiveDatagram -> []byte  (an INDEPENDENT allocation; see below)
//	DecodeVarint            -> context ID + length
//	<buffer strategy>       -> the subject of these benchmarks
//	handler.handlePacket(buffer)
//
// The original strategy acquired a pooled buffer and memcpy'd the whole packet
// into it, on top of the copy quic-go had already performed:
//
//	buffer := buf.NewSize(headroom + len(datagram) - contextLength)
//	buffer.Resize(headroom, 0)
//	common.Must1(buffer.Write(datagram[contextLength:]))
//
// The current strategy wraps the received slice instead, because quic-go
// transfers ownership of it (see the verification note below).
//
// # Why the strategy comparison is a DIRECT benchmark
//
// A benchmark that drives the whole session per packet spends almost all of its
// time in fixture setup -- goroutine creation, channel handoff, session
// construction -- which is identical for both strategies and therefore SWAMPS
// the difference. That is why the first version of this file reported
// 19 allocs/op for BOTH strategies: the copy was real but invisible against a
// fixed ~2us of harness cost.
//
// So BenchmarkIngressBufferCopy and BenchmarkIngressBufferWrap measure the two
// strategies directly with no harness in the way, and
// BenchmarkDatagramIngressEndToEnd is kept only as an integration guard that the
// real path still runs and still delivers every datagram. The direct benchmarks
// are where the numbers in docs/JIEJIE-MASQUE-PERFORMANCE.md come from.
//
// # Why the returned slice is safe to keep
//
// Verified in the pinned quic-go (v0.61.0-sing-box-mod.7), not assumed:
//
//	datagram_queue.go HandleDatagramFrame:
//	    data := make([]byte, len(f.Data))
//	    copy(data, f.Data)
//	    h.rcvQueue = append(h.rcvQueue, data)
//	datagram_queue.go Receive:
//	    data := h.rcvQueue[0]
//	    h.rcvQueue = h.rcvQueue[1:]
//	    return data
//
// The slice is a fresh allocation per datagram, the receive queue drops its own
// reference before returning, and nothing reuses the backing array. That is what
// makes wrapping it (buf.As, UNMANAGED) a valid ownership transfer rather than a
// use-after-free.
//
// The same property is already relied upon by the CONNECT-UDP ingress in
// transport/http/capsule.go, which wraps rather than copies for the same reason.

// ingressDatagramSource is a DatagramStream that yields a fresh datagram slice per
// call, matching quic-go's per-datagram allocation.
type ingressDatagramSource struct {
	payload []byte
	// frames is how many datagrams to serve before parking.
	frames int
	// served receives one token per delivered datagram, so a test can wait for
	// real progress instead of sleeping and hoping.
	served chan struct{}
}

func (s *ingressDatagramSource) DatagramsEnabled() bool { return true }

// ReceiveDatagram returns a NEW slice each time, which is what quic-go does. A
// fixture that returned a shared backing array would make the copy under test
// look cheaper than it is, and would make the ownership transfer look unsafe when
// it is not.
func (s *ingressDatagramSource) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if s.frames <= 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	s.frames--
	datagram := make([]byte, len(s.payload))
	copy(datagram, s.payload)
	if s.served != nil {
		select {
		case s.served <- struct{}{}:
		default:
		}
	}
	return datagram, nil
}

func (s *ingressDatagramSource) SendDatagram([]byte) error { return nil }

// Read parks so the capsule loop cannot end the session while datagrams are
// still being delivered. Returning EOF would terminate run() immediately.
func (s *ingressDatagramSource) Read([]byte) (int, error) { select {} }

func (s *ingressDatagramSource) Write(p []byte) (int, error) { return len(p), nil }

func (s *ingressDatagramSource) Close() error { return nil }

// ingressHandler consumes packets and releases them, which is what the real
// handler does once it has handed the buffer to the device.
type ingressHandler struct {
	packets chan *buf.Buffer
}

func (h *ingressHandler) handleAddressAssign([]AssignedAddress) error  { return nil }
func (h *ingressHandler) handleAddressRequest([]AssignedAddress) error { return nil }
func (h *ingressHandler) handleDNSAssign([]DNSConfiguration) error     { return nil }

func (h *ingressHandler) handlePREF64([]netip.Prefix) error { return nil }

func (h *ingressHandler) handleRouteAdvertisement([]AddressRange) error { return nil }
func (h *ingressHandler) handlePacketTooBig(_ *buf.Buffer, _ int)       {}

func (h *ingressHandler) handlePacket(buffer *buf.Buffer) {
	// The reference is dropped exactly as the production handler does. A
	// fixture that kept every buffer would measure unbounded growth instead of
	// steady-state pool behaviour.
	select {
	case h.packets <- buffer:
	default:
		buffer.Release()
	}
}

// buildIngressDatagram frames `payload` as an H3 datagram with a zero context ID,
// which is what a CONNECT-IP datagram looks like on the wire.
func buildIngressDatagram(payload []byte) []byte {
	datagram := make([]byte, 0, len(payload)+1)
	datagram = append(datagram, 0) // context ID 0
	datagram = append(datagram, payload...)
	return datagram
}

// ingressMTUSizes are the packet sizes that matter for a MASQUE tunnel: 1280 is
// the IPv6 minimum link MTU and the default session MTU, 1400 is a typical
// ethernet-path MTU, and the small ones stand for DNS or ACK-sized datagrams
// where fixed per-packet overhead dominates the copy.
var ingressMTUSizes = []int{64, 256, 1280, 1400}

func ingressSizeName(size int) string {
	switch size {
	case 64:
		return "64B"
	case 256:
		return "256B"
	case 1280:
		return "1280B"
	case 1400:
		return "1400B"
	default:
		return "other"
	}
}

// BenchmarkIngressBufferCopy measures the ORIGINAL strategy: acquire a pooled
// buffer, reserve headroom, memcpy the payload, release the buffer.
//
// It is kept as the baseline the wrap strategy is compared against. Removing it
// would make the improvement unverifiable and would let a future change quietly
// reintroduce the copy with no benchmark to catch it.
func BenchmarkIngressBufferCopy(b *testing.B) {
	for _, size := range ingressMTUSizes {
		b.Run(ingressSizeName(size), func(b *testing.B) {
			payload := make([]byte, size)
			headroom := PacketHeadroom
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				buffer := buf.NewSize(headroom + len(payload))
				buffer.Resize(headroom, 0)
				_, _ = buffer.Write(payload)
				buffer.Release()
			}
		})
	}
}

// BenchmarkIngressBufferWrap measures the CURRENT strategy: wrap the received
// slice with an unmanaged buffer and release it. No pool acquisition, no memcpy.
func BenchmarkIngressBufferWrap(b *testing.B) {
	for _, size := range ingressMTUSizes {
		b.Run(ingressSizeName(size), func(b *testing.B) {
			payload := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				buffer := buf.As(payload)
				buffer.Release()
			}
		})
	}
}

// BenchmarkDatagramIngressEndToEnd runs the real loopDatagram over a burst of
// packets.
//
// It is an integration guard, not a comparison: its per-op cost is dominated by
// fixture setup. It exists to keep the real path exercised under -bench, so a
// change that made loopDatagram stop delivering datagrams would fail here rather
// than only in a unit test that calls the buffer helper directly.
func BenchmarkDatagramIngressEndToEnd(b *testing.B) {
	const frames = 32
	size := 1400
	payload := make([]byte, size)
	datagram := buildIngressDatagram(payload)
	headroom := PacketHeadroom

	b.ReportAllocs()
	b.SetBytes(int64(size))
	for b.Loop() {
		handler := &ingressHandler{packets: make(chan *buf.Buffer, frames)}
		source := &ingressDatagramSource{
			payload: datagram,
			frames:  frames,
			served:  make(chan struct{}, frames),
		}
		current := newSession(context.Background(), source, handler, func() int { return headroom })
		current.datagrams = source
		done := make(chan struct{})
		go func() {
			defer close(done)
			current.loopDatagram()
		}()
		// Wait for the source to hand over every frame, so the measured burst is
		// the whole burst rather than however much got through before teardown.
		for range frames {
			select {
			case <-source.served:
			case <-time.After(10 * time.Second):
				b.Fatal("datagram ingress stalled")
			}
		}
		current.cancel(context.Canceled)
		<-done
		for {
			select {
			case buffer := <-handler.packets:
				buffer.Release()
			default:
				goto drained
			}
		}
	drained:
	}
}

var _ transportHTTP.DatagramStream = (*ingressDatagramSource)(nil)
