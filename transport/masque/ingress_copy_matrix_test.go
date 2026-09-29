//go:build with_quic

package masque

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

// The inbound copy matrix, pinned by test rather than asserted in prose.
//
// # What the inbound path actually costs
//
//	quic-go decrypt + HandleDatagramFrame   make + copy        (1 copy, inside quic-go)
//	http3 ReceiveDatagram                   slice              (0)
//	session.loopDatagram                    DecodeVarint+slice (0)
//	handleIngressDatagram                   buf.As             (0, an unmanaged wrap)
//	device WriteInboundBuffers              no return path -> straight through (0)
//
// So the honest total is ONE application-layer copy, and it happens inside quic-go before this
// package ever sees the bytes. That copy cannot be removed without changing the QUIC receive
// packet's lifetime, which the task forbids for this round and which the profile does not justify.
//
// # Why the return path is the thing to check
//
// transport/device can perform a SECOND full copy, but only when a return path is attached and the
// buffer lacks the return headroom. AttachReturn is defined on several endpoints and called by NONE
// of them, so in the product the state is nil and the packets go straight to the device writer.
//
// That is a fact about the current wiring rather than a guarantee, and it is exactly the kind of
// fact that changes silently. The test below pins the zero-copy half of it, so if the ingress path
// ever starts copying per packet, this fails.

// addressRecordingHandler records the backing array of the first buffer it is given.
type addressRecordingHandler struct {
	access  sync.Mutex
	address *byte
	length  int
}

// addressRecordingHandler is a sessionHandler: the session hands it the buffers it would deliver.
func (h *addressRecordingHandler) handleAddressAssign([]AssignedAddress) error   { return nil }
func (h *addressRecordingHandler) handleAddressRequest([]AssignedAddress) error  { return nil }
func (h *addressRecordingHandler) handleRouteAdvertisement([]AddressRange) error { return nil }
func (h *addressRecordingHandler) handleDNSAssign([]DNSConfiguration) error      { return nil }
func (h *addressRecordingHandler) handlePREF64([]netip.Prefix) error             { return nil }
func (h *addressRecordingHandler) handlePacketTooBig(*buf.Buffer, int)           {}

func (h *addressRecordingHandler) handlePacket(packetBuffers *buf.Buffer) {
	h.access.Lock()
	defer h.access.Unlock()
	if h.address == nil {
		payload := packetBuffers.Bytes()
		if len(payload) > 0 {
			h.address = &payload[0]
			h.length = len(payload)
		}
	}
}

func (h *addressRecordingHandler) firstBufferAddress() *byte {
	h.access.Lock()
	defer h.access.Unlock()
	return h.address
}

// TestIngressDeliversTheTransportBufferWithoutCopying proves the inbound session path wraps the
// slice it is given rather than copying it.
//
// The payload is allocated once and its first byte's address recorded. If the session copied the
// bytes into a pooled buffer, the delivered buffer would point at a different array -- and every
// received packet would cost one more full copy, which is exactly the regression to guard.
func TestIngressDeliversTheTransportBufferWithoutCopying(t *testing.T) {
	t.Parallel()

	handler := &addressRecordingHandler{}
	session := newSession(context.Background(), &ingressDatagramSource{}, handler,
		func() int { return PacketHeadroom })

	const payloadSize = 1280
	payload := make([]byte, payloadSize)
	for index := range payload {
		payload[index] = byte(index)
	}
	originalAddress := &payload[0]

	session.handleIngressDatagram(payload)

	delivered := handler.firstBufferAddress()
	if delivered == nil {
		t.Fatal("the handler received no buffer")
	}
	if delivered != originalAddress {
		t.Fatalf("the ingress path COPIED the payload: the handler saw backing array %p instead of "+
			"%p. Each received packet must WRAP the transport's slice; copying it adds a full "+
			"packet-sized copy per packet", delivered, originalAddress)
	}
}

// TestIngressDeliveredLengthMatchesPayload is the companion check that the wrap carries the whole
// packet, so the test above cannot pass on a truncated buffer.
func TestIngressDeliveredLengthMatchesPayload(t *testing.T) {
	t.Parallel()

	handler := &addressRecordingHandler{}
	session := newSession(context.Background(), &ingressDatagramSource{}, handler,
		func() int { return PacketHeadroom })

	payload := make([]byte, 512)
	session.handleIngressDatagram(payload)

	handler.access.Lock()
	length := handler.length
	handler.access.Unlock()
	if length != len(payload) {
		t.Fatalf("the delivered buffer holds %d bytes, expected %d", length, len(payload))
	}
}
