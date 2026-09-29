//go:build with_quic

package masque

import (
	"testing"

	"github.com/sagernet/sing/common/buf"
)

// TestBatchPathDeliversExactBytesInOrder drives a multi-packet batch and compares what the
// transport received against what the device handed over.
//
// # Why counts are not enough
//
// The ownership tests prove WHO owns each buffer. They say nothing about WHAT is in them. A batch
// path that reversed the order, or that left the context ID off one payload, would still pass every
// release-count assertion. This test makes the payload content and its ORDER observable.
func TestBatchPathDeliversExactBytesInOrder(t *testing.T) {
	sink := &copyCountingStream{}
	current := batchTestSession(t, sink)
	sink.recordPayloads = true

	// Distinct payloads, so an ordering error cannot be masked by identical bytes. The marker is
	// written into the IP payload area, past the 20-byte header.
	const n = 5
	const markerOffset = 100
	raw := make([]*buf.Buffer, 0, n)
	for i := range n {
		packet := batchTestPacket(1200)
		packet[markerOffset] = byte(i + 1)
		buffer := buf.NewSize(PacketHeadroom + len(packet))
		buffer.Resize(PacketHeadroom, 0)
		if _, err := buffer.Write(packet); err != nil {
			t.Fatal(err)
		}
		raw = append(raw, buffer)
	}

	if err := current.client.WritePacketBuffers(raw, false); err != nil {
		t.Fatal(err)
	}

	got := sink.drainPayloads()
	if len(got) != n {
		t.Fatalf("expected %d payloads at the transport, got %d", n, len(got))
	}
	for i, payload := range got {
		if len(payload) < markerOffset+1 {
			t.Fatalf("payload %d too short: %d bytes", i, len(payload))
		}
		// The device prepends a 1-byte context ID of 0. If the batch forgot it, the IP header
		// would start one byte early and the version nibble would sit at offset 0.
		if payload[0] != 0 {
			t.Fatalf("payload %d: first byte is %#x, want the 0 context ID", i, payload[0])
		}
		// 0x45 = IPv4, 20-byte header -- i.e. the IP packet starts exactly after the context ID.
		if payload[1] != 0x45 {
			t.Fatalf("payload %d: byte after the context ID is %#x, want 0x45 (IPv4/IHL5)",
				i, payload[1])
		}
		if marker := payload[1+markerOffset]; marker != byte(i+1) {
			t.Fatalf("payload %d arrived out of order: marker=%d, want %d", i, marker, i+1)
		}
	}
}

// TestBatchFallbackDeliversExactBytesInOrder is the same assertion on the refusal path.
//
// The fallback re-sends from the caller's buffers after the batch was refused, so it exercises the
// context-ID restore. If that restore were missing or wrong, the payloads here would be shifted --
// which is exactly the bug this shape of test catches.
func TestBatchFallbackDeliversExactBytesInOrder(t *testing.T) {
	sink := &copyCountingStream{}
	sink.setRefuseBatch(true)
	current := batchTestSession(t, sink)
	sink.recordPayloads = true

	const n = 5
	const markerOffset = 100
	raw := make([]*buf.Buffer, 0, n)
	for i := range n {
		packet := batchTestPacket(1200)
		packet[markerOffset] = byte(i + 1)
		buffer := buf.NewSize(PacketHeadroom + len(packet))
		buffer.Resize(PacketHeadroom, 0)
		if _, err := buffer.Write(packet); err != nil {
			t.Fatal(err)
		}
		raw = append(raw, buffer)
	}

	if err := current.client.WritePacketBuffers(raw, false); err != nil {
		t.Fatal(err)
	}

	got := sink.drainPayloads()
	if len(got) != n {
		t.Fatalf("the fallback must deliver %d payloads, got %d", n, len(got))
	}
	for i, payload := range got {
		if len(payload) < markerOffset+1 {
			t.Fatalf("payload %d too short: %d bytes", i, len(payload))
		}
		if payload[0] != 0 {
			t.Fatalf("payload %d: first byte is %#x, want the 0 context ID (a doubled prefix shows here)",
				i, payload[0])
		}
		if payload[1] != 0x45 {
			t.Fatalf("payload %d: byte after the context ID is %#x, want 0x45 -- the payload is shifted",
				i, payload[1])
		}
		if marker := payload[1+markerOffset]; marker != byte(i+1) {
			t.Fatalf("payload %d arrived out of order: marker=%d, want %d", i, marker, i+1)
		}
	}
}
