//go:build with_quic

package masque

import (
	"net/netip"
	"testing"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
)

// Tests for the batched owned send path in session.writePackets.
//
// # What is actually at risk
//
// The batch path hands every payload to the transport in one call and relies on the transport's
// all-or-nothing contract. Two mistakes are possible and both are silent:
//
//   - the fallback loop runs after the batch was ACCEPTED, sending every packet twice;
//   - the fallback loop runs over buffers whose original was CONSUMED by PrependContextID, i.e.
//     over released memory.
//
// Neither shows up as a failure at the call site. They corrupt unrelated traffic later, which is
// why these tests count sends and releases rather than asserting on internals.

// batchTestPacket builds a valid IPv4 packet of the given size for the batch tests.
func batchTestPacket(size int) []byte {
	return buildBenchIPv4Packet(size, 6,
		netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"))
}

// batchTestSession builds a real clientSession and resolves the owned capabilities exactly the way
// newSession does, so a broken As* helper is caught here rather than in production.
func batchTestSession(t *testing.T, stream *copyCountingStream) *clientSession {
	t.Helper()
	current := benchSession(stream, &benchDiscardStream{}, &benchHandler{})
	// Re-resolve through the production helpers instead of assigning the fields: this is what makes
	// the test cover capability detection and not just the send loop.
	current.session.ownedDatagrams = transportHTTP.AsOwnedDatagramSender(stream)
	current.session.batchOwnedDatagrams = transportHTTP.AsBatchOwnedDatagramSender(stream)
	if current.session.ownedDatagrams == nil {
		t.Fatal("fixture must expose the owned capability")
	}
	if current.session.batchOwnedDatagrams == nil {
		t.Fatal("fixture must expose the batch owned capability")
	}
	return current
}

// TestBatchPathSendsEveryPayloadOnce proves a multi-packet group takes the batch path, exactly once,
// carrying every payload.
func TestBatchPathSendsEveryPayloadOnce(t *testing.T) {
	sink := &copyCountingStream{}
	current := batchTestSession(t, sink)

	const n = 8
	buffers := newBenchPacketBuffers(n, batchTestPacket(1400))
	if err := current.client.WritePacketBuffers(buffers, false); err != nil {
		t.Fatal(err)
	}

	calls, payloads := sink.batchStats()
	if calls != 1 {
		t.Fatalf("expected exactly ONE batched send for %d packets, got %d", n, calls)
	}
	if payloads != n {
		t.Fatalf("expected %d batched payloads, got %d", n, payloads)
	}
	// Nothing may ALSO go through the per-packet path, or every packet would be sent twice.
	if copies, owned, legacy := sink.stats(); copies != 0 || owned != 0 || legacy != 0 {
		t.Fatalf("batch path must not also use the per-packet paths: copies=%d owned=%d legacy=%d",
			copies, owned, legacy)
	}
}

// TestBatchPathIsNotTakenForOnePacket is the batch=1 regression guard.
//
// The measurement showed the batched form is slightly SLOWER for one packet, because the transport
// charges the same fixed cost either way. A single packet must keep using the original path.
func TestBatchPathIsNotTakenForOnePacket(t *testing.T) {
	sink := &copyCountingStream{}
	current := batchTestSession(t, sink)

	buffers := newBenchPacketBuffers(1, batchTestPacket(1400))
	if err := current.client.WritePacketBuffers(buffers, false); err != nil {
		t.Fatal(err)
	}
	if calls, _ := sink.batchStats(); calls != 0 {
		t.Fatalf("a single packet must NOT use the batch path, got %d batch calls", calls)
	}
	if _, owned, _ := sink.stats(); owned != 1 {
		t.Fatalf("a single packet must use the per-packet owned path, got %d calls", owned)
	}
}

// TestBatchRefusalFallsBackToPerPacketLoop is the core safety property.
//
// When the transport refuses the batch, EVERY buffer must still be valid and the per-packet loop
// must then send all of them. A fallback over handed-over or consumed buffers fails this as a
// double release, a garbled payload, or a panic.
func TestBatchRefusalFallsBackToPerPacketLoop(t *testing.T) {
	sink := &copyCountingStream{}
	sink.setRefuseBatch(true)
	current := batchTestSession(t, sink)

	const n = 6
	buffers := newBenchPacketBuffers(n, batchTestPacket(1200))
	if err := current.client.WritePacketBuffers(buffers, false); err != nil {
		t.Fatal(err)
	}

	if calls, _ := sink.batchStats(); calls != 0 {
		t.Fatalf("a refused batch must not be counted as accepted, got %d", calls)
	}
	// Every packet must still have gone out, through the per-packet owned path.
	if _, owned, _ := sink.stats(); owned != n {
		t.Fatalf("the fallback must send all %d packets, got %d", n, owned)
	}
}

// TestBatchRefusalRestoresTheOriginalLayout is what catches a mis-restored prefix.
//
// # What the bug looks like, and why a digest misses it
//
// The refused batch must hand every buffer back with the context ID REMOVED. If it does not, the
// fallback prepends a second one and the inner IP packet shifts by a byte. The payload still has
// the right LENGTH and the right last byte, so a digest over sampled bytes does not notice -- which
// is exactly how this bug survived a first version of this test.
//
// The invariant that does notice is the layout: after a refused batch, each buffer must be
// byte-for-byte what the caller passed in. That is checked directly here, before and after, rather
// than inferred from what the transport later received.
func TestBatchRefusalRestoresTheOriginalLayout(t *testing.T) {
	sink := &copyCountingStream{}
	sink.setRefuseBatch(true)
	current := batchTestSession(t, sink)

	const n = 4
	buffers := newBenchPacketBuffers(n, batchTestPacket(1200))
	before := make([][]byte, n)
	beforeStart := make([]int, n)
	for i, b := range buffers {
		before[i] = append([]byte(nil), b.Bytes()...)
		beforeStart[i] = b.Start()
	}

	// Attempt the batch directly, so the refusal is observed without the fallback loop running and
	// consuming the buffers first.
	if current.session.writeBatchOwned(buffers) {
		t.Fatal("the fixture refuses every batch, so this must report a refusal")
	}

	for i, b := range buffers {
		if b.Start() != beforeStart[i] {
			t.Fatalf("buffer %d: start moved from %d to %d -- the context ID was not undone",
				i, beforeStart[i], b.Start())
		}
		if got := b.Bytes(); string(got) != string(before[i]) {
			t.Fatalf("buffer %d: payload changed by a refused batch", i)
		}
	}
}

// TestBatchRefusalFallbackDeliversEveryPacket is the end-to-end consequence.
//
// It drives the real entry point and counts what the transport actually received, so a fallback
// that silently drops the whole batch is a failure rather than an empty-but-equal digest.
func TestBatchRefusalFallbackDeliversEveryPacket(t *testing.T) {
	sink := &copyCountingStream{}
	sink.setRefuseBatch(true)
	current := batchTestSession(t, sink)

	const n = 4
	if err := current.client.WritePacketBuffers(newBenchPacketBuffers(n, batchTestPacket(1200)), false); err != nil {
		t.Fatal(err)
	}
	if _, sent, _ := sink.stats(); sent != n {
		t.Fatalf("the fallback must deliver all %d packets, got %d -- a mis-restored prefix drops them",
			n, sent)
	}
}

// TestBatchAcceptanceDoesNotDoubleRelease proves the session gives ownership up exactly once.
//
// The fixture releases every buffer it accepts. If the session released them too, the same pooled
// array would be handed out twice and later traffic would be corrupted. Detecting that directly is
// unreliable (Release is idempotent), so this test instead pins the observable consequence: after
// an accepted batch the session must not touch the buffers again, i.e. a second packet batch with
// FRESH buffers still reaches the transport normally.
func TestBatchAcceptanceDoesNotDoubleRelease(t *testing.T) {
	sink := &copyCountingStream{}
	current := batchTestSession(t, sink)

	if err := current.client.WritePacketBuffers(newBenchPacketBuffers(4, batchTestPacket(1200)), false); err != nil {
		t.Fatal(err)
	}
	if calls, payloads := sink.batchStats(); calls != 1 || payloads != 4 {
		t.Fatalf("expected one batch of 4, got calls=%d payloads=%d", calls, payloads)
	}

	// A second, independent batch must behave identically. A double release of the first batch's
	// buffers would have poisoned the pool that these came from.
	if err := current.client.WritePacketBuffers(newBenchPacketBuffers(4, batchTestPacket(1200)), false); err != nil {
		t.Fatal(err)
	}
	if calls, payloads := sink.batchStats(); calls != 2 || payloads != 8 {
		t.Fatalf("second batch must also succeed: calls=%d payloads=%d", calls, payloads)
	}
}

// TestBatchFallbackStillClassifiesOversize proves the fallback keeps the per-packet error handling.
//
// The batch returns false on refusal and the loop then classifies the failure, so an oversize packet
// must still produce a Packet Too Big exactly as it did before batching existed.
//
// The ceiling matters: writePackets only emits a PTB when the resulting MTU is at or above the
// 1280-byte minimum link MTU. A ceiling that subtracts below that produces a connection error
// instead, which is correct but is a different branch. 1300 is used so the PTB branch is the one
// under test -- the same value the existing oversize benchmark uses.
func TestBatchFallbackStillClassifiesOversize(t *testing.T) {
	sink := &copyCountingStream{}
	sink.setRefuseBatch(true)
	sink.setRefuseOwnedAbove(1300)

	handler := &benchHandler{}
	current := benchSession(sink, &benchDiscardStream{}, handler)
	current.session.ownedDatagrams = transportHTTP.AsOwnedDatagramSender(sink)
	current.session.batchOwnedDatagrams = transportHTTP.AsBatchOwnedDatagramSender(sink)

	// Two real packets, both above the ceiling, so both must become PTBs.
	buffers := newBenchPacketBuffers(2, batchTestPacket(1400))
	if err := current.client.WritePacketBuffers(buffers, false); err != nil {
		t.Fatal(err)
	}
	// handlePacketTooBig routes the ICMP error to the device, which is this handler.
	if got := handler.packetCount(); got != 2 {
		t.Fatalf("expected 2 Packet Too Big replies, got %d", got)
	}
	// Nothing may have been released as "sent", since nothing was sent.
	if _, owned, _ := sink.stats(); owned != 0 {
		t.Fatalf("no packet should have been sent, got %d owned sends", owned)
	}
}

// TestBatchFallbackBelowMinimumLinkMTUIsAnError covers the other side of the same branch.
//
// When the ceiling is so low that the resulting MTU would be below the 1280-byte minimum link MTU,
// no PTB can be built and the session must report a hard error rather than inventing a message.
func TestBatchFallbackBelowMinimumLinkMTUIsAnError(t *testing.T) {
	sink := &copyCountingStream{}
	sink.setRefuseBatch(true)
	sink.setRefuseOwnedAbove(1000) // mtu becomes 999, below the 1280 minimum

	handler := &benchHandler{}
	current := benchSession(sink, &benchDiscardStream{}, handler)
	current.session.ownedDatagrams = transportHTTP.AsOwnedDatagramSender(sink)
	current.session.batchOwnedDatagrams = transportHTTP.AsBatchOwnedDatagramSender(sink)

	err := current.session.writePackets(newBenchPacketBuffers(2, batchTestPacket(1200)))
	if err == nil {
		t.Fatal("a ceiling below the minimum link MTU must be reported as an error")
	}
	if got := handler.packetCount(); got != 0 {
		t.Fatalf("no Packet Too Big can be built below the minimum link MTU, got %d", got)
	}
}
