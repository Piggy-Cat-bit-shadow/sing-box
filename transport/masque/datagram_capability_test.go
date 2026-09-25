package masque

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common/buf"
)

// The HTTP Datagram capability, and what a session does when the peer did NOT
// negotiate it.
//
// RFC 9297 says the payload then travels as DATAGRAM capsules on the request
// stream, and these tests pin the session's decisions around that.
//
// SCOPE, stated plainly because an earlier version of this file overstated it:
// these are hardening tests, not regressions for a demonstrated defect. The
// original motivation was a claim that a session which inferred the capability
// from a type assertion would run a datagram receive loop that consumed bytes
// from the capsule reader and could cancel the session. That claim was measured
// and is false - the server-side ReceiveDatagram reads a dedicated datagram queue,
// not the DATA stream, so such a loop simply blocks.
//
// What the tests below therefore establish is the INTENT the code now encodes:
//
//   - a session whose peer did not negotiate datagrams holds no datagram view and
//     never calls ReceiveDatagram;
//   - a session whose peer did negotiate them does use the datagram path, so the
//     guard cannot be implemented by disabling datagrams altogether;
//   - the write path goes straight to a capsule without attempting a datagram.
//
// The end-to-end proof of the fallback itself lives in the reference interop
// module (test/jiejie/reference), against a real peer.

// capabilityProbeStream models quic-go's behaviour faithfully: it satisfies the
// datagram interface, its SendDatagram refuses (as the real one does when the
// peer disabled datagrams), and its ReceiveDatagram BLOCKS rather than failing -
// which is what a read on a stream with no incoming data does.
type capabilityProbeStream struct {
	receiveCalls atomic.Int32
	sendCalls    atomic.Int32
	closed       atomic.Bool
	// capable is what the peer negotiated, reported through the interface method
	// the session now consults.
	capable bool
	// blockReceive keeps ReceiveDatagram parked until the stream closes, so a
	// test can observe whether the loop started at all.
	blockReceive chan struct{}
}

func newCapabilityProbeStream(capable bool) *capabilityProbeStream {
	return &capabilityProbeStream{capable: capable, blockReceive: make(chan struct{})}
}

// DatagramsEnabled reports the negotiated capability, which is the whole point of
// the interface method: the session decides from this, not from the type.
func (s *capabilityProbeStream) DatagramsEnabled() bool { return s.capable }

func (s *capabilityProbeStream) Read([]byte) (int, error) { return 0, io.EOF }

func (s *capabilityProbeStream) Write(p []byte) (int, error) { return len(p), nil }

func (s *capabilityProbeStream) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		close(s.blockReceive)
	}
	return nil
}

// SendDatagram refuses, exactly as the real implementation does when the peer
// disabled datagrams.
func (s *capabilityProbeStream) SendDatagram([]byte) error {
	s.sendCalls.Add(1)
	return transportHTTP.ErrDatagramUnsupported
}

// ReceiveDatagram parks until the stream is closed, modelling a read that cannot
// produce a datagram. It does NOT return ErrDatagramUnsupported, because the real
// one does not either - that is the whole problem.
func (s *capabilityProbeStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	s.receiveCalls.Add(1)
	select {
	case <-s.blockReceive:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// capabilityProbeHandler records the payloads a session delivers upward.
type capabilityProbeHandler struct {
	packets atomic.Int32
}

func (h *capabilityProbeHandler) handleAddressAssign([]AssignedAddress) error { return nil }
func (h *capabilityProbeHandler) handleAddressRequest([]AssignedAddress) error {
	return nil
}
func (h *capabilityProbeHandler) handleRouteAdvertisement([]AddressRange) error { return nil }
func (h *capabilityProbeHandler) handlePacket(*buf.Buffer)                      { h.packets.Add(1) }
func (h *capabilityProbeHandler) handlePacketTooBig(*buf.Buffer, int)           {}

// TestSessionDoesNotStartTheDatagramLoopWhenCapabilityIsAbsent pins the intent.
//
// When the peer did not negotiate HTTP Datagrams the session must not call
// ReceiveDatagram at all: there is no capability to receive with, so a call is at
// best a wasted blocked goroutine and at worst a capability check that would
// always fail. The assertion is on the CALL rather than on an error, because a
// ReceiveDatagram that fails is still a call that should not have happened.
func TestSessionDoesNotStartTheDatagramLoopWhenCapabilityIsAbsent(t *testing.T) {
	stream := newCapabilityProbeStream(false)
	handler := &capabilityProbeHandler{}

	current := newSession(context.Background(), stream, handler, false)
	if current.datagrams != nil {
		t.Fatal("the session must hold no datagram view when the peer did not " +
			"negotiate HTTP Datagrams")
	}

	done := make(chan error, 1)
	go func() { done <- current.run() }()

	// Let any incorrectly started datagram loop run.
	time.Sleep(250 * time.Millisecond)

	if calls := stream.receiveCalls.Load(); calls != 0 {
		t.Fatalf("ReceiveDatagram was called %d time(s) on a session whose peer did "+
			"not negotiate HTTP Datagrams. quic-go's ReceiveDatagram reads from the "+
			"QUIC stream itself, so this consumes bytes the capsule reader owns and "+
			"desynchronises capsule framing; the session must not start that loop.",
			calls)
	}

	// Shut the session down and require it to finish.
	current.cancel(nil)
	_ = stream.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return after cancellation: the datagram loop is " +
			"blocked on a read that can never complete")
	}
}

// TestSessionStartsTheDatagramLoopWhenCapabilityIsPresent is the counter-case.
//
// The guard above must not be implemented by never starting the loop. With the
// capability present the session must use the datagram receive path, or every
// datagram-capable peer would lose its data path - which no test of the fallback
// would notice.
func TestSessionStartsTheDatagramLoopWhenCapabilityIsPresent(t *testing.T) {
	stream := newCapabilityProbeStream(true)
	handler := &capabilityProbeHandler{}

	current := newSession(context.Background(), stream, handler, false)
	if current.datagrams == nil {
		t.Fatal("the session must hold the datagram view when the peer negotiated " +
			"HTTP Datagrams, or a capable peer would lose its data path")
	}

	done := make(chan error, 1)
	go func() { done <- current.run() }()

	deadline := time.After(5 * time.Second)
	for stream.receiveCalls.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("ReceiveDatagram was never called on a session whose peer DID " +
				"negotiate HTTP Datagrams, so a capable peer would have no data path")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	current.cancel(nil)
	_ = stream.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return after cancellation")
	}
}

// TestSessionSendPathFallsBackToCapsulesWhenCapabilityIsAbsent pins the write
// half, which was already correct and must stay correct.
//
// With no datagram capability the payload must be written as a DATAGRAM capsule
// on the request stream rather than attempted as a datagram.
func TestSessionSendPathFallsBackToCapsulesWhenCapabilityIsAbsent(t *testing.T) {
	stream := newCapabilityProbeStream(false)
	handler := &capabilityProbeHandler{}

	current := newSession(context.Background(), stream, handler, false)

	packet := buf.NewSize(PacketHeadroom + 4)
	packet.Resize(PacketHeadroom, 0)
	packet.Write([]byte{0x45, 0x00, 0x00, 0x00})

	if err := current.writePacket(packet); err != nil {
		t.Fatalf("writePacket must fall back to a capsule rather than reporting an "+
			"error, got %v", err)
	}
	if calls := stream.sendCalls.Load(); calls != 0 {
		t.Fatalf("SendDatagram was attempted %d time(s) although the peer did not "+
			"negotiate datagrams; the write path must go straight to a capsule",
			calls)
	}
}
