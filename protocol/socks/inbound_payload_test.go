package socks

import (
	"bytes"
	"context"
	"testing"

	N "github.com/sagernet/sing/common/network"
)

// ---------------------------------------------------------------------------
// First payload integrity through the real inbound.
//
// A proxy client may write its first payload byte in the same segment as the
// handshake. The handshake reads through a bufio.Reader, so those bytes are
// pulled out of the socket and live in the parser's buffer; a parser that hands
// its own connection downstream strands them and the tunnel silently starts
// mid-stream. This inbound used to build that reader inline and throw it away,
// which is exactly that bug.
// ---------------------------------------------------------------------------

func TestPipelinedFirstPayloadIsDeliveredExactlyOnce(t *testing.T) {
	payload := tlsClientHelloLike(517)
	cases := []struct {
		name       string
		handshake  []byte
		plan       []int
		readPlanBy string
	}{
		{"socks5/single-segment", socks5NoAuth("example.com", 443), nil, "one read"},
		{"socks5/one-byte-reads", socks5NoAuth("example.com", 443), readPlanFor(1), "one byte per read"},
		{"socks5/kernel-sized-reads", socks5NoAuth("example.com", 443), readPlanFor(1448), "kernel-sized reads"},
		{"socks4/single-segment", socks4Connect([4]byte{203, 0, 113, 5}, 9050, ""), nil, "one read"},
		{"socks4/one-byte-reads", socks4Connect([4]byte{203, 0, 113, 5}, 9050, ""), readPlanFor(1), "one byte per read"},
	}
	for _, testCase := range cases {
		testCase := testCase
		stream := append(append([]byte{}, testCase.handshake...), payload...)
		t.Run(testCase.name, func(t *testing.T) {
			harness := newInboundHarness(t, nil)
			var conn *scriptedConn
			if testCase.plan == nil {
				conn = newScriptedConn(stream)
			} else {
				conn = newScriptedConn(stream, testCase.plan...)
			}
			harness.newConnection(context.Background(), conn, nil)
			routed := harness.router.waitConnection(t)

			got, err := readExact(routed.conn, len(payload))
			if err != nil {
				t.Fatalf("read payload (%s): %v (got %d/%d bytes)", testCase.readPlanBy, err, len(got), len(payload))
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload mismatch (%s)\n got: %x\nwant: %x", testCase.readPlanBy, got, payload)
			}
			// Drained: the tunnel must not hand the same bytes back, and the
			// double must never have been read past what the client wrote.
			extra := make([]byte, 256)
			if n, _ := routed.conn.Read(extra); n != 0 {
				t.Fatalf("payload read twice: %d extra bytes", n)
			}
			if delivered := conn.bytesDelivered(); delivered > len(stream) {
				t.Fatalf("read %d bytes from a %d byte stream: bytes were replayed", delivered, len(stream))
			}
		})
	}
}

// TestHandshakeOnlyLeavesNoPhantomPayload is the converse: the wrapper must not
// invent bytes when the client sent nothing but the handshake.
func TestHandshakeOnlyLeavesNoPhantomPayload(t *testing.T) {
	streams := []struct {
		name string
		data []byte
	}{
		{"socks5", socks5NoAuth("example.com", 443)},
		{"socks4", socks4Connect([4]byte{203, 0, 113, 5}, 9050, "")},
	}
	for _, stream := range streams {
		stream := stream
		t.Run(stream.name, func(t *testing.T) {
			harness := newInboundHarness(t, nil)
			conn := newScriptedConn(stream.data)
			harness.newConnection(context.Background(), conn, nil)
			routed := harness.router.waitConnection(t)

			got := make([]byte, 64)
			n, err := routed.conn.Read(got)
			if n != 0 {
				t.Fatalf("phantom payload %x", got[:n])
			}
			if err == nil {
				t.Fatal("expected an error from an exhausted connection")
			}
		})
	}
}

// TestPayloadArrivingAfterHandoffIsNotSwallowed proves the other half: bytes
// that arrive AFTER the hand-off must reach the tunnel too, so the wrapper's
// capture cannot be mistaken for "everything the client will ever send".
func TestPayloadArrivingAfterHandoffIsNotSwallowed(t *testing.T) {
	late := bytes.Repeat([]byte{0x42}, 64)
	harness := newInboundHarness(t, nil)
	conn := newScriptedConn(socks5NoAuth("example.com", 443))
	conn.onRead = func() {}
	harness.newConnection(context.Background(), conn, nil)
	routed := harness.router.waitConnection(t)

	conn.mu.Lock()
	conn.payload = append(conn.payload, late...)
	conn.done = false
	conn.mu.Unlock()

	got, err := readExact(routed.conn, len(late))
	if err != nil {
		t.Fatalf("read late payload: %v (got %d/%d)", err, len(got), len(late))
	}
	if !bytes.Equal(got, late) {
		t.Fatalf("late payload mismatch\n got: %x\nwant: %x", got, late)
	}
}

// readPlanFor builds a read plan that delivers the stream in fixed-size chunks.
func readPlanFor(size int) []int {
	var plan []int
	for i := 0; i < 4096; i++ {
		plan = append(plan, size)
	}
	return plan
}

// tlsClientHelloLike returns a plausible TLS ClientHello-shaped payload.
func tlsClientHelloLike(size int) []byte {
	out := make([]byte, size)
	out[0] = 0x16
	out[1] = 0x03
	out[2] = 0x01
	out[3] = byte((size - 5) >> 8)
	out[4] = byte(size - 5)
	if size > 5 {
		out[5] = 0x01
	}
	for i := 6; i < size; i++ {
		out[i] = byte(i * 7)
	}
	return out
}

var _ = N.NetworkTCP
