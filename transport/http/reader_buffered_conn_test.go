package http

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Reader.BufferedConn is the primitive every parser uses to hand its pre-read
// payload to the routing layer. Its contract is narrow and easy to get wrong in
// two opposite directions:
//
//   - moving the buffer too EARLY replays the handshake, because Peek does not
//     consume;
//   - moving it too LATE, or not at all, silently truncates the tunnel.
//
// These tests pin the exact boundary.
// ---------------------------------------------------------------------------

// scriptedReaderConn serves a fixed stream and counts what it has handed out.
type scriptedReaderConn struct {
	stream    []byte
	offset    int
	delivered int
}

func (c *scriptedReaderConn) Read(p []byte) (int, error) {
	if c.offset >= len(c.stream) {
		return 0, io.EOF
	}
	n := copy(p, c.stream[c.offset:])
	c.offset += n
	c.delivered += n
	return n, nil
}

func (c *scriptedReaderConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *scriptedReaderConn) Close() error                { return nil }
func (c *scriptedReaderConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *scriptedReaderConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *scriptedReaderConn) SetDeadline(time.Time) error { return nil }
func (c *scriptedReaderConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *scriptedReaderConn) SetWriteDeadline(time.Time) error { return nil }

func TestBufferedConnIsNilWhenNothingIsBuffered(t *testing.T) {
	conn := &scriptedReaderConn{stream: []byte("a")}
	reader := NewReader(conn)
	if cached := reader.BufferedConn(conn); cached != nil {
		t.Fatal("BufferedConn must be nil when nothing has been buffered")
	}
}

func TestBufferedConnAfterPeekMovesThePeekedByteToo(t *testing.T) {
	// This is the trap: Peek does NOT consume, so after a Peek the buffer still
	// contains the peeked byte. A caller that moves it before the parser has
	// consumed it steals the parser's input.
	conn := &scriptedReaderConn{stream: []byte("HELLO")}
	reader := NewReader(conn)
	head, err := reader.Peek(1)
	if err != nil {
		t.Fatal(err)
	}
	if head[0] != 'H' {
		t.Fatalf("peek = %q", head)
	}
	cached := reader.BufferedConn(conn)
	if cached == nil {
		t.Fatal("expected a cached connection")
	}
	moved, err := io.ReadAll(cached)
	if err != nil {
		t.Fatal(err)
	}
	if string(moved) != "HELLO" {
		t.Fatalf("moved %q, want %q", moved, "HELLO")
	}
	// Only one copy of the stream exists.
	if conn.delivered != len(conn.stream) {
		t.Fatalf("transport delivered %d bytes for a %d byte stream", conn.delivered, len(conn.stream))
	}
}

func TestBufferedConnMovesOnlyTheUnconsumedRemainder(t *testing.T) {
	// After the parser has consumed the handshake, the buffer holds exactly the
	// payload, and that is what must move.
	conn := &scriptedReaderConn{stream: []byte("HANDSHAKEpayload")}
	reader := NewReader(conn)
	if _, err := reader.Peek(1); err != nil {
		t.Fatal(err)
	}
	handshake := make([]byte, len("HANDSHAKE"))
	if _, err := io.ReadFull(reader, handshake); err != nil {
		t.Fatal(err)
	}
	if string(handshake) != "HANDSHAKE" {
		t.Fatalf("handshake = %q", handshake)
	}
	cached := reader.BufferedConn(conn)
	if cached == nil {
		t.Fatal("expected a cached connection")
	}
	payload, err := io.ReadAll(cached)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "payload" {
		t.Fatalf("payload = %q, want %q", payload, "payload")
	}
	if conn.delivered != len(conn.stream) {
		t.Fatalf("transport delivered %d bytes, want %d", conn.delivered, len(conn.stream))
	}
}

func TestBufferedConnFallsThroughToTheTransport(t *testing.T) {
	// The cached connection must serve the buffered bytes first and then the
	// socket. A cached connection that stops at the buffer would hang the
	// tunnel after the pre-read payload ran out.
	conn := &scriptedReaderConn{stream: []byte("AB")}
	reader := NewReader(conn)
	if _, err := reader.Peek(1); err != nil {
		t.Fatal(err)
	}
	reader.ReadByte()
	cached := reader.BufferedConn(conn)
	if cached == nil {
		t.Fatal("expected a cached connection")
	}
	// Append what the transport still owes.
	conn.stream = append(conn.stream, []byte("CD")...)
	all, err := io.ReadAll(cached)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(all, []byte("BCD")) {
		t.Fatalf("read %q, want %q", all, "BCD")
	}
}

func TestReaderPeekDoesNotLoseBytes(t *testing.T) {
	stream := []byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	for _, plan := range []int{1, 2, 7, len(stream)} {
		conn := &scriptedReaderConn{stream: stream}
		reader := NewReader(conn)
		for consumed := 0; consumed < len(stream); {
			head, err := reader.Peek(1)
			if err != nil {
				t.Fatalf("plan %d: peek: %v", plan, err)
			}
			if head[0] != stream[consumed] {
				t.Fatalf("plan %d: peek = %q at %d, want %q", plan, head[0], consumed, stream[consumed])
			}
			size := min(plan, len(stream)-consumed)
			chunk := make([]byte, size)
			if _, err := io.ReadFull(reader, chunk); err != nil {
				t.Fatalf("plan %d: read: %v", plan, err)
			}
			if !bytes.Equal(chunk, stream[consumed:consumed+size]) {
				t.Fatalf("plan %d: chunk at %d = %q", plan, consumed, chunk)
			}
			consumed += size
		}
	}
}

func TestReadLimiterRejectsOversizedInput(t *testing.T) {
	// The header limit feeds max_header_bytes, so it has to hold even when the
	// stream is much larger than any single read.
	conn := &scriptedReaderConn{stream: bytes.Repeat([]byte{'x'}, 4096)}
	reader := NewReader(conn)
	reader.setLimit(64)
	buffer := make([]byte, 256)
	var total int
	for {
		n, err := reader.Read(buffer)
		total += n
		if err != nil {
			if err != errHeaderTooLarge {
				t.Fatalf("err = %v, want errHeaderTooLarge", err)
			}
			break
		}
		if total > 4096 {
			t.Fatal("limit was not enforced")
		}
	}
	if total != 64 {
		t.Fatalf("read %d bytes before the limit fired, want 64", total)
	}
}
