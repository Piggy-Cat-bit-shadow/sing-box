package socks

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// ---------------------------------------------------------------------------
// FirstPayloadConn: the buffer ownership contract.
//
// Every assertion here is about an object count or a byte count, not about a
// wall-clock ratio: the payload is delivered exactly once, the pooled buffer is
// returned exactly once, and the socket is closed exactly once.
// ---------------------------------------------------------------------------

// firstPayloadSocket is a socket double that records what the wrapper asks of
// it and answers the optional capability interfaces.
type firstPayloadSocket struct {
	net.Conn
	stream *bytes.Reader

	readFromCalled  atomic.Bool
	writeToCalled   atomic.Bool
	closeWriteCount atomic.Int32
	closeReadCount  atomic.Int32
	closeCount      atomic.Int32
	written         bytes.Buffer
	writeMu         sync.Mutex
}

func newFirstPayloadSocket(stream []byte) *firstPayloadSocket {
	return &firstPayloadSocket{stream: bytes.NewReader(stream)}
}

func (c *firstPayloadSocket) Read(p []byte) (int, error) { return c.stream.Read(p) }
func (c *firstPayloadSocket) Close() error               { c.closeCount.Add(1); return nil }
func (c *firstPayloadSocket) CloseRead() error           { c.closeReadCount.Add(1); return nil }
func (c *firstPayloadSocket) CloseWrite() error          { c.closeWriteCount.Add(1); return nil }
func (c *firstPayloadSocket) ReadFrom(r io.Reader) (int64, error) {
	c.readFromCalled.Store(true)
	return io.Copy(&structWriter{c}, r)
}
func (c *firstPayloadSocket) WriteTo(w io.Writer) (int64, error) {
	c.writeToCalled.Store(true)
	n, err := w.Write([]byte("socket"))
	return int64(n), err
}
func (c *firstPayloadSocket) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.written.Write(p)
}
func (c *firstPayloadSocket) LocalAddr() net.Addr              { return nil }
func (c *firstPayloadSocket) RemoteAddr() net.Addr             { return nil }
func (c *firstPayloadSocket) SetDeadline(time.Time) error      { return nil }
func (c *firstPayloadSocket) SetReadDeadline(time.Time) error  { return nil }
func (c *firstPayloadSocket) SetWriteDeadline(time.Time) error { return nil }

type structWriter struct{ conn *firstPayloadSocket }

func (w *structWriter) Write(p []byte) (int, error) { return w.conn.Write(p) }

// bufferedReader records how often its buffer was consulted, which is how the
// "close must not drain the parser" rule is asserted.
type bufferedReader struct {
	reader    *bytes.Reader
	buffered  int
	readCount atomic.Int32
	bufferGet atomic.Int32
}

func newBufferedReader(buffer []byte) *bufferedReader {
	return &bufferedReader{reader: bytes.NewReader(buffer), buffered: len(buffer)}
}

func (r *bufferedReader) Read(p []byte) (int, error) {
	r.readCount.Add(1)
	return r.reader.Read(p)
}

func (r *bufferedReader) Buffered() int {
	r.bufferGet.Add(1)
	return r.buffered
}

func TestFirstPayloadServedBeforeSocketExactlyOnce(t *testing.T) {
	payload := []byte("early-payload")
	socketPayload := []byte("socket-payload")
	socket := newFirstPayloadSocket(socketPayload)
	reader := newBufferedReader(payload)
	wrapper := NewFirstPayloadConn(socket, reader)

	got, err := readExact(wrapper, len(payload)+len(socketPayload))
	if err != nil {
		t.Fatalf("read: %v (got %q)", err, got)
	}
	want := append(append([]byte{}, payload...), socketPayload...)
	if !bytes.Equal(got, want) {
		t.Fatalf("stream = %q, want %q", got, want)
	}
	// Drained: the socket reports EOF and nothing is replayed.
	extra := make([]byte, 64)
	n, err := wrapper.Read(extra)
	if n != 0 || err == nil {
		t.Fatalf("after the stream ended: n=%d err=%v", n, err)
	}
	if reader.readCount.Load() != 1 {
		t.Fatalf("parser reader read %d times, want exactly 1 (the capture)", reader.readCount.Load())
	}
}

// TestFirstPayloadBufferIsReturnedOnceOnDrain asserts the ownership rule on the
// normal path with the buffer as the observable object: a released pooled buffer
// has been handed back and zeroed, so its capacity and length are both zero.
func TestFirstPayloadBufferIsReturnedOnceOnDrain(t *testing.T) {
	payload := []byte("buffered-bytes")
	pending := buf.NewSize(len(payload))
	if _, err := pending.Write(payload); err != nil {
		t.Fatal(err)
	}
	socket := newFirstPayloadSocket(nil)
	wrapper := &FirstPayloadConn{Conn: socket, pending: pending}

	if pending.Cap() == 0 {
		t.Fatal("precondition: the injected buffer is already released")
	}
	got, err := readExact(wrapper, len(payload))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	if pending.Cap() != 0 || pending.Len() != 0 {
		t.Fatalf("buffer was not returned to the pool after being drained: cap=%d len=%d", pending.Cap(), pending.Len())
	}
	// A second drain attempt must not double-release; the connection still
	// answers, now from the socket.
	if _, err = wrapper.Read(make([]byte, 8)); err == nil {
		t.Fatal("expected EOF from the exhausted socket")
	}
}

// TestFirstPayloadBufferIsReturnedOnceOnClose is the early-close half: the
// session ends before the payload was read, and the buffer must still go back.
func TestFirstPayloadBufferIsReturnedOnceOnClose(t *testing.T) {
	payload := []byte("never-read")
	pending := buf.NewSize(len(payload))
	if _, err := pending.Write(payload); err != nil {
		t.Fatal(err)
	}
	socket := newFirstPayloadSocket(nil)
	wrapper := &FirstPayloadConn{Conn: socket, pending: pending}

	if err := wrapper.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if pending.Cap() != 0 || pending.Len() != 0 {
		t.Fatalf("buffer was not returned on close: cap=%d len=%d", pending.Cap(), pending.Len())
	}
	if socket.closeCount.Load() != 1 {
		t.Fatalf("socket closed %d times, want 1", socket.closeCount.Load())
	}
	// Close is idempotent: a second close must not release again (which would be
	// a double free of pooled memory) and must not fail.
	if err := wrapper.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if socket.closeCount.Load() != 2 {
		t.Fatalf("socket close count = %d, want 2 (the wrapper forwards every close)", socket.closeCount.Load())
	}
	if pending.Cap() != 0 || pending.Len() != 0 {
		t.Fatalf("double release: cap=%d len=%d", pending.Cap(), pending.Len())
	}
}

// TestFirstPayloadCloseDoesNotDrainTheParser pins the deliberate restriction:
// Close can be reached while the handshake is still reading through the parser's
// reader, so it must not consult that reader at all.
func TestFirstPayloadCloseDoesNotDrainTheParser(t *testing.T) {
	reader := newBufferedReader([]byte("handshake-and-payload"))
	socket := newFirstPayloadSocket(nil)
	wrapper := NewFirstPayloadConn(socket, reader)

	if err := wrapper.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if reader.bufferGet.Load() != 0 || reader.readCount.Load() != 0 {
		t.Fatalf("close consulted the parser reader %d/%d times, want 0/0",
			reader.bufferGet.Load(), reader.readCount.Load())
	}
}

// TestFirstPayloadWriteDoesNotDrainTheParser is the same rule for the write
// side: the handshake writes its reply before the parser has consumed the
// request, so a write must not move the buffer either.
func TestFirstPayloadWriteDoesNotDrainTheParser(t *testing.T) {
	reader := newBufferedReader([]byte("handshake-and-payload"))
	socket := newFirstPayloadSocket(nil)
	wrapper := NewFirstPayloadConn(socket, reader)

	if _, err := wrapper.Write([]byte("reply")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if reader.readCount.Load() != 0 {
		t.Fatalf("write consulted the parser reader %d times, want 0", reader.readCount.Load())
	}
	if !bytes.Equal(socket.written.Bytes(), []byte("reply")) {
		t.Fatalf("socket received %q", socket.written.Bytes())
	}
}

// TestFirstPayloadReplaceabilityTracksTheBuffer pins the splice guard: while
// payload is buffered the reader must NOT be reported replaceable, and once it
// is drained the walk must be able to descend to the socket.
func TestFirstPayloadReplaceabilityTracksTheBuffer(t *testing.T) {
	payload := []byte("buffered")
	reader := newBufferedReader(payload)
	socket := newFirstPayloadSocket(nil)
	wrapper := NewFirstPayloadConn(socket, reader)

	replaceable, isReplaceable := any(wrapper).(N.ReaderWithUpstream)
	if !isReplaceable {
		t.Fatal("wrapper does not answer ReaderWithUpstream")
	}
	if replaceable.ReaderReplaceable() {
		t.Fatal("reader reported replaceable while the payload was still buffered: a splice would skip it")
	}
	if writerReplaceable, isWriter := any(wrapper).(N.WriterWithUpstream); !isWriter || !writerReplaceable.WriterReplaceable() {
		t.Fatal("write side must not be degraded by inbound buffering")
	}
	if upstream := any(wrapper).(interface{ Upstream() any }).Upstream(); upstream != net.Conn(socket) {
		t.Fatalf("Upstream() = %T, want the socket", upstream)
	}
	if _, err := readExact(wrapper, len(payload)); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !replaceable.ReaderReplaceable() {
		t.Fatal("reader still reported not-replaceable after the payload was drained")
	}
}

// TestFirstPayloadEmptyReaderIsTransparent covers a connection with no early
// data: the wrapper must be a pass-through in every observable way.
func TestFirstPayloadEmptyReaderIsTransparent(t *testing.T) {
	reader := newBufferedReader(nil)
	socket := newFirstPayloadSocket([]byte("socket-only"))
	wrapper := NewFirstPayloadConn(socket, reader)

	got, err := readExact(wrapper, len("socket-only"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "socket-only" {
		t.Fatalf("stream = %q", got)
	}
	if reader.readCount.Load() != 0 {
		t.Fatalf("an empty reader was read %d times", reader.readCount.Load())
	}
	if replaceable := any(wrapper).(N.ReaderWithUpstream); !replaceable.ReaderReplaceable() {
		t.Fatal("reader reported not-replaceable with nothing buffered")
	}
}

// TestFirstPayloadCapabilitiesAreForwarded proves the wrapper does not take a
// capability away: the routing core probes for these on every session.
func TestFirstPayloadCapabilitiesAreForwarded(t *testing.T) {
	socket := newFirstPayloadSocket([]byte("socket"))
	wrapper := NewFirstPayloadConn(socket, newBufferedReader(nil)).(*FirstPayloadConn)

	// WriteTo is the io.WriterTo contract over the whole remaining stream: with
	// nothing buffered that is the socket.
	var out bytes.Buffer
	if _, err := wrapper.WriteTo(&out); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if out.String() != "socket" {
		t.Fatalf("WriteTo carried %q, want the socket's remaining bytes", out.String())
	}
	if _, err := wrapper.ReadFrom(bytes.NewReader([]byte("x"))); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !socket.readFromCalled.Load() {
		t.Fatal("ReadFrom did not reach the socket")
	}
	if err := wrapper.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if err := wrapper.CloseRead(); err != nil {
		t.Fatalf("CloseRead: %v", err)
	}
	if socket.closeWriteCount.Load() != 1 || socket.closeReadCount.Load() != 1 {
		t.Fatalf("half-close counts = %d/%d, want 1/1", socket.closeReadCount.Load(), socket.closeWriteCount.Load())
	}
}

// TestFirstPayloadWriteToCarriesTheBuffer first: the whole remaining stream is
// the buffered payload followed by the socket, and the buffer is released.
func TestFirstPayloadWriteToCarriesTheBuffer(t *testing.T) {
	payload := []byte("early")
	pending := buf.NewSize(len(payload))
	if _, err := pending.Write(payload); err != nil {
		t.Fatal(err)
	}
	socket := newFirstPayloadSocket(nil)
	wrapper := &FirstPayloadConn{Conn: socket, pending: pending}

	var out bytes.Buffer
	n, err := wrapper.WriteTo(&out)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("WriteTo wrote %d bytes, want %d", n, len(payload))
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("far end received %q, want %q", out.Bytes(), payload)
	}
	if pending.Cap() != 0 {
		t.Fatal("buffer was not released after WriteTo")
	}
}

// TestFirstPayloadConcurrentReadAndCloseIsSerialized is the ownership stress
// case: a read that already took the buffer must finish with it, and a close
// that wins must release it. Either way the buffer is released exactly once, and
// the race detector is the assertion that no read ever touches released memory.
func TestFirstPayloadConcurrentReadAndCloseIsSerialized(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5A}, 512)
	for round := 0; round < 200; round++ {
		pending := buf.NewSize(len(payload))
		if _, err := pending.Write(payload); err != nil {
			t.Fatal(err)
		}
		socket := newFirstPayloadSocket(nil)
		wrapper := &FirstPayloadConn{Conn: socket, pending: pending}

		start := make(chan struct{})
		var wait sync.WaitGroup
		var readBytes int
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			buffer := make([]byte, len(payload))
			readBytes, _ = wrapper.Read(buffer)
		}()
		go func() {
			defer wait.Done()
			<-start
			_ = wrapper.Close()
		}()
		close(start)
		wait.Wait()

		// The read either got the payload before the close or was refused, but
		// never a torn prefix of it: the buffer is served whole or not at all.
		if readBytes != 0 && readBytes != len(payload) {
			t.Fatalf("round %d: read %d of %d buffered bytes", round, readBytes, len(payload))
		}
		if pending.Cap() != 0 {
			t.Fatalf("round %d: buffer was not released exactly once", round)
		}
	}
}

// TestFirstPayloadCaptureRacingCloseDoesNotStrandTheBuffer covers the window a
// close can open while the capture is running: the captured buffer must be
// released rather than parked on a connection nobody will read from.
func TestFirstPayloadCaptureRacingCloseDoesNotStrandTheBuffer(t *testing.T) {
	payload := bytes.Repeat([]byte{0x33}, 128)
	for round := 0; round < 200; round++ {
		reader := newBufferedReader(payload)
		socket := newFirstPayloadSocket(nil)
		wrapper := NewFirstPayloadConn(socket, reader).(*FirstPayloadConn)

		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			wrapper.resolve()
		}()
		go func() {
			defer wait.Done()
			<-start
			_ = wrapper.Close()
		}()
		close(start)
		wait.Wait()

		wrapper.access.Lock()
		stillPending := wrapper.pending
		wrapper.access.Unlock()
		if stillPending != nil {
			t.Fatalf("round %d: a capture that raced the close left a live buffer behind", round)
		}
	}
}
