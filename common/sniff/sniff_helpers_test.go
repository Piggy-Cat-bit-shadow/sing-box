package sniff_test

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// scriptedConn is an in-memory net.Conn whose Read hands back one preset chunk per call and then
// reports whatever terminal error the case asked for.
//
// It exists so PeekStream's multi-read loop can be driven deterministically and without a syscall.
// Deadlines are accepted, recorded and otherwise ignored: that is the part of the cost the
// benchmarks here deliberately do not measure, and the part the read-count assertions do not
// depend on. Everything above the syscall - the read loop, the payload view, the parsers and the
// error aggregation - is real.
type scriptedConn struct {
	chunks    [][]byte
	index     int
	reads     int
	deadlines []time.Time
	// terminal is returned once the chunks run out. nil means io.EOF.
	terminal error
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	c.reads++
	if c.index >= len(c.chunks) {
		if c.terminal != nil {
			return 0, c.terminal
		}
		return 0, io.EOF
	}
	n := copy(p, c.chunks[c.index])
	c.index++
	return n, nil
}

// reset rewinds the connection so a benchmark can replay the same chunks without rebuilding it.
func (c *scriptedConn) reset() {
	c.index = 0
	c.reads = 0
	c.deadlines = c.deadlines[:0]
}

func (c *scriptedConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *scriptedConn) Close() error                     { return nil }
func (c *scriptedConn) LocalAddr() net.Addr              { return scriptedAddr{} }
func (c *scriptedConn) RemoteAddr() net.Addr             { return scriptedAddr{} }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

func (c *scriptedConn) SetReadDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	return nil
}

type scriptedAddr struct{}

func (scriptedAddr) Network() string { return "scripted" }
func (scriptedAddr) String() string  { return "scripted" }

// timeoutError is a net.Error that reports a timeout, which is what a real connection returns when
// the sniff read deadline expires.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// captureClientHello returns a real crypto/tls ClientHello, so the cases below parse the bytes a
// browser sends rather than a hand-written approximation of them.
func captureClientHello(tb testing.TB, config *tls.Config) []byte {
	tb.Helper()
	conn := &captureHelloConn{}
	client := tls.Client(conn, config)
	// The handshake cannot finish - the capture conn never answers - but the ClientHello is
	// written before the first read, which is all this needs.
	_ = client.Handshake()
	hello := conn.written.Bytes()
	if len(hello) == 0 || hello[0] != 0x16 {
		tb.Fatal("failed to capture a TLS ClientHello")
	}
	return hello
}

type captureHelloConn struct {
	written bytes.Buffer
}

func (c *captureHelloConn) Read(p []byte) (int, error)       { return 0, io.EOF }
func (c *captureHelloConn) Write(p []byte) (int, error)      { return c.written.Write(p) }
func (c *captureHelloConn) Close() error                     { return nil }
func (c *captureHelloConn) LocalAddr() net.Addr              { return scriptedAddr{} }
func (c *captureHelloConn) RemoteAddr() net.Addr             { return scriptedAddr{} }
func (c *captureHelloConn) SetDeadline(time.Time) error      { return nil }
func (c *captureHelloConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureHelloConn) SetWriteDeadline(time.Time) error { return nil }

func mustHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

// resetSniffResult clears the fields a sniffer is allowed to write. A real flow starts from a zero
// InboundContext; clearing only these four keeps that true without paying for clearing the
// router-owned fields the sniffers never touch.
func resetSniffResult(metadata *adapter.InboundContext) {
	metadata.Protocol = ""
	metadata.Domain = ""
	metadata.Client = ""
	metadata.SniffContext = nil
}

// splitChunks cuts a payload into count consecutive pieces, the way consecutive reads of one
// stream would deliver it.
func splitChunks(payload []byte, count int) [][]byte {
	chunks := make([][]byte, 0, count)
	size := (len(payload) + count - 1) / count
	for start := 0; start < len(payload); start += size {
		end := start + size
		if end > len(payload) {
			end = len(payload)
		}
		chunks = append(chunks, payload[start:end])
	}
	return chunks
}
