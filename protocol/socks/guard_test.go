package socks

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// GuardSOCKS5Address has to satisfy four things that a happy-path test cannot
// establish on its own:
//
//	it rejects the zero-length domain,
//	it passes every legal stream through byte for byte,
//	it never waits for bytes the client has not sent, and
//	it does not hide the transport's optional capabilities.
//
// The third is why the guard exists at all: SOCKS5 negotiation is a round trip,
// so the request is not on the wire when the inbound could inspect the stream. A
// check that had to wait for it deadlocked curl before the greeting reply was
// written.
// ---------------------------------------------------------------------------

// wires builds a SOCKS5 greeting, an optional RFC 1929 sub-negotiation and a
// request with the given ATYP/address bytes.
func wires(auth bool, address []byte) []byte {
	var out []byte
	if auth {
		out = append(out, 0x05, 0x02, 0x00, 0x02)
		out = append(out, 0x01, 4)
		out = append(out, "user"...)
		out = append(out, 4)
		out = append(out, "pass"...)
	} else {
		out = append(out, 0x05, 0x01, 0x00)
	}
	out = append(out, 0x05, 0x01, 0x00)
	return append(out, address...)
}

func domainAddress(host string, port uint16) []byte {
	out := []byte{0x03, byte(len(host))}
	out = append(out, host...)
	return append(out, byte(port>>8), byte(port))
}

// greetThenBlock models a real client at the moment the inbound could look: the
// greeting has arrived and the request will not be sent until the greeting has
// been answered.
type greetThenBlock struct {
	head    []byte
	offset  int
	release chan struct{}
}

func (c *greetThenBlock) Read(p []byte) (int, error) {
	if c.offset < len(c.head) {
		n := copy(p, c.head[c.offset:])
		c.offset += n
		return n, nil
	}
	<-c.release
	return 0, io.EOF
}

func (c *greetThenBlock) Write(p []byte) (int, error) { return len(p), nil }
func (c *greetThenBlock) Close() error                { return nil }
func (c *greetThenBlock) LocalAddr() net.Addr         { return nil }
func (c *greetThenBlock) RemoteAddr() net.Addr        { return nil }
func (c *greetThenBlock) SetDeadline(time.Time) error { return nil }
func (c *greetThenBlock) SetReadDeadline(time.Time) error {
	return nil
}
func (c *greetThenBlock) SetWriteDeadline(time.Time) error { return nil }

// TestGuardNeverWaitsForTheRequest is the deadlock regression: the guard must
// not block on a connection whose request has not been sent yet.
func TestGuardNeverWaitsForTheRequest(t *testing.T) {
	base := &greetThenBlock{head: []byte{0x05, 0x01, 0x00}, release: make(chan struct{})}
	guarded := GuardSOCKS5Address(base)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 64)
		if _, err := guarded.Read(buffer); err != nil {
			t.Errorf("guarded read failed: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(base.release)
		t.Fatal("guard blocked waiting for a request the client has not sent")
	}
	close(base.release)
}

// TestGuardRejectsEmptyDomainWithAuthAndWithout covers both sub-negotiation
// shapes, since the two put the address length at different offsets.
func TestGuardRejectsEmptyDomain(t *testing.T) {
	for _, auth := range []bool{false, true} {
		stream := wires(auth, domainAddress("", 80))
		guarded := GuardSOCKS5Address(newBufferConn(stream))
		_, err := io.ReadAll(guarded)
		if !errors.Is(err, errEmptyDomain) {
			t.Fatalf("auth=%v: err = %v, want errEmptyDomain", auth, err)
		}
	}
}

// TestGuardPassesLegalStreamsThrough is the counterweight, and it also pins the
// exact bytes: the guard must not alter, drop or duplicate anything.
func TestGuardPassesLegalStreamsThrough(t *testing.T) {
	cases := []struct {
		name    string
		auth    bool
		address []byte
		payload string
	}{
		{"domain", false, domainAddress("example.com", 443), "early payload"},
		{"domain-one-byte", false, domainAddress("a", 1), ""},
		{"domain-255", false, append([]byte{0x03, 255}, append(bytes.Repeat([]byte{'a'}, 255), 0x01, 0xbb)...), "x"},
		{"ipv4", false, []byte{0x01, 192, 0, 2, 1, 0x01, 0xbb}, "y"},
		{"ipv6", false, append([]byte{0x04}, append(bytes.Repeat([]byte{0x20}, 16), 0x01, 0xbb)...), "z"},
		{"domain-auth", true, domainAddress("example.com", 443), "w"},
		{"ipv4-auth", true, []byte{0x01, 192, 0, 2, 1, 0x01, 0xbb}, "v"},
		// A client that offers username/password against an inbound with no users
		// is answered AuthTypeNotRequired, so no sub-negotiation happens even
		// though the greeting advertised it.
		{"auth-offered-but-not-selected", false, domainAddress("example.com", 443), "u"},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			var stream []byte
			if testCase.name == "auth-offered-but-not-selected" {
				stream = []byte{0x05, 0x02, 0x00, 0x02}
			} else {
				stream = wires(testCase.auth, nil)
			}
			stream = append(stream, 0x05, 0x01, 0x00)
			stream = append(stream, testCase.address...)
			stream = append(stream, testCase.payload...)

			got, err := io.ReadAll(GuardSOCKS5Address(newBufferConn(stream)))
			if err != nil {
				t.Fatalf("legal stream rejected: %v", err)
			}
			if !bytes.Equal(got, stream) {
				t.Fatalf("stream altered\n got: %x\nwant: %x", got, stream)
			}
		})
	}
}

// TestGuardIsFragmentationInvariant drives every stream one byte at a time, so
// the scanner cannot rely on the whole field arriving in one Read.
func TestGuardIsFragmentationInvariant(t *testing.T) {
	cases := []struct {
		name   string
		stream []byte
		reject bool
	}{
		{"valid-domain", wires(false, domainAddress("example.com", 443)), false},
		{"empty-domain", wires(false, domainAddress("", 80)), true},
		{"valid-domain-auth", wires(true, domainAddress("example.com", 443)), false},
		{"empty-domain-auth", wires(true, domainAddress("", 80)), true},
	}
	for _, testCase := range cases {
		testCase := testCase
		for _, size := range []int{1, 2, 3, 7, len(testCase.stream)} {
			size := size
			guarded := GuardSOCKS5Address(&dripConn{stream: testCase.stream, size: size})
			got, err := io.ReadAll(guarded)
			if testCase.reject {
				if !errors.Is(err, errEmptyDomain) {
					t.Fatalf("%s size=%d: err = %v, want errEmptyDomain", testCase.name, size, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s size=%d: legal stream rejected: %v", testCase.name, size, err)
			}
			if !bytes.Equal(got, testCase.stream) {
				t.Fatalf("%s size=%d: stream altered", testCase.name, size)
			}
		}
	}
}

// TestGuardLeavesOtherShapesAlone pins the boundary: this guard exists to catch
// ONE shape, and every other malformed stream must still be reported by the
// parser that owns it.
func TestGuardLeavesOtherShapesAlone(t *testing.T) {
	cases := []struct {
		name   string
		stream []byte
	}{
		{"empty", nil},
		{"version-only", []byte{0x05}},
		{"truncated-methods", []byte{0x05, 0x02, 0x00}},
		{"not-socks5", []byte{0x04, 0x01, 0x00, 0x50}},
		{"greeting-only", []byte{0x05, 0x01, 0x00}},
		{"unsupported-atyp", wires(false, []byte{0x09, 1, 2, 3, 4, 0, 80})},
		{"truncated-domain", wires(false, []byte{0x03, 200, 'a', 'b'})},
		{"truncated-auth", []byte{0x05, 0x02, 0x00, 0x02, 0x01, 200, 'a'}},
		{"zero-methods", []byte{0x05, 0x00}},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			_, err := io.ReadAll(GuardSOCKS5Address(newBufferConn(testCase.stream)))
			if err != nil {
				t.Fatalf("guard claimed a stream it does not own: %v", err)
			}
		})
	}
}

// TestGuardPreservesCapabilities proves the guard does not hide the transport's
// optional interfaces behind a bare net.Conn. The shared core probes for these
// by type assertion, and a wrapper that answers none of them silently disables
// the zero-copy and splice paths -- which costs more than the guard saves.
func TestGuardPreservesCapabilities(t *testing.T) {
	guarded := GuardSOCKS5Address(newCapabilityConn(nil))
	if _, ok := guarded.(io.ReaderFrom); !ok {
		t.Fatal("io.ReaderFrom lost")
	}
	if _, ok := guarded.(io.WriterTo); !ok {
		t.Fatal("io.WriterTo lost")
	}
	if _, ok := guarded.(interface{ CloseWrite() error }); !ok {
		t.Fatal("CloseWrite lost")
	}
	if _, ok := guarded.(interface {
		CloseRead() error
		CloseWrite() error
	}); !ok {
		t.Fatal("half-close lost")
	}
	if _, ok := guarded.(interface{ Upstream() any }); !ok {
		t.Fatal("Upstream lost")
	}
}

// ---------------------------------------------------------------------------
// doubles
// ---------------------------------------------------------------------------

// bufferConn is a net.Conn over a byte slice, so the guard can be driven without
// a socket.
type bufferConn struct {
	stream []byte
	offset int
}

func newBufferConn(stream []byte) *bufferConn {
	return &bufferConn{stream: stream}
}

func (c *bufferConn) Read(p []byte) (int, error) {
	if c.offset >= len(c.stream) {
		return 0, io.EOF
	}
	n := copy(p, c.stream[c.offset:])
	c.offset += n
	return n, nil
}

func (c *bufferConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *bufferConn) Close() error                { return nil }
func (c *bufferConn) LocalAddr() net.Addr         { return nil }
func (c *bufferConn) RemoteAddr() net.Addr        { return nil }
func (c *bufferConn) SetDeadline(time.Time) error { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

// capabilityConn offers every optional interface the guard is expected to keep
// reachable.
type capabilityConn struct {
	*bufferConn
}

func newCapabilityConn(stream []byte) *capabilityConn {
	return &capabilityConn{bufferConn: newBufferConn(stream)}
}

func (c *capabilityConn) ReadFrom(r io.Reader) (int64, error) { return 0, nil }
func (c *capabilityConn) WriteTo(w io.Writer) (int64, error)  { return 0, nil }
func (c *capabilityConn) CloseRead() error                    { return nil }
func (c *capabilityConn) CloseWrite() error                   { return nil }
func (c *capabilityConn) ReaderReplaceable() bool             { return true }
func (c *capabilityConn) WriterReplaceable() bool             { return true }
func (c *capabilityConn) Upstream() any                       { return c.bufferConn }

// dripConn serves a fixed stream in fixed-size pieces, then EOF.
type dripConn struct {
	stream []byte
	offset int
	size   int
}

func (c *dripConn) Read(p []byte) (int, error) {
	if c.offset >= len(c.stream) {
		return 0, io.EOF
	}
	size := min(c.size, len(p))
	if size > len(c.stream)-c.offset {
		size = len(c.stream) - c.offset
	}
	n := copy(p[:size], c.stream[c.offset:c.offset+size])
	c.offset += n
	return n, nil
}

func (c *dripConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *dripConn) Close() error                { return nil }
func (c *dripConn) LocalAddr() net.Addr         { return nil }
func (c *dripConn) RemoteAddr() net.Addr        { return nil }
func (c *dripConn) SetDeadline(time.Time) error { return nil }
func (c *dripConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *dripConn) SetWriteDeadline(time.Time) error { return nil }
