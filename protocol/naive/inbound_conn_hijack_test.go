package naive

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestHijackedConnReturnsBufferedBytes covers the bytes net/http has already read past the
// end of a CONNECT request when the handler hijacks the connection.
//
// The reader returned by Hijack can hold the start of the tunnel payload, because the HTTP
// parser reads ahead. Reading only from the underlying connection loses those bytes and
// desynchronises the tunnel from its first payload.
func TestHijackedConnReturnsBufferedBytes(t *testing.T) {
	t.Parallel()

	const payload = "EARLY-TUNNEL-BYTES"

	// The reader holds bytes the parser already consumed, which is the state Hijack can
	// return; nothing else is written to the connection.
	buffered := bufio.NewReaderSize(bytes.NewReader([]byte(payload)), len(payload))
	// bufio fills lazily, so Buffered() is 0 until a read forces it. Hijack returns a
	// reader the HTTP parser has ALREADY read into, so the fill is forced here to reach
	// the state the production path actually receives.
	_, err := buffered.Peek(len(payload))
	require.NoError(t, err)
	require.Equal(t, len(payload), buffered.Buffered())

	conn := &deadlineConn{}

	tunnel := hijackedConn(conn, &bufio.ReadWriter{Reader: buffered})

	require.NoError(t, tunnel.SetReadDeadline(time.Now().Add(2*time.Second)))
	buffer := make([]byte, len(payload)+16)
	n, err := tunnel.Read(buffer)
	require.NoError(t, err,
		"the buffered bytes must be readable from the tunnel: they were read from the "+
			"socket and would otherwise be lost")
	require.Equal(t, payload, string(buffer[:n]))

	// Once the buffer is drained the tunnel must read from the connection.
	conn.write([]byte("later"))
	n, err = tunnel.Read(buffer)
	require.NoError(t, err, "the tunnel must fall through to the connection")
	require.Equal(t, "later", string(buffer[:n]))
}

// TestHijackedConnWithoutBufferedBytesReturnsTheConnection is the control: a hijack with
// nothing buffered must behave exactly as before.
func TestHijackedConnWithoutBufferedBytesReturnsTheConnection(t *testing.T) {
	t.Parallel()

	conn := &deadlineConn{}
	empty := bufio.NewReader(bytes.NewReader(nil))

	tunnel := hijackedConn(conn, &bufio.ReadWriter{Reader: empty})
	require.Same(t, net.Conn(conn), tunnel,
		"with nothing buffered the connection must be returned unchanged")

	// A nil ReadWriter must also be tolerated, since Hijack is not required to return one.
	require.Same(t, net.Conn(conn), hijackedConn(conn, nil))
}

// deadlineConn is a minimal net.Conn whose reads are fed by the test.
type deadlineConn struct {
	net.Conn
	feed chan byte
}

// Read drains whatever the test has fed, blocking only when nothing is queued, so it
// behaves like a socket rather than returning a single byte per call.
func (c *deadlineConn) Read(p []byte) (int, error) {
	if c.feed == nil {
		c.feed = make(chan byte, 64)
	}
	n := 0
	for n < len(p) {
		select {
		case b := <-c.feed:
			p[n] = b
			n++
			continue
		default:
		}
		break
	}
	if n > 0 {
		return n, nil
	}
	select {
	case b := <-c.feed:
		p[0] = b
		return 1, nil
	case <-time.After(2 * time.Second):
		return 0, io.EOF
	}
}

func (c *deadlineConn) write(data []byte) {
	if c.feed == nil {
		c.feed = make(chan byte, 64)
	}
	for _, b := range data {
		c.feed <- b
	}
}

func (c *deadlineConn) Close() error                     { return nil }
func (c *deadlineConn) LocalAddr() net.Addr              { return testAddr{} }
func (c *deadlineConn) RemoteAddr() net.Addr             { return testAddr{} }
func (c *deadlineConn) SetDeadline(time.Time) error      { return nil }
func (c *deadlineConn) SetReadDeadline(time.Time) error  { return nil }
func (c *deadlineConn) SetWriteDeadline(time.Time) error { return nil }
func (c *deadlineConn) Write(p []byte) (int, error)      { return len(p), nil }

type testAddr struct{}

func (testAddr) Network() string { return "test" }
func (testAddr) String() string  { return "test" }
