package http

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// # The residual this test reproduces
//
// clientStreamConn.Close is bounded for a blocked WRITER: it releases the stream context before it
// closes the response body, and the body close's wait is a select that the context breaks (see
// client_h2_close_test.go). It is NOT bounded when the peer has also delivered tunnel payload that
// nobody has read, and that is a dependency limitation rather than an ordering one.
//
// x/net/http2's transportResponseBody.Close runs this before its context-watching select:
//
//	unread := cs.bufPipe.Len()
//	if unread > 0 {
//	    cc.mu.Lock(); connAdd := cc.inflow.add(unread); cc.mu.Unlock()
//	    // TODO(dneil): Acquiring this mutex can block indefinitely.
//	    cc.wmu.Lock()          // <-- BLOCKS HERE
//	    ...
//	}
//	select { case <-cs.donec: ... case <-cs.ctx.Done(): return nil ... }
//
// cc.wmu is the connection's write mutex, and the request-body writer holds it across
// `cc.fr.WriteData` + `cc.bw.Flush` (http2/transport.go, writeRequestBody). This fork never sets
// http2.Transport.WriteByteTimeout (ConfigureHTTP2Transport leaves it zero), so `cc.bw`'s
// stickyErrWriter calls the socket directly with no deadline: a peer that has stopped reading parks
// that flush with cc.wmu held, and the response-body close waits for it. The context escape is
// unreachable because it is after the lock.
//
// # Upstream status (checked, not assumed)
//
// The pinned golang.org/x/net is v0.57.0. `transportResponseBody.Close` is byte-for-byte identical
// in v0.58.0 and v0.59.0 (the current release), TODO included, so a dependency bump cannot fix it;
// v0.59.0 additionally requires go >= 1.26 and this tree is on go1.25.5. The upstream issue is
// golang/go#48908, "x/net/http2: indefinite hangs when closing response body", still open with the
// first case (flow-control return on a write-blocked conn) unaddressed; the CL that mentions it
// (355491) fixed the second case, closing the request body when aborting a stream.
//
// # Why it cannot be closed from this package
//
//   - Draining first does not avoid cc.wmu: transportResponseBody.Read takes the same mutex to
//     return the tokens for bytes it consumed. And the drain has no bound: bufPipe.Read parks on a
//     sync.Cond when the buffer is empty, and neither its length nor a deadline is exported, so any
//     drain goroutine can wait forever on a silent peer - the immortal waiter this package refuses
//     to detach.
//   - Discarding the unread bytes (skipping the flow-control return) permanently shrinks the
//     connection's receive window, which starves every other stream on the shared connection.
//   - Not reading into the pipe at all is not a choice this package can make; the http2 read loop
//     fills it, and keeping it empty would require buffering the peer's whole window in the tunnel.
//   - Closing the shared ClientConn or its socket unblocks the mutex by destroying every other
//     stream on the connection, which the bounded-writer test already forbids.
//
// So this test PINS the residual instead of asserting a fix: it must FAIL (Close returning inside
// the window) when x/net/http2 finally moves the flow-control return off the write mutex, and the
// doc comment on clientStreamConn.Close should be rewritten when it does.

// unreadH2Conn is the server half of an HTTP/2 connection that answers one CONNECT, delivers one
// DATA frame's worth of tunnel payload, proves the client buffered it, and then stops reading.
//
// The proof is a PING: the client's read loop processes frames in order, so the PING ACK can only
// be written after the DATA frame ahead of it is already in the response body's pipe. Waiting for
// that ACK is what makes "there is unread body here" deterministic rather than a sleep.
type unreadH2Conn struct {
	readCh  chan []byte
	readBuf bytes.Buffer

	writeCh      chan []byte
	drainStopped chan struct{}
	blockedWrite chan struct{}
	blockOnce    sync.Once

	dataDelivered chan struct{}
	deliveredOnce sync.Once

	closed    chan struct{}
	closeOnce sync.Once

	framesRead  atomic.Int64
	typeAccess  sync.Mutex
	types       []string
	countErrors []string
}

func (c *unreadH2Conn) recordType(name string) {
	c.typeAccess.Lock()
	c.types = append(c.types, name)
	c.typeAccess.Unlock()
}

func (c *unreadH2Conn) frameTypes() []string {
	c.typeAccess.Lock()
	defer c.typeAccess.Unlock()
	return append([]string(nil), c.types...)
}

func frameIsAck(frame http2.Frame) bool {
	switch typed := frame.(type) {
	case *http2.PingFrame:
		return typed.IsAck()
	case *http2.SettingsFrame:
		return typed.IsAck()
	default:
		return false
	}
}

func newUnreadH2Conn() *unreadH2Conn {
	conn := &unreadH2Conn{
		readCh:        make(chan []byte, 8),
		writeCh:       make(chan []byte),
		drainStopped:  make(chan struct{}),
		blockedWrite:  make(chan struct{}),
		dataDelivered: make(chan struct{}),
		closed:        make(chan struct{}),
	}
	conn.readCh <- serverSettingsFrame()
	return conn
}

func (c *unreadH2Conn) serve() {
	reader := &h2ChanReader{source: c.writeCh}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(reader, preface); err != nil {
		return
	}
	framer := http2.NewFramer(io.Discard, reader)
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return
		}
		c.framesRead.Add(1)
		c.recordType(fmt.Sprintf("%T ack=%v", frame, frameIsAck(frame)))
		switch typed := frame.(type) {
		case *http2.HeadersFrame:
			// The CONNECT. Answer it, then push tunnel payload the client will never read, then
			// ask for an ACK so the test can be sure the payload is buffered.
			c.readCh <- statusOKHeadersFrame()
			c.readCh <- unreadDataFrame()
			c.readCh <- pingFrame()
		case *http2.PingFrame:
			if typed.IsAck() {
				c.deliveredOnce.Do(func() { close(c.dataDelivered) })
			}
		case *http2.DataFrame:
			// The client started writing tunnel payload. Stop draining, which is the TCP-level
			// picture of a peer whose receive window has closed.
			close(c.drainStopped)
			return
		}
	}
}

func (c *unreadH2Conn) Read(p []byte) (int, error) {
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(p)
	}
	select {
	case data := <-c.readCh:
		c.readBuf.Write(data)
		return c.readBuf.Read(p)
	case <-c.closed:
		return 0, io.EOF
	}
}

func (c *unreadH2Conn) Write(p []byte) (int, error) {
	data := append([]byte(nil), p...)
	select {
	case c.writeCh <- data:
		return len(p), nil
	case <-c.drainStopped:
		c.blockOnce.Do(func() { close(c.blockedWrite) })
	case <-c.closed:
		return 0, net.ErrClosed
	}
	<-c.closed
	return 0, net.ErrClosed
}

func (c *unreadH2Conn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *unreadH2Conn) LocalAddr() net.Addr                { return h2TestAddr{} }
func (c *unreadH2Conn) RemoteAddr() net.Addr               { return h2TestAddr{} }
func (c *unreadH2Conn) SetDeadline(t time.Time) error      { return nil }
func (c *unreadH2Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *unreadH2Conn) SetWriteDeadline(t time.Time) error { return nil }

func unreadDataFrame() []byte {
	// The payload must fit one frame: the client advertises MaxReadFrameSize (16 KiB default) and
	// closes the connection with read_frame_too_large for anything larger. The size only has to be
	// non-zero for the body to have unread bytes; 8 KiB stays inside both the frame size and the
	// initial stream window.
	var frame bytes.Buffer
	err := http2.NewFramer(&frame, nil).WriteData(1, false, make([]byte, 8<<10))
	if err != nil {
		panic(err)
	}
	return frame.Bytes()
}

func pingFrame() []byte {
	var frame bytes.Buffer
	err := http2.NewFramer(&frame, nil).WritePing(false, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		panic(err)
	}
	return frame.Bytes()
}

// TestH2TunnelCloseWithUnreadBodyStaysBlockedBehindABlockedWriter is the deterministic reproducer.
//
// The final wait is the assertion, not padding: "Close does not complete while the write mutex is
// held and the body has unread bytes" is a liveness property, and the only observable form of it is
// that Close has not returned after everything needed to complete it is in place. The test then
// releases the peer and requires Close to return, so it can never leave a goroutine parked.
func TestH2TunnelCloseWithUnreadBodyStaysBlockedBehindABlockedWriter(t *testing.T) {
	t.Parallel()

	fakeConn := newUnreadH2Conn()
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		fakeConn.serve()
	}()
	t.Cleanup(func() {
		_ = fakeConn.Close()
		<-serveDone
	})

	h2Transport, err := httpclient.ConfigureHTTP2Transport(option.HTTP2Options{})
	require.NoError(t, err)
	h2Transport.CountError = func(errType string) {
		fakeConn.typeAccess.Lock()
		fakeConn.countErrors = append(fakeConn.countErrors, errType)
		fakeConn.typeAccess.Unlock()
	}
	clientConn, err := newHTTP2ClientConn(h2Transport, fakeConn)
	require.NoError(t, err)

	client := &Client{}
	destination := M.ParseSocksaddr("target.example:443")
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: destination.String()},
		Host:   destination.String(),
		Header: make(http.Header),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	streamConn, err := client.roundTripHTTP2(ctx, clientConn, request, destination)
	require.NoError(t, err, "the CONNECT must be answered before the writer can stall")

	// The PING ACK proves the read loop already consumed the DATA frame ahead of it, so the
	// response body now holds unread bytes - the precondition for the blocking close path.
	select {
	case <-fakeConn.dataDelivered:
	case <-time.After(5 * time.Second):
		connClosed := false
		select {
		case <-fakeConn.closed:
			connClosed = true
		default:
		}
		fakeConn.typeAccess.Lock()
		countErrors := append([]string(nil), fakeConn.countErrors...)
		fakeConn.typeAccess.Unlock()
		t.Fatalf("the client never acknowledged the server PING (frames=%d connClosed=%v frames=%v countErrors=%v), so the unread-body "+
			"precondition was not established", fakeConn.framesRead.Load(), connClosed, fakeConn.frameTypes(), countErrors)
	}

	// Block a writer so it holds cc.wmu: one large write the stalled peer cannot drain.
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := streamConn.Write(make([]byte, 256<<10))
		writeDone <- writeErr
	}()
	select {
	case <-fakeConn.blockedWrite:
	case <-time.After(5 * time.Second):
		t.Fatal("the HTTP/2 writer never became blocked, so cc.wmu is not held and the reproducer " +
			"cannot demonstrate the residual")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- streamConn.Close() }()

	select {
	case closeErr := <-closeDone:
		require.NoError(t, closeErr)
		t.Fatal("Close returned while the peer was stalled and the response body had unread bytes. " +
			"This is GOOD news and means the residual may be gone: golang.org/x/net/http2's " +
			"transportResponseBody.Close no longer blocks on cc.wmu before its context select. " +
			"Re-check the pinned x/net version, then rewrite the residual paragraph on " +
			"clientStreamConn.Close (and this test) instead of deleting the explanation.")
	case <-time.After(time.Second):
		// Expected: Close is in transportResponseBody.Close, past BreakWithError/abortStream and
		// stuck acquiring cc.wmu.
	}

	// Bounded teardown must not have been bought by destroying the connection, which is what would
	// unblock cc.wmu from underneath.
	select {
	case <-fakeConn.closed:
		t.Fatal("the shared socket was closed to unblock the response-body close")
	default:
	}

	// Release the peer: the parked write returns an error, cc.wmu is dropped, and Close can
	// finish. This is also what keeps the test from leaking the paused goroutines.
	_ = fakeConn.Close()
	select {
	case closeErr := <-closeDone:
		require.NoError(t, closeErr)
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return even after the peer released cc.wmu")
	}
	select {
	case writeErr := <-writeDone:
		require.Error(t, writeErr)
		require.True(t, errors.Is(writeErr, net.ErrClosed), "got %v", writeErr)
	case <-time.After(5 * time.Second):
		t.Fatal("the blocked writer did not observe the close")
	}
}
