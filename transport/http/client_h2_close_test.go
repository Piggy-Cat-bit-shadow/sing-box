package http

import (
	"bytes"
	"context"
	"errors"
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
	"golang.org/x/net/http2/hpack"
)

// # B: a graceful RST_STREAM is optional; bounded teardown is mandatory
//
// An HTTP/2 CONNECT tunnel is torn down by clientStreamConn.Close. The response body it holds is
// golang.org/x/net/http2's transportResponseBody, whose Close does two things: it aborts the
// stream, and then it WAITS for the stream to reach its closed state. That wait is normally
// instant, but the state transition is performed by the request-writing goroutine inside
// cleanupWriteRequest, and that function sends the stream reset under the connection's write
// mutex (cc.wmu). A peer that has stopped reading, so that the connector's own Write cannot make
// progress, holds cc.wmu while blocked inside a flush. The reset -- a courtesy to a peer that is
// no longer listening -- therefore cannot be sent, the state transition never happens, and a Close
// that waits for it blocks for as long as the peer stays silent.
//
// This fork does not hand-roll HTTP/2 framing and owns none of that code, but it does own the
// ORDER of its own teardown, and that order is what decides whether the wait can be escaped.
// clientStreamConn.Close must therefore release its own stream context BEFORE it asks the HTTP/2
// layer to close the response body, because the body close's wait is a select that the stream
// context can break. The polite reset is still attempted on the transport's own goroutine; what
// must never happen is this goroutine waiting for it.
//
// The test below builds the situation deterministically. It runs a REAL x/net/http2 client
// connection (so the wait under test is the library's, not a double's) over a net.Conn that
// completes the preface, SETTINGS exchange and one CONNECT, answers 200, and then stops draining
// the client's writes entirely -- the TCP-level picture of a peer whose receive window has closed.
// It then proves three things: Close returns inside a hard deadline while a writer really is
// blocked; the blocked writer receives an error; and the socket was NOT closed to force the issue,
// so the relief came from the fork's own ordering rather than from destroying the connection every
// other stream shares.

// blockingH2Conn is the server half of a deliberately stalled HTTP/2 connection.
//
// It is a net.Conn, because that is the only seam the HTTP/2 transport offers, and it speaks
// exactly as much of the protocol as the assertions need. Everything after the first DATA frame is
// silence, which is the whole point.
type blockingH2Conn struct {
	readCh  chan []byte
	readBuf bytes.Buffer

	writeCh chan []byte
	// drainStopped is closed by the server loop immediately before it stops reading, so a Write
	// that arrives afterwards knows it is the one that will block.
	drainStopped chan struct{}
	// blockedWrite is closed once, by the first Write that is past drainStopped and unable to
	// hand its bytes over. It is the deterministic "a writer is blocked right now" signal, so the
	// test never has to sleep and hope.
	blockedWrite chan struct{}
	blockOnce    sync.Once

	closed    chan struct{}
	closeOnce sync.Once

	// Counters exist only to make a failure diagnosable: "the writer never blocked" is not
	// actionable without knowing whether the peer ever saw payload at all.
	framesRead  atomic.Int64
	dataFrames  atomic.Int64
	writeCalls  atomic.Int64
	serveExited atomic.Bool
}

func newBlockingH2Conn() *blockingH2Conn {
	conn := &blockingH2Conn{
		readCh:       make(chan []byte, 8),
		writeCh:      make(chan []byte),
		drainStopped: make(chan struct{}),
		blockedWrite: make(chan struct{}),
		closed:       make(chan struct{}),
	}
	// The server's SETTINGS must be available before the client's read loop looks for it. It is
	// queued here rather than pushed from serve() so it cannot race the preface.
	conn.readCh <- serverSettingsFrame()
	return conn
}

// serve acts as the peer: it consumes the client preface and frames until the request payload
// starts, answers the CONNECT with 200 when the request headers arrive, and then abandons the
// connection.
func (c *blockingH2Conn) serve() {
	defer c.serveExited.Store(true)
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
		switch frame.(type) {
		case *http2.HeadersFrame:
			// The CONNECT has been received. 200 with no END_STREAM: for a CONNECT the 200 is
			// where the tunnel begins, and the write side stays open.
			c.readCh <- statusOKHeadersFrame()
		case *http2.DataFrame:
			// Payload has started. Stop draining; the next Write has nowhere to go.
			c.dataFrames.Add(1)
			close(c.drainStopped)
			return
		}
	}
}

func (c *blockingH2Conn) Read(p []byte) (int, error) {
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

func (c *blockingH2Conn) Write(p []byte) (int, error) {
	c.writeCalls.Add(1)
	data := append([]byte(nil), p...)
	// All three arms are in ONE select so there is no window in which the peer can stop
	// reading after the send has already committed: once serve() returns, nobody receives on
	// writeCh, so the send can never be the chosen arm again.
	select {
	case c.writeCh <- data:
		return len(p), nil
	case <-c.drainStopped:
		// The peer has stopped reading, so this write cannot make progress. Announce it
		// deterministically, then stay parked exactly as a blocked syscall would rather than
		// returning an error the transport never observes.
		c.blockOnce.Do(func() { close(c.blockedWrite) })
	case <-c.closed:
		return 0, net.ErrClosed
	}
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingH2Conn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *blockingH2Conn) LocalAddr() net.Addr                { return h2TestAddr{} }
func (c *blockingH2Conn) RemoteAddr() net.Addr               { return h2TestAddr{} }
func (c *blockingH2Conn) SetDeadline(t time.Time) error      { return nil }
func (c *blockingH2Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *blockingH2Conn) SetWriteDeadline(t time.Time) error { return nil }

type h2TestAddr struct{}

func (h2TestAddr) Network() string { return "h2-test" }
func (h2TestAddr) String() string  { return "h2-test" }

// h2ChanReader turns the fake connection's write channel into an io.Reader for the frame parser.
// It does not read ahead, so stopping in serve() stops the peer exactly.
type h2ChanReader struct {
	source  chan []byte
	current []byte
}

func (r *h2ChanReader) Read(p []byte) (int, error) {
	for len(r.current) == 0 {
		data, ok := <-r.source
		if !ok {
			return 0, io.EOF
		}
		r.current = data
	}
	n := copy(p, r.current)
	r.current = r.current[n:]
	return n, nil
}

func serverSettingsFrame() []byte {
	var frame bytes.Buffer
	writeErr := http2.NewFramer(&frame, nil).WriteSettings()
	if writeErr != nil {
		panic(writeErr)
	}
	return frame.Bytes()
}

func statusOKHeadersFrame() []byte {
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	if err := encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
		panic(err)
	}
	var frame bytes.Buffer
	err := http2.NewFramer(&frame, nil).WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: block.Bytes(),
		EndHeaders:    true,
		// EndStream is deliberately false: a CONNECT 200 opens the tunnel rather than
		// completing the request, so the stream must stay open for payload.
	})
	if err != nil {
		panic(err)
	}
	return frame.Bytes()
}

// TestH2TunnelCloseIsBoundedBehindABlockedWriter is THE regression test for B.
//
// It fails, by blocking past its own hard deadline, against a Close that asks the HTTP/2 layer to
// close the response body before it releases the stream context.
func TestH2TunnelCloseIsBoundedBehindABlockedWriter(t *testing.T) {
	t.Parallel()

	fakeConn := newBlockingH2Conn()
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		fakeConn.serve()
	}()
	t.Cleanup(func() {
		// Releasing the socket is what lets the transport's own goroutine finish; without it a
		// red-check run would leave a goroutine parked and the test binary would not exit.
		_ = fakeConn.Close()
		<-serveDone
	})

	h2Transport, err := httpclient.ConfigureHTTP2Transport(option.HTTP2Options{})
	require.NoError(t, err)
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

	// One large write. It cannot complete: the transport fills its frame buffer, hands a DATA
	// frame to the stalled connection, and then has nowhere to put the rest.
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := streamConn.Write(make([]byte, 256<<10))
		writeDone <- writeErr
	}()

	// Deterministic proof that a writer is blocked inside Write. The server loop has stopped
	// draining, and this fires when the transport reaches the next write.
	select {
	case <-fakeConn.blockedWrite:
	case <-time.After(5 * time.Second):
		t.Fatalf("the HTTP/2 writer never became blocked (frames=%d data=%d writes=%d serveExited=%v); "+
			"the test cannot prove anything about a blocked writer",
			fakeConn.framesRead.Load(), fakeConn.dataFrames.Load(), fakeConn.writeCalls.Load(), fakeConn.serveExited.Load())
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- streamConn.Close() }()
	select {
	case err = <-closeDone:
		require.NoError(t, err, "Close must return successfully, not merely quickly")
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked behind a writer holding the HTTP/2 connection write mutex; " +
			"a graceful RST_STREAM is optional, bounded teardown is mandatory")
	}

	// The blocked writer must observe the teardown rather than waiting for a peer that will
	// never answer.
	select {
	case writeErr := <-writeDone:
		require.Error(t, writeErr, "the blocked writer must receive an error, not stay blocked")
		require.True(t, errors.Is(writeErr, net.ErrClosed),
			"the error must identify the tunnel as closed, got %v", writeErr)
	case <-time.After(3 * time.Second):
		t.Fatal("the blocked writer did not observe the close")
	}

	// Bounded teardown must not be bought by destroying the connection every stream shares.
	// If Close had closed the socket to unblock itself, every other stream on that connection
	// would have died with this one.
	//
	// The assertion is on the socket rather than on the HTTP/2 ClientConn's state because the
	// library's State accessor takes the SAME write mutex the stalled writer holds -- calling it
	// here deadlocks the test, which is itself the sharpest evidence that the mutex is still held
	// and that nothing in Close waited for it.
	select {
	case <-fakeConn.closed:
		t.Fatal("the shared connection's socket was closed to make teardown bounded; " +
			"that trades one blocked tunnel for every stream on the connection")
	default:
	}
}
