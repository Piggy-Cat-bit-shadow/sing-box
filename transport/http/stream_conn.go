package http

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type clientStreamConn struct {
	reader     io.ReadCloser
	writer     net.Conn
	cancel     context.CancelFunc
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     atomic.Bool
}

func (c *clientStreamConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	return n, c.wrapError(err)
}

func (c *clientStreamConn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	return n, c.wrapError(err)
}

func (c *clientStreamConn) wrapError(err error) error {
	if err == nil {
		return nil
	}
	if c.closed.Load() || strings.Contains(err.Error(), "client connection force closed") {
		return net.ErrClosed
	}
	return baderror.WrapH2(err)
}

func (c *clientStreamConn) CloseWrite() error {
	return c.writer.Close()
}

// Close tears the tunnel down, and the order below is the difference between a teardown that is
// bounded and one that waits for a peer that may never speak again.
//
// # Why the stream context is released BEFORE the response body is closed
//
// reader is golang.org/x/net/http2's transportResponseBody. Its Close aborts the stream and then
// WAITS for the stream to reach its closed state; that transition is performed by the transport's
// own request-writing goroutine in cleanupWriteRequest, which sends the stream reset while holding
// the connection's write mutex. A peer that has stopped reading -- a closed TCP receive window --
// leaves that goroutine parked inside a flush with the mutex held, so the reset cannot be sent and
// the transition never happens. Waiting for it is waiting for the peer to start reading again.
//
// The body close's wait is a select that also watches the stream's context, so cancelling that
// context is the escape hatch, and it has to happen FIRST. The reset is still attempted by the
// transport on its own goroutine; a graceful RST_STREAM is a courtesy to a peer that can still
// hear it, and is optional. Bounded teardown is not optional: Close runs on the failure path of a
// live tunnel, and a Close that never returns leaks the tunnel, its stream and its goroutine for
// the life of the process.
//
// Deliberately NOT "fixed" by closing the socket or the shared ClientConn to unblock the flush:
// those carry every other stream on the connection, so trading one blocked tunnel for all of them
// is worse than the bug. See TestH2TunnelCloseIsBoundedBehindABlockedWriter.
//
// # What is left unbounded, and why it is not fixed here
//
// x/net/http2's response-body Close has one earlier step that takes the same write mutex to return
// connection-level flow control for buffered-but-unread body bytes:
//
//	unread := cs.bufPipe.Len()
//	if unread > 0 {
//	    cc.mu.Lock(); connAdd := cc.inflow.add(unread); cc.mu.Unlock()
//	    cc.wmu.Lock()   // blocks here, BEFORE the select below
//	    ...
//	}
//	select { case <-cs.donec: ... case <-cs.ctx.Done(): return nil ... }
//
// The context escape this file relies on comes AFTER the lock, so it cannot break it. cc.wmu is
// held by the request-body writer across `cc.fr.WriteData` + `cc.bw.Flush`, and
// ConfigureHTTP2Transport leaves http2.Transport.WriteByteTimeout at zero, so that flush is a bare
// socket write with no deadline: a peer that has stopped reading parks it with cc.wmu held for as
// long as it stays silent.
//
// This was re-verified rather than assumed. The tree pins golang.org/x/net v0.57.0, and
// transportResponseBody.Close is byte-for-byte identical in v0.58.0 and v0.59.0 (current), TODO
// included, so a dependency bump cannot fix it; v0.59.0 additionally requires go >= 1.26 while this
// tree is on go1.25.5. Upstream is golang/go#48908, "x/net/http2: indefinite hangs when closing
// response body", still open; the CL it references (355491) fixed only the other half, closing the
// Request's Body when a stream is aborted.
//
// It cannot be closed from this package either. Draining first does not avoid cc.wmu, because
// transportResponseBody.Read takes the same mutex to return the tokens for the bytes it consumed;
// and a drain has no bound, since bufPipe.Read parks on a sync.Cond when the buffer is empty and
// neither its length nor a deadline is exported, so the drain goroutine would be the leaked waiter
// this ordering exists to prevent. Discarding the credit would starve every other stream on the
// shared connection, detaching a closer goroutine leaks, and closing the ClientConn to unblock the
// mutex kills those same streams. It is reachable only when the peer has BOTH stopped reading and
// already delivered unread tunnel payload, and bounding it is a change x/net/http2 must make.
//
// TestH2TunnelCloseWithUnreadBodyStaysBlockedBehindABlockedWriter (client_h2_unread_close_test.go)
// is the deterministic reproducer, and it fails with a pointer back to this paragraph if upstream
// ever moves the flow-control return off the write mutex.
func (c *clientStreamConn) Close() error {
	c.closed.Store(true)
	c.cancel()
	c.writer.Close()
	c.reader.Close()
	return nil
}

func (c *clientStreamConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *clientStreamConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *clientStreamConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *clientStreamConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *clientStreamConn) SetWriteDeadline(t time.Time) error {
	return c.writer.SetWriteDeadline(t)
}

func (c *clientStreamConn) NeedAdditionalReadDeadline() bool {
	return true
}

type clientTunnelConn struct {
	N.ExtendedConn
	streamConn *clientStreamConn
}

func newClientTunnelConn(streamConn *clientStreamConn) *clientTunnelConn {
	return &clientTunnelConn{ExtendedConn: deadline.NewConn(streamConn), streamConn: streamConn}
}

func (c *clientTunnelConn) CloseWrite() error {
	return c.streamConn.CloseWrite()
}

func (c *clientTunnelConn) SetDeadline(t time.Time) error {
	return E.Errors(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *clientTunnelConn) Upstream() any {
	return c.ExtendedConn
}

var (
	_ net.Conn      = (*clientStreamConn)(nil)
	_ N.WriteCloser = (*clientStreamConn)(nil)
	_ N.WriteCloser = (*clientTunnelConn)(nil)
)
