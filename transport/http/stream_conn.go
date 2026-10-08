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
// connection-level flow control for buffered-but-unread body bytes. That step cannot be avoided
// from this package without discarding the flow-control credit -- which would eventually stall
// every other stream on the shared connection -- or by detaching a goroutine that waits on the
// very mutex in question, which is exactly the leaked waiter this ordering exists to prevent. It
// is reachable only when the peer has BOTH stopped reading and already delivered unread tunnel
// payload, and bounding it is a change x/net/http2 must make.
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
