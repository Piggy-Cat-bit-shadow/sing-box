package http

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// The timeout wrappers must PRESERVE the batch capabilities.
//
// # The chain this pins
//
//	http3PacketConn            offers connected batch read + write
//	  -> canceler.NewPacketConn
//	     -> TimerPacketConn      (when the socket cannot take a read deadline)
//	     -> TimeoutPacketConn    (when it can)
//	  -> CreateConnectedPacketBatchReadWaiter / ...Writer
//	  -> bufio.CopyPacket selects the batch path
//
// route/conn.go wraps every CONNECT-UDP connection in canceler.NewPacketConn for the
// UDP idle timeout. If the wrapper does not forward the creators, the tunnel silently
// falls back to one packet at a time: it keeps working, so nothing fails, and the
// batching that was implemented on the tunnel is simply unreachable in production.
//
// # Why the assertions call the CREATORS and not just type-assert
//
// An interface assertion only proves a method exists. The creators are what
// bufio.CopyPacket actually calls, and they walk the upstream chain themselves, so a
// wrapper that merely declared the method but returned false would still strand the
// copy on the fallback. These tests therefore obtain a real waiter and a real writer
// through the same entry points the copy path uses.
//
// # Both wrapper types are covered, and they are not interchangeable
//
// canceler.NewPacketConn picks its implementation from the underlying connection's
// ability to take a read deadline. A real UDP socket can, so production mostly takes
// the TimeoutPacketConn branch; the HTTP/3 packet connection cannot, which is the
// TimerPacketConn branch. Fixing one and not the other would leave the production path
// broken, so they are separate tests with separate fixtures rather than one shared
// assertion.

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// batchCapablePacketConn is a connected packet connection that offers the batch
// capabilities and whose OTHER behaviour the test controls.
//
// It is a test double rather than a real socket because the two wrapper branches differ
// in exactly one observable way - whether SetReadDeadline succeeds - and a fake is the
// only way to hold everything else equal between them. Every method the copy path can
// reach is implemented, so a fallback is a counted event rather than a nil panic.
type batchCapablePacketConn struct {
	// deadlineErr is what SetReadDeadline returns. nil selects the TimeoutPacketConn
	// branch; os.ErrInvalid (what the HTTP/3 connection reports) selects the
	// TimerPacketConn branch.
	deadlineErr error

	// packets is the queue the read waiter drains.
	packets chan *buf.Buffer
	// closed is closed by Close, so a blocked read can observe shutdown.
	closed chan struct{}
	// destination is the connected peer address reported with every read.
	destination M.Socksaddr

	// readWaiterCalls and readWaiterOK count creations, so "the wrapper asked the
	// inner connection exactly once" is assertable.
	readWaiterCalls int
	readWaiterOK    bool
	writeCreatorHit int

	// batchReadCalls / batchWriteCalls count the calls the WRAPPER forwards, which is
	// how the tests prove the batch path was really used rather than merely offered.
	forwardedBatchReads  int
	forwardedBatchWrites int
}

func newBatchCapablePacketConn(deadlineErr error) *batchCapablePacketConn {
	return &batchCapablePacketConn{
		deadlineErr: deadlineErr,
		packets:     make(chan *buf.Buffer, 256),
		closed:      make(chan struct{}),
		destination: M.ParseSocksaddr("192.0.2.10:443"),
	}
}

func (c *batchCapablePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case packet := <-c.packets:
		_, err := buffer.Write(packet.Bytes())
		packet.Release()
		if err != nil {
			return M.Socksaddr{}, err
		}
		return c.destination, nil
	case <-c.closed:
		return M.Socksaddr{}, net.ErrClosed
	}
}

func (c *batchCapablePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *batchCapablePacketConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *batchCapablePacketConn) SetReadDeadline(t time.Time) error { return c.deadlineErr }

func (c *batchCapablePacketConn) SetWriteDeadline(t time.Time) error { return c.deadlineErr }

func (c *batchCapablePacketConn) SetDeadline(t time.Time) error { return c.deadlineErr }

// CreateConnectedPacketBatchReadWaiter is the INNER capability: it is what the wrapper
// is supposed to forward. Its call count proves the wrapper delegates rather than
// fabricating a waiter.
func (c *batchCapablePacketConn) CreateConnectedPacketBatchReadWaiter() (N.ConnectedPacketBatchReadWaiter, bool) {
	c.readWaiterCalls++
	return &countingConnectedReadWaiter{conn: c}, true
}

func (c *batchCapablePacketConn) CreateConnectedPacketBatchWriter() (N.ConnectedPacketBatchWriter, bool) {
	c.writeCreatorHit++
	return &countingConnectedBatchWriter{conn: c}, true
}

// countingConnectedReadWaiter drains the queue without blocking past the first packet,
// and counts every call so a test can assert the batch path (not ReadPacket) ran.
type countingConnectedReadWaiter struct {
	conn *batchCapablePacketConn
	size int
}

func (w *countingConnectedReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.size = options.BatchSize
	if w.size <= 0 {
		w.size = 1
	}
	// The queue holds complete buffers already, so nothing needs copying into waiter
	// storage. Reporting true here would make the copy path allocate and copy, which is
	// what the batch path exists to avoid.
	return false
}

func (w *countingConnectedReadWaiter) WaitReadConnectedPackets() ([]*buf.Buffer, M.Socksaddr, error) {
	select {
	case first := <-w.conn.packets:
		w.conn.forwardedBatchReads++
		buffers := []*buf.Buffer{first}
		for len(buffers) < w.size {
			select {
			case next := <-w.conn.packets:
				buffers = append(buffers, next)
			default:
				return buffers, w.conn.destination, nil
			}
		}
		return buffers, w.conn.destination, nil
	case <-w.conn.closed:
		return nil, M.Socksaddr{}, net.ErrClosed
	}
}

type countingConnectedBatchWriter struct {
	conn *batchCapablePacketConn
}

func (w *countingConnectedBatchWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	w.conn.forwardedBatchWrites++
	// Match the ownership contract the real writers use: the writer consumes every
	// buffer it is handed, on both the success and the failure path.
	buf.ReleaseMulti(buffers)
	return nil
}

// noBatchPacketConn is a connected packet connection with NO batch capability at all.
// It exists so the tests can prove the wrapper does not claim a capability the inner
// connection does not have.
type noBatchPacketConn struct {
	closed chan struct{}
}

func newNoBatchPacketConn() *noBatchPacketConn {
	return &noBatchPacketConn{closed: make(chan struct{})}
}

func (c *noBatchPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	<-c.closed
	return M.Socksaddr{}, net.ErrClosed
}

func (c *noBatchPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *noBatchPacketConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *noBatchPacketConn) SetReadDeadline(t time.Time) error { return os.ErrInvalid }

func (c *noBatchPacketConn) SetWriteDeadline(t time.Time) error { return os.ErrInvalid }

func (c *noBatchPacketConn) SetDeadline(t time.Time) error { return os.ErrInvalid }

// The net.PacketConn methods. They are part of N.PacketConn even though the copy path
// never calls them on a connected connection, so both fixtures must provide them for the
// compile-time guards below to mean anything.
func (c *batchCapablePacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero} }

func (c *batchCapablePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *batchCapablePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, net.ErrClosed
}

func (c *noBatchPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero} }

func (c *noBatchPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *noBatchPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, net.ErrClosed
}

// Compile-time guards: the fixtures must keep satisfying the interfaces the wrapper
// switches on. If the upstream definitions move, this fails at build time rather than
// letting the tests silently exercise a different code path.
var (
	_ N.PacketConn                          = (*batchCapablePacketConn)(nil)
	_ N.ConnectedPacketBatchReadWaitCreator = (*batchCapablePacketConn)(nil)
	_ N.ConnectedPacketBatchWriteCreator    = (*batchCapablePacketConn)(nil)
	_ N.PacketConn                          = (*noBatchPacketConn)(nil)
)

// ---------------------------------------------------------------------------
// A. TimerPacketConn
// ---------------------------------------------------------------------------

// TestTimerPacketConnPreservesConnectedBatchCapabilities is branch A.
//
// A connection whose SetReadDeadline fails is wrapped in TimerPacketConn. This is the
// branch the HTTP/3 packet connection takes, so it is the one MASQUE CONNECT-UDP needs.
func TestTimerPacketConnPreservesConnectedBatchCapabilities(t *testing.T) {
	inner := newBatchCapablePacketConn(os.ErrInvalid)
	defer inner.Close()

	// Precondition: the bare connection offers both capabilities, so anything lost
	// below is attributable to the wrapper.
	_, bareRead := bufio.CreateConnectedPacketBatchReadWaiter(inner)
	_, bareWrite := bufio.CreateConnectedPacketBatchWriter(inner)
	require.True(t, bareRead, "precondition: the bare connection offers batch read")
	require.True(t, bareWrite, "precondition: the bare connection offers batch write")

	// The precondition above already invoked the inner creators once, so the delegation
	// assertion below compares against that baseline rather than against zero.
	baselineReadCreates := inner.readWaiterCalls
	baselineWriteCreates := inner.writeCreatorHit

	_, wrapped := canceler.NewPacketConn(context.Background(), inner, 30*time.Second)

	timerConn, isTimer := wrapped.(*canceler.TimerPacketConn)
	require.True(t, isTimer,
		"a connection that cannot take a read deadline must select TimerPacketConn, "+
			"got %T", wrapped)

	// # The assertions: real waiter and real writer through the real entry points

	readWaiter, readOK := bufio.CreateConnectedPacketBatchReadWaiter(timerConn)
	require.True(t, readOK,
		"TimerPacketConn must forward the connected batch read capability; without it "+
			"a CONNECT-UDP tunnel behind the idle-timeout wrapper silently drops to one "+
			"packet at a time")
	require.NotNil(t, readWaiter,
		"a creator that reports true must return a usable waiter")

	writeWriter, writeOK := bufio.CreateConnectedPacketBatchWriter(timerConn)
	require.True(t, writeOK,
		"TimerPacketConn must forward the connected batch write capability")
	require.NotNil(t, writeWriter)

	// The waiter must be the wrapper's own, doing its own accounting - not the raw
	// inner waiter handed straight back. Handing it back would enable batching while
	// bypassing the idle-timeout refresh, which is the one outcome that must not ship.
	require.Equal(t, baselineReadCreates+1, inner.readWaiterCalls,
		"the wrapper must delegate to the inner connection exactly once per request")
	require.Equal(t, baselineWriteCreates+1, inner.writeCreatorHit,
		"the wrapper must delegate the write capability exactly once per request")

	// InitializeReadWaiter must forward the caller's options unchanged.
	needCopy := readWaiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})
	require.False(t, needCopy,
		"the waiter must forward the inner needCopy rather than forcing a copy the "+
			"batch path exists to avoid")

	// # The batch path must actually work through the wrapper

	for index := range 8 {
		packet := buf.NewSize(4)
		packet.Write([]byte{byte(index), 1, 2, 3})
		inner.packets <- packet
	}

	buffers, destination, err := readWaiter.WaitReadConnectedPackets()
	require.NoError(t, err)
	require.Len(t, buffers, 8,
		"the batch must carry every queued packet up to the requested size")
	require.Equal(t, inner.destination, destination,
		"the connected destination must be preserved through the wrapper")
	for index, buffer := range buffers {
		require.Equal(t, byte(index), buffer.Bytes()[0],
			"packets must keep their order through the wrapper")
	}
	buf.ReleaseMulti(buffers)

	// Writes through the wrapper must land on the inner batch writer.
	writeBuffers := []*buf.Buffer{buf.NewSize(2), buf.NewSize(2)}
	writeBuffers[0].Write([]byte{1, 2})
	writeBuffers[1].Write([]byte{3, 4})
	require.NoError(t, writeWriter.WriteConnectedPacketBatch(writeBuffers))
	require.Equal(t, 1, inner.forwardedBatchWrites,
		"the batch write must reach the inner connection as ONE batch")
}

// ---------------------------------------------------------------------------
// B. TimeoutPacketConn
// ---------------------------------------------------------------------------

// TestTimeoutPacketConnPreservesConnectedBatchCapabilities is branch B.
//
// A connection whose SetReadDeadline succeeds is wrapped in TimeoutPacketConn. This is
// the branch a real UDP socket takes, so it is the one most production CONNECT-UDP
// traffic goes through, and it is a different implementation with different timeout
// semantics - which is why it gets its own test rather than sharing branch A's.
func TestTimeoutPacketConnPreservesConnectedBatchCapabilities(t *testing.T) {
	inner := newBatchCapablePacketConn(nil)
	defer inner.Close()

	_, bareRead := bufio.CreateConnectedPacketBatchReadWaiter(inner)
	_, bareWrite := bufio.CreateConnectedPacketBatchWriter(inner)
	require.True(t, bareRead, "precondition: the bare connection offers batch read")
	require.True(t, bareWrite, "precondition: the bare connection offers batch write")

	baselineReadCreates := inner.readWaiterCalls
	baselineWriteCreates := inner.writeCreatorHit

	_, wrapped := canceler.NewPacketConn(context.Background(), inner, 30*time.Second)

	timeoutConn, isTimeout := wrapped.(*canceler.TimeoutPacketConn)
	require.True(t, isTimeout,
		"a connection that accepts a read deadline must select TimeoutPacketConn, got %T",
		wrapped)

	readWaiter, readOK := bufio.CreateConnectedPacketBatchReadWaiter(timeoutConn)
	require.True(t, readOK,
		"TimeoutPacketConn must forward the connected batch read capability")
	require.NotNil(t, readWaiter)

	writeWriter, writeOK := bufio.CreateConnectedPacketBatchWriter(timeoutConn)
	require.True(t, writeOK,
		"TimeoutPacketConn must forward the connected batch write capability")
	require.NotNil(t, writeWriter)

	require.Equal(t, baselineReadCreates+1, inner.readWaiterCalls,
		"the wrapper must delegate to the inner connection exactly once per request")
	require.Equal(t, baselineWriteCreates+1, inner.writeCreatorHit)

	needCopy := readWaiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})
	require.False(t, needCopy)

	for index := range 8 {
		packet := buf.NewSize(4)
		packet.Write([]byte{byte(index), 1, 2, 3})
		inner.packets <- packet
	}

	buffers, destination, err := readWaiter.WaitReadConnectedPackets()
	require.NoError(t, err)
	require.Len(t, buffers, 8)
	require.Equal(t, inner.destination, destination)
	for index, buffer := range buffers {
		require.Equal(t, byte(index), buffer.Bytes()[0])
	}
	buf.ReleaseMulti(buffers)

	writeBuffers := []*buf.Buffer{buf.NewSize(2), buf.NewSize(2)}
	writeBuffers[0].Write([]byte{1, 2})
	writeBuffers[1].Write([]byte{3, 4})
	require.NoError(t, writeWriter.WriteConnectedPacketBatch(writeBuffers))
	require.Equal(t, 1, inner.forwardedBatchWrites)
}

// ---------------------------------------------------------------------------
// C. No batch capability on the inner connection
// ---------------------------------------------------------------------------

// TestTimeoutWrapperDoesNotInventBatchCapabilities is branch C.
//
// A wrapper must not claim a capability its inner connection does not have. Claiming it
// would be worse than losing it: the copy path would select a batch route and then have
// nothing to serve it, so this asserts the fallback is preserved rather than merely
// that no panic occurs.
func TestTimeoutWrapperDoesNotInventBatchCapabilities(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		deadlineErr error
	}{
		{"timer-branch", os.ErrInvalid},
		{"timeout-branch", nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			inner := newNoBatchPacketConn()
			defer inner.Close()

			// Precondition: the bare connection genuinely has no batch capability.
			_, bareRead := bufio.CreateConnectedPacketBatchReadWaiter(inner)
			_, bareWrite := bufio.CreateConnectedPacketBatchWriter(inner)
			require.False(t, bareRead, "precondition: no batch read on the bare connection")
			require.False(t, bareWrite, "precondition: no batch write on the bare connection")

			_, wrapped := canceler.NewPacketConn(context.Background(), inner, 30*time.Second)

			_, wrappedRead := bufio.CreateConnectedPacketBatchReadWaiter(wrapped)
			_, wrappedWrite := bufio.CreateConnectedPacketBatchWriter(wrapped)
			require.False(t, wrappedRead,
				"the wrapper must report no batch read when the inner connection has none")
			require.False(t, wrappedWrite,
				"the wrapper must report no batch write when the inner connection has none")

			// The ordinary single-packet path must still work: that is the fallback the
			// batch-less protocols depend on.
			buffer := buf.NewSize(4)
			require.NoError(t, wrapped.WritePacket(buffer, M.ParseSocksaddr("192.0.2.1:53")),
				"the ordinary packet path must remain usable without batch support")
		})
	}
}

// TestTimeoutWrapperKeepsTheOrdinaryPacketPathUsable guards the non-batch path for a
// connection that DOES have batch capability.
//
// A fix that routed every packet through the batch machinery would break the protocols
// that never ask for it, so the single-packet methods must keep working and must keep
// their existing behaviour.
func TestTimeoutWrapperKeepsTheOrdinaryPacketPathUsable(t *testing.T) {
	inner := newBatchCapablePacketConn(os.ErrInvalid)
	defer inner.Close()

	_, wrapped := canceler.NewPacketConn(context.Background(), inner, 30*time.Second)

	require.NoError(t, wrapped.WritePacket(buf.NewSize(4), inner.destination),
		"WritePacket must still work on a batch-capable connection")

	require.Same(t, inner, wrapped.(interface{ Upstream() any }).Upstream(),
		"Upstream must still report the inner connection, so wrappers above this one "+
			"can still see through it")
}

// TestTimeoutWrapperSetTimeoutStillApplies keeps the timeout API intact.
//
// The batch path shares the wrapper's state, so a timeout change made after the wrapper
// exists must remain effective. A waiter that cached the timeout at creation would make
// SetTimeout silently ineffective on the batch path only, which is the kind of
// divergence that is invisible until production.
func TestTimeoutWrapperSetTimeoutStillApplies(t *testing.T) {
	inner := newBatchCapablePacketConn(nil)
	defer inner.Close()

	_, wrapped := canceler.NewPacketConn(context.Background(), inner, time.Minute)

	timeoutConn, ok := wrapped.(canceler.PacketConn)
	require.True(t, ok, "the wrapper must expose the timeout API")

	require.Equal(t, time.Minute, timeoutConn.Timeout())
	require.True(t, timeoutConn.SetTimeout(11*time.Second),
		"SetTimeout must succeed on a connection that accepts deadlines")
	require.Equal(t, 11*time.Second, timeoutConn.Timeout(),
		"an updated timeout must be observable after the batch waiter exists")
}

// Compile-time reference so the errors import is used even if an assertion is removed.
var _ = errors.Is
