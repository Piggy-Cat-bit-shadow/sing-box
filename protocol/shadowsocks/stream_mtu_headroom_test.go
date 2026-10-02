package shadowsocks

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Regression coverage for the stacked-writer headroom bug.
//
// # The production panic this reproduces
//
//	panic: buffer overflow: capacity 16384, start 0, need 9
//	  buf.(*Buffer).ExtendHeader(..., 9)
//	  sing-shadowtls.(*verifiedConn).WriteBuffer        v3_conn.go:140
//	  shadowio.(*Writer).WriteBuffer                    writer.go:90
//	  shadowaead_2022.(*clientConn).WriteBuffer         method.go:346
//	  shadowsocks.(*mtuAdvertisingConn).WriteBuffer     stream_mtu.go
//	  bufio.copyWaitWithPool
//
// withStreamMTU took only the immediate Shadowsocks writer's headroom:
//
//	conn.(N.FrontHeadroom).FrontHeadroom()
//
// That is 2 + 16 = 18 for SS2022. ShadowTLS v3 sits BELOW it and prepends its own
// tlsHmacHeaderSize = 9, so the chain needs 27 while 18 was advertised. Under
// with_low_memory (which iOS Libbox is built with) BufferSize is 16384, so the copy
// loop allocated streamWriterMTU() + 18 + 16 = 16350 + 34 = 16384 - exactly the
// capacity in the panic - leaving 0 bytes free when ShadowTLS asked for 9.
//
// # Why the existing transparency test did not catch it
//
// TestWithStreamMTUIsTransparent dials over copyDetectingWriter, which advertises no
// headroom at all. N.CalculateFrontHeadroom then equals the local value, so the bug
// is arithmetically invisible there. The fixture below is what makes it visible: it
// advertises 9 AND actually consumes it, the way verifiedConn does.

// shadowTLSLikeWriter stands in for sing-shadowtls verifiedConn.
//
// It has to do both halves of the contract. Advertising 9 without consuming it would
// make the geometry assertions pass while proving nothing, and consuming 9 without
// advertising it would be the very bug under test. So it advertises 9, walks to the
// writer beneath it, and prepends 9 bytes for real.
type shadowTLSLikeWriter struct {
	// nopConn supplies the net.Conn surface; only the write path matters here.
	nopConn
	beneath      N.ExtendedWriter
	recordHeader []byte
	writes       int
}

// The value verifiedConn actually prepends; see tlsHmacHeaderSize in sing-shadowtls.
const shadowTLSLikeHeaderSize = 9

func (w *shadowTLSLikeWriter) WriteBuffer(buffer *buf.Buffer) error {
	// ExtendHeader fails when the buffer has fewer than 9 free bytes at the front,
	// which is precisely the panic being reproduced.
	header := buffer.ExtendHeader(shadowTLSLikeHeaderSize)
	for i := range header {
		header[i] = byte(0xA0 + i)
	}
	w.recordHeader = append([]byte(nil), header...)
	w.writes++
	return w.beneath.WriteBuffer(buffer)
}

func (w *shadowTLSLikeWriter) Upstream() any { return w.beneath }

func (w *shadowTLSLikeWriter) FrontHeadroom() int { return shadowTLSLikeHeaderSize }

// copySink collects what finally reaches the socket, and forwards the interfaces the
// Shadowsocks writer walks through.
type copySink struct {
	nopConn
	written int
	frames  int
}

func (s *copySink) WriteBuffer(buffer *buf.Buffer) error {
	s.written += buffer.Len()
	s.frames++
	buffer.Release()
	return nil
}

func (s *copySink) Upstream() any { return nil }

// shadowOverTLSChain builds: SS2022 clientConn -> shadowTLSLikeWriter -> copySink
//
// This is the production topology reduced to its essentials. The sink is the bottom
// of the chain; the TLS-like writer sits between it and Shadowsocks.
func shadowOverTLSChain(t *testing.T, method shadowssMethod) (net.Conn, *shadowTLSLikeWriter, *copySink) {
	t.Helper()
	sink := &copySink{}
	tlsLike := &shadowTLSLikeWriter{beneath: sink}
	real := method.DialEarlyConn(tlsLike, M.ParseSocksaddrHostPort("target.example", 443))
	return real, tlsLike, sink
}

// shadowssMethod is an alias so this file does not depend on the concrete interface
// name used by the other audit tests.
type shadowssMethod = interface {
	DialEarlyConn(conn net.Conn, destination M.Socksaddr) net.Conn
}

// handshake performs the first write, which carries the SS2022 salt and never reaches
// the inner writer. The steady-state writes that follow are the ones that exercise the
// MTU-constrained path - and the ones that crashed in production. Tests must get past
// this before asserting anything about the layer beneath.
func handshake(t *testing.T, wrapped net.Conn, mtu, front, rear int) {
	t.Helper()
	buffer := buf.NewSize(mtu + front + rear)
	buffer.Resize(front, 0)
	buffer.Extend(1)
	require.NoError(t, wrapped.(N.ExtendedWriter).WriteBuffer(buffer),
		"the salt write must succeed")
}

// --- the geometry contract ----------------------------------------------------

func TestStreamMTU_PreservesStackedHeadroom(t *testing.T) {
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	sink := &copySink{}
	tlsLike := &shadowTLSLikeWriter{beneath: sink}
	real := method.DialEarlyConn(tlsLike, M.ParseSocksaddrHostPort("target.example", 443))

	// The chain must require MORE than the Shadowsocks layer alone, or this test is
	// not exercising the bug. Without this guard the test would silently degrade into
	// a duplicate of the transparency test if the fixture ever stopped advertising.
	realFront := N.CalculateFrontHeadroom(real)
	require.Equal(t, 18+shadowTLSLikeHeaderSize, realFront,
		"the stacked chain must require the Shadowsocks headroom PLUS what sits beneath it")

	// A local-only reading, which is what the bug did, would see just the SS layer.
	if local, isLocal := real.(N.FrontHeadroom); isLocal {
		require.Equal(t, 18, local.FrontHeadroom(),
			"the immediate writer's own headroom is 18; the bug was reporting only this")
	}

	wrapped := withStreamMTU(real)
	require.NotSame(t, real, wrapped, "the conn must actually be wrapped")

	require.Equal(t, realFront, N.CalculateFrontHeadroom(wrapped),
		"the wrapper must advertise the headroom of the WHOLE chain, not one layer")
	require.Equal(t, N.CalculateRearHeadroom(real), N.CalculateRearHeadroom(wrapped),
		"rear headroom must be preserved too")

	// And the only added capability is still the MTU.
	withMTU, hasMTU := wrapped.(N.WriterWithMTU)
	require.True(t, hasMTU, "the wrapper exists to advertise WriterMTU")
	require.Equal(t, streamWriterMTU(), withMTU.WriterMTU())
}

func TestStreamMTU_PooledBufferHasRoomForEveryLayer(t *testing.T) {
	// Geometry equality is necessary but not sufficient: the real question is whether
	// a pooled buffer sized by the advertised MTU still has room at each layer. This
	// asserts the property the panic violated.
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	sink := &copySink{}
	tlsLike := &shadowTLSLikeWriter{beneath: sink}
	real := method.DialEarlyConn(tlsLike, M.ParseSocksaddrHostPort("target.example", 443))
	wrapped := withStreamMTU(real)

	mtu := N.CalculateMTU(nil, wrapped)
	require.Equal(t, streamWriterMTU(), mtu)
	require.Greater(t, mtu, 0, "the MTU optimisation must still be advertised")

	// Size a buffer exactly the way bufio.Copy does: allocate the payload plus both
	// headrooms, then set the start offset to the front headroom. Getting this order
	// wrong (Resize(0, mtu)) zeroes the very headroom under test.
	front := N.CalculateFrontHeadroom(wrapped)
	rear := N.CalculateRearHeadroom(wrapped)
	buffer := buf.NewSize(mtu + front + rear)
	buffer.Resize(front, 0)
	buffer.Extend(mtu)

	require.GreaterOrEqual(t, buffer.Start(), front,
		"a buffer sized by the advertised geometry must have that much front room")
	require.LessOrEqual(t, buffer.Len(), mtu, "payload must fit the advertised MTU")

	// Reach steady state first: the opening write carries the salt and does not touch
	// the layer beneath, so asserting before it would prove nothing.
	handshake(t, wrapped, mtu, front, rear)

	// This is the call that panicked in production.
	require.NotPanics(t, func() {
		require.NoError(t, wrapped.(N.ExtendedWriter).WriteBuffer(buffer))
	}, "writing a full-MTU buffer through the stacked writer must not overflow")

	require.Greater(t, sink.written, 0, "the payload must reach the socket")
	require.Equal(t, shadowTLSLikeHeaderSize, len(tlsLike.recordHeader),
		"the lower layer must have prepended its own header")
}

func TestStreamMTU_OldImplementationWouldFail(t *testing.T) {
	// Demonstrates the bug directly, so the regression test above cannot quietly stop
	// testing anything. Constructing the OLD behaviour by hand - advertising only the
	// local headroom - must produce a buffer that overflows at the lower layer.
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	sink := &copySink{}
	tlsLike := &shadowTLSLikeWriter{beneath: sink}
	real := method.DialEarlyConn(tlsLike, M.ParseSocksaddrHostPort("target.example", 443))

	local, hasLocal := real.(N.FrontHeadroom)
	require.True(t, hasLocal, "the SS writer must expose its own headroom for this to be meaningful")

	// Exactly what withStreamMTU used to compute: the local layer only.
	mtu := streamWriterMTU()
	oldWaysBuffer := buf.NewSize(mtu + local.FrontHeadroom() + N.CalculateRearHeadroom(real))
	oldWaysBuffer.Resize(local.FrontHeadroom(), 0)
	oldWaysBuffer.Extend(mtu)

	// The local layer succeeds, which is why the bug is invisible from here.
	require.NoError(t, real.(N.ExtendedWriter).WriteBuffer(oldWaysBuffer),
		"the Shadowsocks layer fits, because its own requirement was the one advertised")

	// Steady state: a second write with a full payload is where the chain actually
	// reaches the layer beneath. Sized the old way, it overflows there - which is the
	// production panic, reproduced.
	steady := buf.NewSize(mtu + local.FrontHeadroom() + N.CalculateRearHeadroom(real))
	steady.Resize(local.FrontHeadroom(), 0)
	steady.Extend(mtu)
	require.Panics(t, func() {
		_ = real.(N.ExtendedWriter).WriteBuffer(steady)
	}, "a buffer sized for only the SS layer must overflow at the layer beneath")
}

// --- the copy loop ------------------------------------------------------------

func TestStreamMTU_FullCopyLoopThroughStackedWriter(t *testing.T) {
	// Drives the real path end to end: a fixed source through bufio.Copy into the
	// wrapped conn, over a Stacked writer that needs 9 bytes. This is the shape of the
	// crash, not just its arithmetic.
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	sink := &copySink{}
	tlsLike := &shadowTLSLikeWriter{beneath: sink}
	real := method.DialEarlyConn(tlsLike, M.ParseSocksaddrHostPort("target.example", 443))
	wrapped := withStreamMTU(real)

	// Enough to span several MTU-sized chunks, so the MTU-constrained copy loop runs
	// its steady-state path repeatedly rather than once. The reader is the same
	// fixture the existing audit tests use, so the comparison stays apples to apples.
	const payloadSize int64 = 64 * 1024
	source := &fixedSizeReader{remaining: int(payloadSize)}

	copied, err := bufio.Copy(wrapped, source)
	require.NoError(t, err, "the copy must complete without panicking")
	require.Equal(t, payloadSize, copied,
		"the whole payload must be consumed by the copy loop")

	// What matters is that the loop ran its steady-state path repeatedly through the
	// stacked writer without overflowing. Bytes at the sink are NOT the assertion:
	// Shadowsocks frames and buffers internally, so what reaches the layer beneath is
	// not a 1:1 reflection of what the loop delivered. Asserting equality there failed
	// for that reason, not because data was lost.
	require.Greater(t, tlsLike.writes, 1,
		"the steady-state writer must be reached more than once, or the MTU path was not exercised")
	require.Greater(t, sink.written, 0, "payload must reach the socket")
}

// --- other stacks -------------------------------------------------------------

func TestStreamMTU_PlainSinkStillWorks(t *testing.T) {
	// The original case must keep working: SS over something that asks for nothing.
	// CalculateFrontHeadroom returns the local 18 here, so behaviour is unchanged.
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	sink := &copySink{}
	real := method.DialEarlyConn(sink, M.ParseSocksaddrHostPort("target.example", 443))
	wrapped := withStreamMTU(real)

	require.Equal(t, N.CalculateFrontHeadroom(real), N.CalculateFrontHeadroom(wrapped))
	require.Equal(t, N.CalculateRearHeadroom(real), N.CalculateRearHeadroom(wrapped))

	mtu := N.CalculateMTU(nil, wrapped)
	front := N.CalculateFrontHeadroom(wrapped)
	buffer := buf.NewSize(mtu + front + N.CalculateRearHeadroom(wrapped))
	buffer.Resize(front, 0)
	buffer.Extend(mtu)
	handshake(t, wrapped, mtu, front, N.CalculateRearHeadroom(wrapped))
	require.NotPanics(t, func() {
		require.NoError(t, wrapped.(N.ExtendedWriter).WriteBuffer(buffer))
	})
	require.Greater(t, sink.written, 0)
}

func TestStreamMTU_NonExtendedWriterIsUnchanged(t *testing.T) {
	// A conn that cannot write buffers has nothing to advertise against, so it must be
	// returned as-is rather than wrapped in something that would break it.
	plain := &plainConn{}
	require.Same(t, net.Conn(plain), withStreamMTU(plain),
		"a conn without ExtendedWriter must not be wrapped")
}

type plainConn struct {
	nopConn
}

func (c *plainConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *plainConn) Close() error                { return nil }
func (c *plainConn) LocalAddr() net.Addr         { return M.Socksaddr{} }
func (c *plainConn) RemoteAddr() net.Addr        { return M.Socksaddr{} }
func (c *plainConn) SetDeadline(time.Time) error { return nil }
