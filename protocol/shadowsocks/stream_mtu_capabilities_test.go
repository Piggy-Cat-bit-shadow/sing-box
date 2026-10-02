package shadowsocks

import (
	"net"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Regression coverage for the capabilities mtuAdvertisingConn must preserve.
//
// # Why this file exists
//
// The wrapper adds one capability, WriterMTU. Everything else the underlying Shadowsocks
// connection implements has to survive it, and a wrapper that hides one does not fail to
// compile - it silently changes behaviour on a path nobody is looking at:
//
//   - hiding ExtendedReader drops the download path from ReadBuffer back to the plain
//     Read([]byte) path, losing buffer reuse;
//   - hiding NeedHandshake leaves server-first protocols waiting for a greeting, because
//     route.NewConnection decides whether to kick a handshake by asking
//     N.NeedHandshakeForWrite(destination);
//   - overwriting an existing WriterMTU replaces a method's own, stricter limit with
//     pooled-buffer arithmetic that knows nothing about its wire format.
//
// Each test below is written to fail against the previous wrapper, which wrapped on
// ExtendedWriter alone and forwarded only the four methods it cared about.

// parseSocksaddr is the destination these fixtures dial toward. Nothing resolves it:
// DialEarlyConn only records it.
func parseSocksaddr(t *testing.T) M.Socksaddr {
	t.Helper()
	return M.ParseSocksaddrHostPort("target.example", 443)
}

// --- ExtendedReader ------------------------------------------------------------

func TestStreamMTU_PreservesExtendedReader(t *testing.T) {
	// The download direction must stay on ReadBuffer.
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")
	sink := &copySink{}
	real := method.DialEarlyConn(sink, parseSocksaddr(t))

	_, realReader := real.(N.ExtendedReader)
	require.True(t, realReader, "the real Shadowsocks conn must be an ExtendedReader")

	wrapped := withStreamMTU(real)
	_, hasReader := wrapped.(N.ExtendedReader)
	require.True(t, hasReader,
		"the wrapper must preserve ExtendedReader, or downloads fall back to Read([]byte)")

	_, hasFullConn := wrapped.(N.ExtendedConn)
	require.True(t, hasFullConn, "the wrapper must still be a full ExtendedConn")
}

// --- NeedHandshake -------------------------------------------------------------

func TestStreamMTU_PreservesNeedHandshake(t *testing.T) {
	// SS2022 needs a handshake before the first write, and route relies on being able to
	// ask. Hiding this interface is what would break SMTP/IMAP/POP3.
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")
	sink := &copySink{}
	real := method.DialEarlyConn(sink, parseSocksaddr(t))

	require.True(t, N.NeedHandshakeForWrite(real),
		"before the first write the real conn must report a pending handshake")

	wrapped := withStreamMTU(real)
	require.True(t, N.NeedHandshakeForWrite(wrapped),
		"the wrapper must not hide NeedHandshake: route uses it to kick server-first handshakes")

	// And the answer must keep tracking the real conn, not be frozen at construction.
	mtu := N.CalculateMTU(nil, wrapped)
	front := N.CalculateFrontHeadroom(wrapped)
	rear := N.CalculateRearHeadroom(wrapped)
	handshake(t, wrapped, mtu, front, rear)

	require.False(t, N.NeedHandshakeForWrite(real),
		"after the handshake write the real conn must report no pending handshake")
	require.False(t, N.NeedHandshakeForWrite(wrapped),
		"the wrapper's answer must delegate, not be captured once at construction")
}

func TestStreamMTU_NeedHandshakeIsFalseWithoutEarlyConn(t *testing.T) {
	// A conn with no handshake must not gain one from the wrapper. The method is always
	// present on the wrapper, so it has to answer false rather than claim a handshake is
	// pending and make route issue a pointless Write(nil).
	conn := &noHandshakeConn{}
	wrapped := withStreamMTU(conn)
	require.NotSame(t, net.Conn(conn), wrapped, "this fixture is wrappable")

	_, isEarly := wrapped.(N.EarlyConn)
	require.True(t, isEarly, "the wrapper always exposes the method")
	require.False(t, N.NeedHandshakeForWrite(wrapped),
		"a conn that needs no handshake must not report one through the wrapper")
}

// noHandshakeConn is an ExtendedConn with no early-conn interface and no own MTU.
type noHandshakeConn struct {
	nopConn
}

func (c *noHandshakeConn) ReadBuffer(*buf.Buffer) error  { return nil }
func (c *noHandshakeConn) WriteBuffer(*buf.Buffer) error { return nil }
func (c *noHandshakeConn) FrontHeadroom() int            { return 18 }
func (c *noHandshakeConn) RearHeadroom() int             { return 16 }
func (c *noHandshakeConn) Upstream() any                 { return nil }
func (c *noHandshakeConn) Close() error                  { return nil }
func (c *noHandshakeConn) LocalAddr() net.Addr           { return nil }
func (c *noHandshakeConn) RemoteAddr() net.Addr          { return nil }

// --- existing WriterMTU must win ------------------------------------------------

func TestStreamMTU_LegacyAEADKeepsItsOwnWriterMTU(t *testing.T) {
	// The legacy AEAD methods derive their own limit from the protocol's MaxPacketSize,
	// which is stricter than the pooled-buffer arithmetic. The wrapper must not replace
	// it, and the simplest way to guarantee that is to not wrap at all.
	method := shadowAuditMethod(t, "aes-128-gcm", "test-password")

	sink := &copySink{}
	real := method.DialEarlyConn(sink, parseSocksaddr(t))

	existing, hasMTU := real.(N.WriterWithMTU)
	require.True(t, hasMTU, "the legacy AEAD conn must advertise its own WriterMTU")
	ownMTU := existing.WriterMTU()
	require.Greater(t, ownMTU, 0)

	wrapped := withStreamMTU(real)

	// The primary assertion: it is not wrapped at all, so there is no way for the
	// arithmetic below to shadow the method's own value.
	require.Same(t, net.Conn(real), wrapped,
		"a conn that already advertises WriterMTU must be returned unchanged")

	before := N.CalculateMTU(nil, real)
	after := N.CalculateMTU(nil, wrapped)
	require.Equal(t, before, after, "CalculateMTU must be unchanged")
	require.Equal(t, ownMTU, after, "the method's own limit must still be the one in force")
}

// --- lower-layer MTU must not be widened ---------------------------------------

func TestStreamMTU_DoesNotWidenALowerWriterMTU(t *testing.T) {
	// This conn has no MTU of its own, but the writer beneath it does. The advertised
	// value must be the smaller of the two, or the copy loop would hand the lower layer
	// buffers it cannot frame.
	const lowerLimit = 4096

	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")
	lower := &lowerMTUWriter{limit: lowerLimit}
	real := method.DialEarlyConn(lower, parseSocksaddr(t))

	_, ownMTU := real.(N.WriterWithMTU)
	require.False(t, ownMTU, "SS2022 must not advertise an MTU of its own, or this proves nothing")

	wrapped := withStreamMTU(real)
	advertised, hasMTU := wrapped.(N.WriterWithMTU)
	require.True(t, hasMTU, "the wrapper must advertise a ceiling")

	require.Equal(t, lowerLimit, advertised.WriterMTU(),
		"the wrapper must not advertise above a lower writer's limit")
	require.Less(t, advertised.WriterMTU(), streamWriterMTU(),
		"this fixture is only meaningful while the lower limit is the stricter one")

	// And the number the copy loop will actually use agrees.
	require.Equal(t, lowerLimit, N.CalculateMTU(nil, wrapped))
}

// lowerMTUWriter is a writer beneath Shadowsocks that declares a smaller MTU.
type lowerMTUWriter struct {
	nopConn
	limit int
}

func (w *lowerMTUWriter) WriteBuffer(buffer *buf.Buffer) error {
	buffer.Release()
	return nil
}

func (w *lowerMTUWriter) WriterMTU() int       { return w.limit }
func (w *lowerMTUWriter) Upstream() any        { return nil }
func (w *lowerMTUWriter) Close() error         { return nil }
func (w *lowerMTUWriter) LocalAddr() net.Addr  { return nil }
func (w *lowerMTUWriter) RemoteAddr() net.Addr { return nil }

// --- capability guard -----------------------------------------------------------

func TestStreamMTU_RefusesWithoutFullCapabilities(t *testing.T) {
	// Wrapping requires a real ExtendedConn. A writer-only conn would have to have its
	// reader half invented, and the wrapper must decline rather than guess.
	cases := []struct {
		name string
		conn net.Conn
	}{
		{"plain conn with no buffer methods", &plainConn{}},
		{"writer-only conn", &writerOnlyConn{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Same(t, tc.conn, withStreamMTU(tc.conn),
				"a conn without the full extended surface must be returned unchanged")
		})
	}
}

// writerOnlyConn can write buffers but cannot read them.
type writerOnlyConn struct {
	nopConn
}

func (c *writerOnlyConn) WriteBuffer(*buf.Buffer) error { return nil }
func (c *writerOnlyConn) Write(p []byte) (int, error)   { return len(p), nil }
func (c *writerOnlyConn) Close() error                  { return nil }
func (c *writerOnlyConn) LocalAddr() net.Addr           { return nil }
func (c *writerOnlyConn) RemoteAddr() net.Addr          { return nil }

// --- server-first handshake -----------------------------------------------------

// TestStreamMTU_ServerFirstHandshakeStillKicks is the end-to-end shape of the
// NeedHandshake regression.
//
// Checking the interface is necessary but not sufficient: what matters is that route's
// decision still comes out true, because that decision is what makes it issue the
// Write(nil) that starts the conversation on SMTP, IMAP and POP3. So this reproduces the
// decision route.NewConnection makes, with the wrapper in the destination position.
func TestStreamMTU_ServerFirstHandshakeStillKicks(t *testing.T) {
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	sink := &copySink{}
	real := method.DialEarlyConn(sink, parseSocksaddr(t))
	wrapped := withStreamMTU(real)

	// This is route.kickWriteHandshake's guard verbatim.
	require.True(t, N.NeedHandshakeForWrite(wrapped),
		"route would skip the handshake kick entirely, and a server-first protocol would hang")

	// The kick itself is a Write(nil): no payload, and its success is measured by the
	// handshake being consumed rather than by bytes at the sink. SS2022 writes the salt
	// on this call and flushes it with the first frame, so asserting on sink bytes here
	// would fail for a reason that has nothing to do with the wrapper - which is exactly
	// what the first version of this test did.
	wrote, err := wrapped.Write(nil)
	require.NoError(t, err, "the handshake kick must not fail")
	require.Equal(t, 0, wrote, "a kick write carries no payload")

	require.False(t, N.NeedHandshakeForWrite(wrapped),
		"the kick must actually consume the handshake, not be swallowed by the wrapper")
}

// TestStreamMTU_ServerFirstHandshakeHiddenByOldWrapper documents what the previous
// wrapper did, so the test above cannot silently stop covering it.
func TestStreamMTU_ServerFirstHandshakeHiddenByOldWrapper(t *testing.T) {
	// The old wrapper embedded net.Conn and forwarded neither ReadBuffer nor
	// NeedHandshake. This fixture reproduces that shape directly, and asserts that the
	// guard route uses would have come out FALSE - which is the bug.
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")
	sink := &copySink{}
	real := method.DialEarlyConn(sink, parseSocksaddr(t))

	oldStyle := &oldStyleWrapper{Conn: real}
	require.False(t, N.NeedHandshakeForWrite(oldStyle),
		"the old shape hid NeedHandshake, so route would not have kicked the handshake")

	// The new wrapper must not behave that way.
	require.True(t, N.NeedHandshakeForWrite(withStreamMTU(real)))
}

// oldStyleWrapper mirrors the previous mtuAdvertisingConn: embeds net.Conn and exposes
// only the writer-side capabilities.
type oldStyleWrapper struct {
	net.Conn
}

func (c *oldStyleWrapper) WriteBuffer(buffer *buf.Buffer) error {
	return c.Conn.(N.ExtendedWriter).WriteBuffer(buffer)
}

func (c *oldStyleWrapper) FrontHeadroom() int { return 27 }
func (c *oldStyleWrapper) RearHeadroom() int  { return 16 }
func (c *oldStyleWrapper) WriterMTU() int     { return streamWriterMTU() }
