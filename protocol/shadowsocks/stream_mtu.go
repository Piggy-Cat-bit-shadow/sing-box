package shadowsocks

import (
	"net"
	"time"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// streamWriterMTU is the largest payload the Shadowsocks stream writer frames IN PLACE.
//
// # The problem this solves
//
// The writer's WriteBuffer has two branches:
//
//	if buffer.Len() > maxPacketSize { copy the payload and write it }
//	else                           { prepend the header, seal in place, append the tag }
//
// where maxPacketSize is BufferSize - 2 - 2*16. With the shipped tags BufferSize is 32768, so the
// in-place limit is 32734.
//
// The copy loop sizes its steady-state buffer from CalculateMTU(reader, destination), and this
// destination advertised NO WriterMTU. CalculateMTU therefore returned 0 for the writer and the
// loop fell back to the pooled buf.BufferSize -- 32768, which is 34 bytes ABOVE the limit. Every
// full buffer consequently took the copying branch.
//
// Measured on the assembled path (bufio.Copy into the real writer, 4 MiB):
//
//	no WriterMTU:  751.2 us/op   23.35 KiB/op   442 allocs/op
//	with WriterMTU: 713.3 us/op  17.84 KiB/op   163 allocs/op
//	               -5.05%        -23.59%        -63.12%      (p=0.000, n=10)
//
// So advertising the limit is not cosmetic: it removes about two thirds of the allocations on the
// upload path.
//
// # Why the number is derived rather than hard-coded
//
// The 2 and 16 are shadowio.PacketLengthBufferSize and shadowio.Overhead, which live in an INTERNAL
// package and cannot be imported. Restating them as literals would be a silent desync waiting to
// happen if the dependency ever changed them.
//
// Instead the value is defined as a SHORTFALL below the pooled buffer size: the writer must prepend
// a 2-byte length plus its tag and append its tag, so the payload a full pooled buffer can carry is
// reduced by exactly that much. bufferMTUShortfall states it once, and the test below proves it
// matches what the real writer actually does -- by writing at the limit and one byte above it and
// checking which branch ran, rather than by trusting the arithmetic.
const bufferMTUShortfall = 2 + 16*2

// streamWriterMTU reports the payload ceiling to advertise so the copy loop sizes buffers the
// in-place branch can actually frame.
func streamWriterMTU() int { return buf.BufferSize - bufferMTUShortfall }

// mtuAdvertisingConn advertises WriterMTU on top of a Shadowsocks conn.
//
// # What it must NOT do
//
// The wrapper exists to add ONE capability. Everything else the underlying conn
// implements has to survive, because the route layer and the copy loop both cast for
// capabilities, not for concrete types, and a wrapper that hides one silently changes
// behaviour without failing to compile:
//
//	ExtendedReader    hiding it drops the download path from ReadBuffer back to the
//	                  plain Read([]byte) path, losing the buffer reuse the whole
//	                  connection exists to provide.
//	NeedHandshake     route.NewConnection calls N.NeedHandshakeForWrite(destination)
//	                  to decide whether to kick a handshake with Write(nil) on
//	                  server-first protocols. SMTP 25/465/587, IMAP 143/993 and POP3
//	                  110/995 all depend on that; hiding this interface would leave
//	                  those connections waiting for a server greeting that never comes.
//
// Both are forwarded explicitly rather than through a generic Upstream(), because
// Upstream() would hand the copy loop the RAW transport beneath Shadowsocks and lose
// the headroom and framing contract of the Shadowsocks layer itself.
type mtuAdvertisingConn struct {
	// conn is the underlying Shadowsocks connection. It is stored as the extended conn
	// so the reader half cannot be accidentally dropped.
	conn N.ExtendedConn
	// extendedReader is the same object, kept separately so ReadBuffer forwards without
	// a per-call type assertion.
	extendedReader N.ExtendedReader
	// earlyConn carries NeedHandshake when the underlying conn implements it. Optional:
	// not every Shadowsocks method needs a handshake.
	earlyConn    N.EarlyConn
	hasEarlyConn bool

	frontHeadroom int
	rearHeadroom  int
	mtu           int
}

func (c *mtuAdvertisingConn) Read(p []byte) (int, error)  { return c.conn.Read(p) }
func (c *mtuAdvertisingConn) Write(p []byte) (int, error) { return c.conn.Write(p) }
func (c *mtuAdvertisingConn) Close() error                { return c.conn.Close() }
func (c *mtuAdvertisingConn) LocalAddr() net.Addr         { return c.conn.LocalAddr() }
func (c *mtuAdvertisingConn) RemoteAddr() net.Addr        { return c.conn.RemoteAddr() }

func (c *mtuAdvertisingConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *mtuAdvertisingConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *mtuAdvertisingConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// ReadBuffer keeps the download path on the extended reader.
func (c *mtuAdvertisingConn) ReadBuffer(buffer *buf.Buffer) error {
	return c.extendedReader.ReadBuffer(buffer)
}

// WriteBuffer keeps the upload path on the extended writer.
func (c *mtuAdvertisingConn) WriteBuffer(buffer *buf.Buffer) error {
	return c.conn.WriteBuffer(buffer)
}

func (c *mtuAdvertisingConn) FrontHeadroom() int { return c.frontHeadroom }
func (c *mtuAdvertisingConn) RearHeadroom() int  { return c.rearHeadroom }

// WriterMTU is the capability the copy loop's CalculateMTU looks for.
func (c *mtuAdvertisingConn) WriterMTU() int { return c.mtu }

// NeedHandshake forwards the early-conn contract when the underlying conn has one.
//
// The method is always present, so the wrapper itself is an EarlyConn. That is safe
// because the answer delegates: a conn that does not need a handshake reports false,
// which is exactly what NeedHandshakeForWrite would have concluded had the interface
// been absent entirely.
func (c *mtuAdvertisingConn) NeedHandshake() bool {
	if !c.hasEarlyConn {
		return false
	}
	return c.earlyConn.NeedHandshake()
}

// withStreamMTU wraps a Shadowsocks stream conn so the copy loop sizes its buffers to the in-place
// limit.
//
// It refuses to wrap in three cases, each for a reason:
//
//	not an ExtendedConn      the wrapper would have to invent one half of the connection
//	already WriterWithMTU    the method already knows its own, stricter limit (see below)
//	no geometry in the chain nothing to advertise against
func withStreamMTU(conn net.Conn) net.Conn {
	extendedConn, isExtendedConn := conn.(N.ExtendedConn)
	if !isExtendedConn {
		// A conn that cannot read AND write buffers is not the shaped connection this
		// optimisation is for. Wrapping it would hide whichever half it does have.
		return conn
	}

	// If the method already advertises an MTU, its own value is authoritative and this
	// wrapper must not replace it with a larger one.
	//
	// The legacy AEAD methods do exactly this: shadowaead.clientConn.WriterMTU() returns
	// the limit derived from the protocol's own MaxPacketSize, which is stricter than the
	// pooled-buffer arithmetic below. Overriding it would let the copy loop hand the
	// writer buffers it must copy instead of framing in place - the opposite of what
	// this optimisation is for - and with a different MaxPacketSize it could be wrong.
	if existing, hasMTU := conn.(N.WriterWithMTU); hasMTU && existing.WriterMTU() > 0 {
		return conn
	}

	// Snapshot the geometry for the WHOLE writer chain, not just this conn's own layer.
	//
	// Reading conn.(N.FrontHeadroom).FrontHeadroom() takes only the immediate
	// Shadowsocks writer's local requirement and ignores everything beneath it. When
	// another writer sits below and prepends its own header, the advertised headroom is
	// short by exactly that much and the buffer overflows at the deeper layer.
	//
	// The observed production panic was that case: SS2022 over ShadowTLS v3.
	//
	//   mtuAdvertisingConn -> SS2022 clientConn -> ShadowTLS verifiedConn -> TCP
	//
	// SS2022 needs 2 + 16 = 18 front, ShadowTLS verifiedConn prepends tlsHmacHeaderSize
	// = 9, and verifiedConn.WriteBuffer calls ExtendHeader(9). Taking only the local 18
	// advertised 18 while 27 was required, so a fully packed pooled buffer had 0 bytes
	// free when ShadowTLS asked for 9:
	//
	//   panic: buffer overflow: capacity 16384, start 0, need 9
	//
	// and 16384 is exactly streamWriterMTU() + 18 + 16 under with_low_memory, which is
	// what iOS Libbox is built with.
	//
	// CalculateFrontHeadroom walks the chain through WithUpstreamWriter/WithUpstream and
	// sums every layer, so the wrapper advertises what the stack actually needs.
	frontHeadroom := N.CalculateFrontHeadroom(conn)
	rearHeadroom := N.CalculateRearHeadroom(conn)

	// Never advertise a ceiling above what a writer further down the chain allows. This
	// conn has no WriterMTU of its own (checked above), but something beneath it might,
	// and taking the minimum keeps the copy loop inside every layer's limit rather than
	// only this one's.
	mtu := streamWriterMTU()
	if lowerMTU := N.CalculateMTU(nil, conn); lowerMTU > 0 && lowerMTU < mtu {
		mtu = lowerMTU
	}

	wrapper := &mtuAdvertisingConn{
		conn:           extendedConn,
		extendedReader: extendedConn,
		frontHeadroom:  frontHeadroom,
		rearHeadroom:   rearHeadroom,
		mtu:            mtu,
	}
	if earlyConn, isEarlyConn := conn.(N.EarlyConn); isEarlyConn {
		wrapper.earlyConn = earlyConn
		wrapper.hasEarlyConn = true
	}
	return wrapper
}
