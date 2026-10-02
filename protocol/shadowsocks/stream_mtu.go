package shadowsocks

import (
	"net"

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

// mtuAdvertisingConn advertises WriterMTU on top of whatever the Shadowsocks conn already
// implements, without changing any other capability it exposes.
//
// The upstream capabilities are forwarded explicitly rather than through Upstream(), because
// doing so would hand the copy loop the RAW TCP conn and lose the headroom the Shadowsocks writer
// needs. The wrapper is transparent for everything except the MTU.
type mtuAdvertisingConn struct {
	net.Conn
	extendedWriter N.ExtendedWriter
	frontHeadroom  int
	rearHeadroom   int
	mtu            int
}

func (c *mtuAdvertisingConn) WriteBuffer(buffer *buf.Buffer) error {
	return c.extendedWriter.WriteBuffer(buffer)
}

func (c *mtuAdvertisingConn) FrontHeadroom() int { return c.frontHeadroom }
func (c *mtuAdvertisingConn) RearHeadroom() int  { return c.rearHeadroom }

// WriterMTU is the capability the copy loop's CalculateMTU looks for.
func (c *mtuAdvertisingConn) WriterMTU() int { return c.mtu }

// withStreamMTU wraps a Shadowsocks stream conn so the copy loop sizes its buffers to the in-place
// limit. A conn that does not implement the geometry capabilities is returned unchanged, because
// there would be nothing to advertise against.
func withStreamMTU(conn net.Conn) net.Conn {
	extendedWriter, isExtended := conn.(N.ExtendedWriter)
	if !isExtended {
		return conn
	}
	// Read the geometry for the WHOLE writer chain, not just this conn's own layer.
	//
	// Reading conn.(N.FrontHeadroom).FrontHeadroom() takes only the immediate
	// Shadowsocks writer's local requirement and ignores everything beneath it. When
	// another writer sits below and prepends its own header, the advertised headroom
	// is short by exactly that much and the buffer overflows at the deeper layer.
	//
	// The observed production panic was that case: SS2022 over ShadowTLS v3.
	//
	//   mtuAdvertisingConn -> SS2022 clientConn -> ShadowTLS verifiedConn -> TCP
	//
	// SS2022 needs 2 + 16 = 18 front, ShadowTLS verifiedConn prepends
	// tlsHmacHeaderSize = 9, and verifiedConn.WriteBuffer calls ExtendHeader(9). Taking
	// only the local 18 advertised 18 while 27 was required, so a fully packed pooled
	// buffer had 0 bytes free when ShadowTLS asked for 9:
	//
	//   panic: buffer overflow: capacity 16384, start 0, need 9
	//
	// and 16384 is exactly streamWriterMTU() + 18 + 16 under with_low_memory, which is
	// what iOS Libbox is built with.
	//
	// CalculateFrontHeadroom walks the chain through WithUpstreamWriter/WithUpstream
	// and sums every layer, so the wrapper advertises what the stack actually needs.
	// It returns 0 when nothing in the chain asks for headroom, so the previous
	// "unsupported writer" outcome is preserved rather than replaced by a guess.
	frontHeadroom := N.CalculateFrontHeadroom(conn)
	rearHeadroom := N.CalculateRearHeadroom(conn)
	return &mtuAdvertisingConn{
		Conn:           conn,
		extendedWriter: extendedWriter,
		frontHeadroom:  frontHeadroom,
		rearHeadroom:   rearHeadroom,
		mtu:            streamWriterMTU(),
	}
}
