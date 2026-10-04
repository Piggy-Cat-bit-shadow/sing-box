// Package trafficsched is documented in doc.go, including the measured evidence for which
// scheduling model earns a place in the data path and why the others do not.
//
// This file documents the gate's own contract, because that contract is what makes any of it
// possible:
//
//	WriterReplaceable() == false   never unwrapped -> the scheduler stays in the write PATH
//	Upstream() any                 common.Cast probe channel -> the handshake stays VISIBLE
//	capability methods             delegate LIVE, never snapshot
//	optional capabilities          advertised only where the upstream chain has them
//
// # Two rules that are easy to get backwards
//
//  1. Capabilities must be advertised truthfully, because sing discovers them by direct type
//     assertion as well as through common.Cast. A wrapper that unconditionally implemented every
//     optional interface would change path selection: CreateVectorisedWriter and
//     CreatePacketBatchWriter are direct assertions, so the gate has to answer them itself rather
//     than rely on Upstream().
//
//  2. The shape is chosen once, at flow setup, but the VALUES are read live. sing's own VLESS
//     connection proves why: the same *vless.Conn changes NeedHandshakeForWrite, WriterReplaceable
//     and FrontHeadroom across its handshake without changing its method set. A gate that
//     snapshotted geometry would be wrong from the first write on.
//
// # The one deliberate deviation: headroom is counted twice by sing's chain walkers
//
// N.CalculateFrontHeadroom walks WithUpstreamWriter / common.WithUpstream *without* consulting
// WriterReplaceable and SUMS what it finds. The gate cannot opt out of that walk while keeping
// Upstream() for handshake probing (they are the same method), and it must report the real
// headroom for N.WriteOwnedBuffer, which resolves geometry from the gate alone. Reporting the real
// value is the safe side of the trade: it keeps WriteOwnedBuffer's decision identical to the
// ungated one, at the cost of a doubled front/rear headroom in the copy loop's buffer sizing. That
// cost is bounded - the implementers in this tree declare tens to hundreds of bytes - and it is
// pinned by a test so it cannot grow silently. Reporting zero instead would hand a
// headroom-starved buffer to a framing writer, and buf.Buffer.ExtendHeader panics on exactly that.
//
// MTU is the one geometry that must NOT be reported this way: sing resolves it as a MINIMUM and
// reads 0 as unconstrained, while WriteOwnedBuffer reads it as a hard ceiling, so the gate
// advertises WriterWithMTU only when the upstream chain actually has one.
package trafficsched

import (
	"io"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// gateCore carries the state every gate shape shares.
//
// It is embedded rather than composed so that a shape can add exactly the capability methods its
// upstream supports without repeating the write path.
type gateCore struct {
	flow     *Flow
	upstream io.Writer
}

// admit asks the scheduler for permission to hand n bytes to the outbound.
//
// It is the single scheduling point of the gate. Nothing else on the write path consults the
// scheduler, and the closed case is reported as an error rather than a silent pass so a shutting
// down scheduler cannot be mistaken for a free one.
func (c *gateCore) admit(n int) error {
	if c.flow == nil {
		return nil
	}
	return c.flow.wait(n)
}

// write performs the gated write and is shared by every shape, so the ordering rule
// (admit -> write -> release the service slot) exists in exactly one place.
func (c *gateCore) write(p []byte) (int, error) {
	err := c.admit(len(p))
	if err != nil {
		return 0, err
	}
	n, err := c.upstream.Write(p)
	if c.flow != nil {
		c.flow.done()
	}
	return n, err
}

func (c *gateCore) WriterReplaceable() bool { return false }

func (c *gateCore) UpstreamWriter() any { return c.upstream }

// Upstream is the common.Cast probe channel. N.NeedHandshakeForWriteAny and every other
// common.Cast probe walk through it, and NOT through WriterReplaceable, which is what makes a
// gate that is invisible to unwrapping still visible to capability probing.
func (c *gateCore) Upstream() any { return c.upstream }

// FrontHeadroom reports the requirement of the WHOLE upstream chain, because
// bufio.WriteOwnedBuffer resolves it from the gate alone and will not walk past a
// non-replaceable writer.
func (c *gateCore) FrontHeadroom() int { return N.CalculateFrontHeadroom(c.upstream) }

// RearHeadroom reports the requirement of the whole upstream chain. See FrontHeadroom.
func (c *gateCore) RearHeadroom() int { return N.CalculateRearHeadroom(c.upstream) }

// CreateVectorisedWriter is a DIRECT type assertion in bufio.CreateVectorisedWriter, so Upstream()
// does not preserve it: the gate has to answer itself.
//
// It delegates the whole creation to the upstream rather than building something of its own,
// which keeps the upstream's own syscall-backed choice intact, and wraps the result so the
// scheduler still sees the batch. Returning false when the upstream has no vectorised writer is
// the same answer the engine would have reached without a gate.
func (c *gateCore) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	upstream, created := bufio.CreateVectorisedWriter(c.upstream)
	if !created {
		return nil, false
	}
	return &gateVectorisedWriter{core: c, upstream: upstream}, true
}

// gateVectorisedWriter keeps the gate in the vectorised write path.
//
// Without it, delegating vectorised creation would hand the engine a writer that talks to the
// upstream's syscall layer directly, and every byte after the copy loop's increase-buffer
// threshold - that is, exactly the bulk transfer the scheduler exists to deprioritise - would
// bypass the scheduler.
type gateVectorisedWriter struct {
	core     *gateCore
	upstream N.VectorisedWriter
}

func (w *gateVectorisedWriter) WriteVectorised(buffers []*buf.Buffer) error {
	err := w.core.admit(buf.LenMulti(buffers))
	if err != nil {
		buf.ReleaseMulti(buffers)
		return err
	}
	// The upstream vectorised writer owns the buffers from here, including on error.
	err = w.upstream.WriteVectorised(buffers)
	if w.core.flow != nil {
		w.core.flow.done()
	}
	return err
}

func (w *gateVectorisedWriter) Upstream() any { return w.upstream }

// gateWriter is the shape for an upstream that is a plain io.Writer: it must NOT claim WriteBuffer
// or the engine would take a buffer path the upstream cannot honour.
type gateWriter struct {
	gateCore
}

func (g *gateWriter) Write(p []byte) (int, error) { return g.write(p) }

// gateWriterMTU adds WriterMTU for an upstream chain that actually constrains the writer MTU.
//
// The split is not cosmetic. sing's chained MTU resolution takes the MINIMUM over the chain, so a
// gate that always implemented WriterMTU would have to invent a value for an upstream that has
// none: math.MaxInt keeps WriteOwnedBuffer's length check vacuous but makes
// ReadWaitOptions.NewBuffer() compute `MaxInt + overhead`, which overflows to a negative size and
// collapses the read buffer to a single byte. Not implementing the interface is the only value
// that is correct in both places.
type gateWriterMTU struct {
	gateWriter
	mtu N.WriterWithMTU
}

func (g *gateWriterMTU) WriterMTU() int { return g.mtu.WriterMTU() }

// gateExtended is the shape for an upstream that is an ExtendedWriter, so the WriteBuffer path is
// preserved rather than degraded to a raw copy.
type gateExtended struct {
	gateWriter
	extended N.ExtendedWriter
}

// WriteBuffer forwards ownership unchanged: the upstream's WriteBuffer releases the buffer on both
// the nil and the non-nil return, so the gate must not release it and must not double-release it.
func (g *gateExtended) WriteBuffer(buffer *buf.Buffer) error {
	err := g.admit(buffer.Len())
	if err != nil {
		// The buffer never reached the upstream, so the gate owns it and must release it.
		buffer.Release()
		return err
	}
	err = g.extended.WriteBuffer(buffer)
	if g.flow != nil {
		g.flow.done()
	}
	return err
}

type gateExtendedMTU struct {
	gateExtended
	mtu N.WriterWithMTU
}

func (g *gateExtendedMTU) WriterMTU() int { return g.mtu.WriterMTU() }

var (
	_ io.Writer                = (*gateWriter)(nil)
	_ io.Writer                = (*gateExtended)(nil)
	_ N.WriterWithUpstream     = (*gateWriter)(nil)
	_ N.WriterWithUpstream     = (*gateExtended)(nil)
	_ N.WithUpstreamWriter     = (*gateWriter)(nil)
	_ N.WithUpstreamWriter     = (*gateExtended)(nil)
	_ N.ExtendedWriter         = (*gateExtended)(nil)
	_ N.ExtendedWriter         = (*gateExtendedMTU)(nil)
	_ N.WriterWithMTU          = (*gateWriterMTU)(nil)
	_ N.WriterWithMTU          = (*gateExtendedMTU)(nil)
	_ N.VectorisedWriteCreator = (*gateWriter)(nil)
	_ N.VectorisedWriteCreator = (*gateExtended)(nil)
)

// NewGate wraps upstream so that every byte written through it is admitted by flow first.
//
// The shape is chosen once here, from the upstream's capabilities, and every later capability
// question is answered by delegating a live call rather than by replaying this inspection.
//
// A nil flow produces a gate that always admits immediately, which is the pass-through
// measurement baseline and the shape the benchmarks compare against.
func NewGate(upstream io.Writer, flow *Flow) io.Writer {
	extended, isExtended := upstream.(N.ExtendedWriter)
	mtu, hasMTU := upstreamMTU(upstream)
	switch {
	case isExtended && hasMTU:
		return &gateExtendedMTU{gateExtended{gateWriter{gateCore{flow: flow, upstream: upstream}}, extended}, mtu}
	case isExtended:
		return &gateExtended{gateWriter{gateCore{flow: flow, upstream: upstream}}, extended}
	case hasMTU:
		return &gateWriterMTU{gateWriter{gateCore{flow: flow, upstream: upstream}}, mtu}
	default:
		return &gateWriter{gateCore{flow: flow, upstream: upstream}}
	}
}

// upstreamMTU reports the writer MTU of the upstream chain, and whether the chain constrains it at
// all. Zero means unconstrained everywhere in sing, and the gate must preserve that rather than
// translate it into a number.
func upstreamMTU(upstream io.Writer) (N.WriterWithMTU, bool) {
	if mtu := N.CalculateMTU(nil, upstream); mtu > 0 {
		return liveMTU{upstream}, true
	}
	return nil, false
}

// liveMTU re-reads the chain MTU on every call, because the VLESS finding applies to MTU too: a
// connection can start unconstrained and become constrained, or the reverse, without the object
// changing.
type liveMTU struct {
	upstream io.Writer
}

func (m liveMTU) WriterMTU() int { return N.CalculateMTU(nil, m.upstream) }

// --- packets ---------------------------------------------------------------------------------

// gatePacketCore carries the state every packet gate shape shares.
type gatePacketCore struct {
	flow     *Flow
	upstream N.PacketWriter
}

func (c *gatePacketCore) admit(n int) error {
	if c.flow == nil {
		return nil
	}
	return c.flow.wait(n)
}

func (c *gatePacketCore) WriterReplaceable() bool { return false }

func (c *gatePacketCore) UpstreamWriter() any { return c.upstream }

func (c *gatePacketCore) Upstream() any { return c.upstream }

func (c *gatePacketCore) FrontHeadroom() int { return N.CalculateFrontHeadroom(c.upstream) }

func (c *gatePacketCore) RearHeadroom() int { return N.CalculateRearHeadroom(c.upstream) }

// gatePacketWriter is the packet shape for an upstream chain without a writer MTU.
type gatePacketWriter struct {
	gatePacketCore
}

func (g *gatePacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	err := g.admit(buffer.Len())
	if err != nil {
		buffer.Release()
		return err
	}
	// The upstream owns the buffer from here, including on error.
	err = g.upstream.WritePacket(buffer, destination)
	if g.flow != nil {
		g.flow.done()
	}
	return err
}

// CreatePacketBatchWriter is a DIRECT assertion in bufio.CreatePacketBatchWriter, and the
// syscall fallback below it needs a raw connection the gate deliberately does not expose.
// Omitting this would silently turn every UDP batch into a per-packet loop.
func (g *gatePacketWriter) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	upstream, created := bufio.CreatePacketBatchWriter(g.upstream)
	if !created {
		return nil, false
	}
	return &gatePacketBatchWriter{core: &g.gatePacketCore, upstream: upstream}, true
}

func (g *gatePacketWriter) CreateConnectedPacketBatchWriter() (N.ConnectedPacketBatchWriter, bool) {
	upstream, created := bufio.CreateConnectedPacketBatchWriter(g.upstream)
	if !created {
		return nil, false
	}
	return &gateConnectedPacketBatchWriter{core: &g.gatePacketCore, upstream: upstream}, true
}

// gatePacketWriterMTU adds WriterMTU for an upstream chain that constrains it. See gateWriterMTU
// for why the interface must be absent rather than neutral when it does not.
type gatePacketWriterMTU struct {
	gatePacketWriter
	mtu N.WriterWithMTU
}

func (g *gatePacketWriterMTU) WriterMTU() int { return g.mtu.WriterMTU() }

// gatePacketBatchWriter admits one batch as ONE scheduling unit, sized by the sum of its packet
// lengths.
//
// The physical batch is never split: a batch is what the read waiter produced and what the
// upstream syscall can send in one call, so cutting it up for accounting would trade a scheduler
// artefact for a real per-packet cost.
type gatePacketBatchWriter struct {
	core     *gatePacketCore
	upstream N.PacketBatchWriter
}

func (w *gatePacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	err := w.core.admit(buf.LenMulti(buffers))
	if err != nil {
		// The batch never reached the upstream, so the gate owns every buffer in it.
		buf.ReleaseMulti(buffers)
		return err
	}
	err = w.upstream.WritePacketBatch(buffers, destinations)
	if w.core.flow != nil {
		w.core.flow.done()
	}
	return err
}

func (w *gatePacketBatchWriter) Upstream() any { return w.upstream }

type gateConnectedPacketBatchWriter struct {
	core     *gatePacketCore
	upstream N.ConnectedPacketBatchWriter
}

func (w *gateConnectedPacketBatchWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	err := w.core.admit(buf.LenMulti(buffers))
	if err != nil {
		buf.ReleaseMulti(buffers)
		return err
	}
	err = w.upstream.WriteConnectedPacketBatch(buffers)
	if w.core.flow != nil {
		w.core.flow.done()
	}
	return err
}

func (w *gateConnectedPacketBatchWriter) Upstream() any { return w.upstream }

var (
	_ N.PacketWriter                     = (*gatePacketWriter)(nil)
	_ N.PacketWriter                     = (*gatePacketWriterMTU)(nil)
	_ N.WriterWithUpstream               = (*gatePacketWriter)(nil)
	_ N.WriterWithMTU                    = (*gatePacketWriterMTU)(nil)
	_ N.PacketBatchWriteCreator          = (*gatePacketWriter)(nil)
	_ N.ConnectedPacketBatchWriteCreator = (*gatePacketWriter)(nil)
	_ N.PacketBatchWriter                = (*gatePacketBatchWriter)(nil)
	_ N.ConnectedPacketBatchWriter       = (*gateConnectedPacketBatchWriter)(nil)
)

// NewPacketGate wraps upstream so every packet, and every batch, is admitted by flow first.
//
// A batch is one scheduling unit sized by its total bytes; it is never decomposed.
func NewPacketGate(upstream N.PacketWriter, flow *Flow) N.PacketWriter {
	mtu, hasMTU := upstreamPacketMTU(upstream)
	base := gatePacketWriter{gatePacketCore{flow: flow, upstream: upstream}}
	if hasMTU {
		return &gatePacketWriterMTU{base, mtu}
	}
	return &base
}

func upstreamPacketMTU(upstream N.PacketWriter) (N.WriterWithMTU, bool) {
	if mtu := N.CalculateMTU(nil, upstream); mtu > 0 {
		return livePacketMTU{upstream}, true
	}
	return nil, false
}

type livePacketMTU struct {
	upstream N.PacketWriter
}

func (m livePacketMTU) WriterMTU() int { return N.CalculateMTU(nil, m.upstream) }
