package route

import (
	"sync/atomic"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
)

// UDP splice diagnostics.
//
// # Why session-level and not packet-level
//
// When a TUN UDP flow can be spliced, sing-tun hands packets straight between the
// TUN socket and the outbound socket and they never enter userspace. When it cannot,
// both directions run bufio.CopyPacket goroutines instead - a copy per packet plus
// scheduling and wakeups. That difference is the resource cost this fork cares
// about, and the symptom on a phone is heat.
//
// The decision is made once per session, not once per packet, so the counting here
// is once per session too. A per-packet counter in this path would itself become a
// source of the contention being investigated: an atomic add per datagram at video
// call rates is measurable, and per-packet logging or error strings would be worse.
// Each session increments one counter a single time and stores nothing else.
//
// # What these counters can and cannot tell you
//
// They answer "of the UDP sessions handled here, how many spliced, and for those
// that did not, at which point did the decision fail". That is what a real-device
// A/B run needs, and it is the whole of the claim: this is observation, not
// optimisation. No production behaviour, eligibility rule or wrapper semantics
// change, and no path is made spliceable that was not already.
//
// The reasons correspond one-to-one with the points the existing code can actually
// distinguish. There are deliberately no speculative entries, because a reason that
// cannot be produced by the code would be a lie in a report.

// spliceReason identifies where a splice decision ended.
//
// It is a uint8 so that the failure path costs a single byte-wide atomic add. It is
// not exposed on any public API: the only consumer is the diagnostics snapshot
// below, which exists for tests and for on-device observation.
type spliceReason uint8

const (
	// spliceReasonSuccess: the flow was spliced and packets bypass userspace.
	spliceReasonSuccess spliceReason = iota

	// --- source side, from unwrapSpliceSource -------------------------------
	// The source is the TUN-side packet connection. Without a tun.UDPNatConn
	// underneath there is nothing to splice from.

	// spliceReasonSourceNotNAT: the outermost writer is not a tun.UDPNatConn.
	spliceReasonSourceNotNAT
	// spliceReasonSourceReaderWriterMismatch: reader and writer resolve to
	// different NAT connections, so splicing would join two flows.
	spliceReasonSourceReaderWriterMismatch
	// spliceReasonSourceNotReplaceable: a wrapper refused to be replaced. This is
	// the case that matters most in practice, because such a wrapper usually just
	// forwards packets and its cost is not obvious.
	spliceReasonSourceNotReplaceable
	// spliceReasonSourceNoUpstream: the walk ended without reaching a NAT conn and
	// without an upstream to follow.
	spliceReasonSourceNoUpstream

	// --- target side, from unwrapSpliceTarget ------------------------------
	// The target is the outbound-side packet connection.

	// spliceReasonTargetCounterMismatch: a read/write counter pair that does not
	// unwrap symmetrically.
	spliceReasonTargetCounterMismatch
	// spliceReasonTargetOffloadNotSocket: offload was offered but the upstream is
	// not a SpliceSocket, so packets could not be handed to the socket directly.
	spliceReasonTargetOffloadNotSocket
	// spliceReasonTargetNotReplaceable: a wrapper refused replacement.
	spliceReasonTargetNotReplaceable
	// spliceReasonTargetNoUpstream: the walk ended with no socket and no upstream.
	spliceReasonTargetNoUpstream
	// spliceReasonTargetUpstreamMismatch: reader and writer upstreams differ.
	spliceReasonTargetUpstreamMismatch

	// --- attach and platform ------------------------------------------------

	// spliceReasonAttachFailed: the socket was found but handing it to the NAT conn
	// failed, typically because the socket already had an owner or was closing.
	spliceReasonAttachFailed
	// spliceReasonPlatformUnsupported: the flow was eligible but the platform has
	// no splice support, so it fell back. This is an expected steady state rather
	// than a defect.
	spliceReasonPlatformUnsupported
)

// String returns a stable lowercase name, for tests and diagnostic output.
//
// It is only ever called off the packet path - when reading a snapshot - so the
// switch here cannot affect forwarding.
func (r spliceReason) String() string {
	switch r {
	case spliceReasonSuccess:
		return "success"
	case spliceReasonSourceNotNAT:
		return "source_not_nat"
	case spliceReasonSourceReaderWriterMismatch:
		return "source_reader_writer_mismatch"
	case spliceReasonSourceNotReplaceable:
		return "source_not_replaceable"
	case spliceReasonSourceNoUpstream:
		return "source_no_upstream"
	case spliceReasonTargetCounterMismatch:
		return "target_counter_mismatch"
	case spliceReasonTargetOffloadNotSocket:
		return "target_offload_not_socket"
	case spliceReasonTargetNotReplaceable:
		return "target_not_replaceable"
	case spliceReasonTargetNoUpstream:
		return "target_no_upstream"
	case spliceReasonTargetUpstreamMismatch:
		return "target_upstream_mismatch"
	case spliceReasonAttachFailed:
		return "attach_failed"
	case spliceReasonPlatformUnsupported:
		return "platform_unsupported"
	default:
		return "unknown"
	}
}

// spliceReasonCount is the number of distinct reasons, used to size the counters.
const spliceReasonCount = int(spliceReasonPlatformUnsupported) + 1

// spliceReasonMax is the largest valid reason, for bounds checks.
const spliceReasonMax = spliceReasonPlatformUnsupported

// spliceDiagnostics accumulates session-level splice outcomes.
//
// Access is a single atomic add on the session path and an atomic load per counter
// when a snapshot is taken. There is no lock, no allocation and nothing to contend
// on beyond the counter being incremented, which is the smallest cost that still
// produces a usable ratio on a real device.
type spliceDiagnostics struct {
	counters [spliceReasonCount]atomic.Uint64
}

// record notes one session outcome.
func (d *spliceDiagnostics) record(reason spliceReason) {
	if int(reason) < spliceReasonCount {
		d.counters[reason].Add(1)
	}
}

// snapshot returns a copy of the counters, indexed by reason.
func (d *spliceDiagnostics) snapshot() map[string]uint64 {
	out := make(map[string]uint64, spliceReasonCount)
	for i := range d.counters {
		if v := d.counters[i].Load(); v != 0 {
			out[spliceReason(i).String()] = v
		}
	}
	return out
}

// total returns the number of sessions recorded.
func (d *spliceDiagnostics) total() uint64 {
	var sum uint64
	for i := range d.counters {
		sum += d.counters[i].Load()
	}
	return sum
}

// spliceAttempts counts every session that reached the splice decision, and
// spliceSuccesses counts those that spliced. Kept as two counters rather than
// derived from the reason table so that the success ratio is a single subtraction
// and cannot be skewed by a reason being added later.
type spliceTelemetry struct {
	attempts  atomic.Uint64
	successes atomic.Uint64
}

func (t *spliceTelemetry) recordAttempt() { t.attempts.Add(1) }
func (t *spliceTelemetry) recordSuccess() { t.successes.Add(1) }

// SpliceSnapshot is an immutable view of the splice diagnostics, for tests and for
// on-device observation.
type SpliceSnapshot struct {
	// Attempts is the number of UDP sessions that reached the splice decision.
	Attempts uint64
	// Successes is the number that spliced.
	Successes uint64
	// Reasons counts sessions by the point at which the decision ended, excluding
	// success. Entries are present only when non-zero.
	Reasons map[string]uint64
}

// Ratio returns successes divided by attempts, or 0 with no attempts.
func (s SpliceSnapshot) Ratio() float64 {
	if s.Attempts == 0 {
		return 0
	}
	return float64(s.Successes) / float64(s.Attempts)
}

// SpliceDiagnostics returns the current splice diagnostics.
//
// This is the observation hook for a real-device A/B run: a caller can read it
// before and after a video call and compare the splice ratio and the fallback
// reasons. Reading it allocates a small map and has no effect on forwarding.
func (m *ConnectionManager) SpliceDiagnostics() SpliceSnapshot {
	return SpliceSnapshot{
		Attempts:  m.spliceTelemetry.attempts.Load(),
		Successes: m.spliceTelemetry.successes.Load(),
		Reasons:   m.spliceDiagnostics.snapshot(),
	}
}

// The reason-returning variants below are the originals with a failure reason
// threaded out. Production callers use the two-value forms, which delegate here and
// discard the reason, so behaviour is identical and the reason is only observable
// where something asks for it.

func unwrapSpliceTargetWithReason(conn any, allowOffload bool) (spliceTarget, spliceReason, bool) {
	var target spliceTarget
	for {
		readCounter, isReadCounter := conn.(N.ReadCounter)
		writeCounter, isWriteCounter := conn.(N.WriteCounter)
		if isReadCounter || isWriteCounter {
			if !isReadCounter || !isWriteCounter {
				return spliceTarget{}, spliceReasonTargetCounterMismatch, false
			}
			reader, readCounters := readCounter.UnwrapReader()
			writer, writeCounters := writeCounter.UnwrapWriter()
			if !sameConn(reader, writer) {
				return spliceTarget{}, spliceReasonTargetCounterMismatch, false
			}
			target.readCounters = append(target.readCounters, readCounters...)
			target.writeCounters = append(target.writeCounters, writeCounters...)
			conn = reader
			continue
		}
		packetReadCounter, isPacketReadCounter := conn.(N.PacketReadCounter)
		packetWriteCounter, isPacketWriteCounter := conn.(N.PacketWriteCounter)
		if isPacketReadCounter || isPacketWriteCounter {
			if !isPacketReadCounter || !isPacketWriteCounter {
				return spliceTarget{}, spliceReasonTargetCounterMismatch, false
			}
			reader, readCounters := packetReadCounter.UnwrapPacketReader()
			writer, writeCounters := packetWriteCounter.UnwrapPacketWriter()
			if !sameConn(reader, writer) {
				return spliceTarget{}, spliceReasonTargetCounterMismatch, false
			}
			target.readCounters = append(target.readCounters, readCounters...)
			target.writeCounters = append(target.writeCounters, writeCounters...)
			conn = reader
			continue
		}
		if allowOffload {
			upstream, offload := N.UnwrapPacketOffload(conn)
			if offload != nil {
				socket, isSocket := upstream.(tun.SpliceSocket)
				if !isSocket {
					return spliceTarget{}, spliceReasonTargetOffloadNotSocket, false
				}
				target.socket = socket
				target.offload = offload
				return target, spliceReasonSuccess, true
			}
		}
		readerWithUpstream, isReaderWithUpstream := conn.(N.ReaderWithUpstream)
		if !isReaderWithUpstream || !readerWithUpstream.ReaderReplaceable() {
			return spliceTarget{}, spliceReasonTargetNotReplaceable, false
		}
		writerWithUpstream, isWriterWithUpstream := conn.(N.WriterWithUpstream)
		if !isWriterWithUpstream || !writerWithUpstream.WriterReplaceable() {
			return spliceTarget{}, spliceReasonTargetNotReplaceable, false
		}
		socket, isSocket := conn.(tun.SpliceSocket)
		if isSocket {
			target.socket = socket
			return target, spliceReasonSuccess, true
		}
		withUpstream, hasUpstream := conn.(common.WithUpstream)
		if hasUpstream {
			conn = withUpstream.Upstream()
			continue
		}
		upstreamReader, hasUpstreamReader := conn.(N.WithUpstreamReader)
		upstreamWriter, hasUpstreamWriter := conn.(N.WithUpstreamWriter)
		if !hasUpstreamReader || !hasUpstreamWriter {
			return spliceTarget{}, spliceReasonTargetNoUpstream, false
		}
		reader := upstreamReader.UpstreamReader()
		if !sameConn(reader, upstreamWriter.UpstreamWriter()) {
			return spliceTarget{}, spliceReasonTargetUpstreamMismatch, false
		}
		conn = reader
	}
}

// sameConn reports whether two upstream values refer to the same connection.
//
// The original compared `any(reader) != any(writer)`, which panics for a
// non-comparable dynamic type. Identical behaviour for comparable values, and a
// false result instead of a panic otherwise.
func sameConn(a any, b any) (equal bool) {
	if a == nil || b == nil {
		return a == b
	}
	// Comparing non-comparable dynamic types panics; treat that as "not the same
	// connection", which is the safe direction - it refuses a splice rather than
	// joining two flows.
	defer func() {
		if recover() != nil {
			equal = false
		}
	}()
	return a == b
}

func unwrapSpliceSourceWithReason(conn N.PacketConn) (spliceSource, spliceReason, bool) {
	var source spliceSource
	writer, writeCounters := N.UnwrapCountPacketWriter(conn, nil)
	natWriter, isNATWriter := N.CastPacketWriter[*tun.UDPNatConn](writer)
	if !isNATWriter {
		return spliceSource{}, spliceReasonSourceNotNAT, false
	}
	source.writeCounters = writeCounters
	var reader N.PacketReader = conn
	for {
		readCounter, isReadCounter := reader.(N.PacketReadCounter)
		if isReadCounter {
			upstreamReader, readCounters := readCounter.UnwrapPacketReader()
			source.readCounters = append(source.readCounters, readCounters...)
			reader = upstreamReader
			continue
		}
		natReader, isNATReader := reader.(*tun.UDPNatConn)
		if isNATReader {
			if natReader != natWriter {
				return spliceSource{}, spliceReasonSourceReaderWriterMismatch, false
			}
			source.natConn = natReader
			return source, spliceReasonSuccess, true
		}
		cachedReader, isCached := reader.(N.CachedPacketReader)
		if isCached {
			source.cachedReaders = append(source.cachedReaders, cachedReader)
		} else {
			readerWithUpstream, isReaderWithUpstream := reader.(N.ReaderWithUpstream)
			if !isReaderWithUpstream || !readerWithUpstream.ReaderReplaceable() {
				return spliceSource{}, spliceReasonSourceNotReplaceable, false
			}
		}
		withUpstream, hasUpstream := reader.(common.WithUpstream)
		if hasUpstream {
			reader, _ = withUpstream.Upstream().(N.PacketReader)
		} else {
			upstreamReader, hasUpstreamReader := reader.(N.WithUpstreamReader)
			if !hasUpstreamReader {
				return spliceSource{}, spliceReasonSourceNoUpstream, false
			}
			reader, _ = upstreamReader.UpstreamReader().(N.PacketReader)
		}
		if reader == nil {
			return spliceSource{}, spliceReasonSourceNoUpstream, false
		}
	}
}
