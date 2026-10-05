package route

import (
	"fmt"
	"reflect"
	"strings"
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

	// spliceReasonSpliceRejected: the flow was eligible - source and target both unwrapped
	// - but tun's Splice returned false.
	//
	// This is deliberately ONE reason rather than several. UDPNatConn.Splice returns a
	// bare bool, and its false paths include the writer not being a GoPacketConn, the
	// platform lacking socket support, NAT origin/destination that the splice cannot
	// express, owner.Attach being refused (typically an existing owner), socket conversion
	// failing, and family mismatches. None of that is observable from here, so splitting
	// it would mean guessing - and a device report that says "attach_failed" when the real
	// cause was platform support is worse than one that says less.
	//
	// Splitting this needs sing-tun to report why, not sing-box to infer it.
	spliceReasonSpliceRejected

	// --- TCP-only points ----------------------------------------------------
	//
	// The reasons above are reachable from both the packet path and the stream path; the
	// three below can only be produced while deciding a TCP connection, so their counters
	// are always zero in the UDP snapshot and vice versa. They share this enum - and its
	// String and bounds handling - because the target-side reasons are literally the same
	// decisions: a stream and a session both ask unwrapSpliceTargetWithReason how the
	// outbound connection ends, and answer with the same vocabulary.
	//
	// They are appended rather than inserted: the numeric values are what the UDP device
	// log's bucket order is built from, and a released build's numbers should not move.

	// spliceReasonSkippedForTLSRewrite: the handover was deliberately not attempted because
	// the fork has to rewrite the stream (TLS fragmentation, record fragmentation, or TLS
	// spoof). This one is recorded by the CALLER, at the point where the decision is made,
	// because spliceConnection is not called at all in this case. It is observable rather
	// than inferred: the three options are read directly.
	spliceReasonSkippedForTLSRewrite
	// spliceReasonSourceNotGoConn: the client-side connection is not backed by a tun.GoConn,
	// so there is nothing that can hand the stream to a socket. This is the TCP counterpart
	// of the packet path's source_not_nat, and on a TUN-routed connection it is the normal
	// answer for every flow that is being proxied in userspace.
	spliceReasonSourceNotGoConn
	// spliceReasonCachedWriteFailed: the connection was eligible, but buffered data that had
	// to be forwarded before the handover could not be written to the remote. The connection
	// is finished in that case rather than falling back, so this is a distinct outcome and
	// not a kind of rejection.
	spliceReasonCachedWriteFailed
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
	case spliceReasonSpliceRejected:
		return "splice_rejected"
	case spliceReasonSkippedForTLSRewrite:
		return "skipped_for_tls_rewrite"
	case spliceReasonSourceNotGoConn:
		return "source_not_go_conn"
	case spliceReasonCachedWriteFailed:
		return "cached_write_failed"
	default:
		return "unknown"
	}
}

// spliceReasonCount is the number of distinct reasons, used to size the counters.
//
// It covers the TCP-only reasons as well, so both diagnostics arrays are sized by the same
// constant and neither can silently drop an outcome that the code can produce.
const spliceReasonCount = int(spliceReasonCachedWriteFailed) + 1

// spliceReasonMax is the largest valid reason, for bounds checks.
const spliceReasonMax = spliceReasonCachedWriteFailed

// spliceDiagnostics counts how each flow's splice decision ended - one array per transport,
// so the stream and the session each satisfy the invariant below on their own.
//
// # One write per session
//
// Every session increments exactly ONE counter, once, at the moment its decision is
// final. There is no separate attempts counter and no separate success counter: a session
// that wrote two of them would be two atomic operations on the hot path, and it would also
// make the invariant below impossible to state, let alone check.
//
//	Attempts == Successes + sum(Reasons)
//
// That holds by construction here, because every session contributes exactly one to
// exactly one bucket, and the snapshot is derived from the same array.
//
// The cost is one atomic add per flow - not per packet. A per-datagram counter at video
// call rates would itself be a source of the contention being investigated.
type spliceDiagnostics struct {
	counters [spliceReasonCount]atomic.Uint64
}

// recordOutcome is the single write a session performs.
func (d *spliceDiagnostics) recordOutcome(outcome spliceReason) {
	if int(outcome) < spliceReasonCount {
		d.counters[outcome].Add(1)
	}
}

// total is the number of sessions that reached a decision.
func (d *spliceDiagnostics) total() uint64 {
	var total uint64
	for i := range d.counters {
		total += d.counters[i].Load()
	}
	return total
}

// successes is the number of sessions that spliced.
func (d *spliceDiagnostics) successes() uint64 {
	return d.counters[spliceReasonSuccess].Load()
}

// snapshot returns the non-zero FAILURE buckets, keyed by reason name.
//
// Success is excluded, and that is load-bearing rather than cosmetic: SpliceSnapshot
// reports Successes separately, so including it here as well would count every spliced
// session twice and break Attempts == Successes + sum(Reasons) - the invariant that makes
// a device report self-consistent.
func (d *spliceDiagnostics) snapshot() map[string]uint64 {
	snapshot := make(map[string]uint64, spliceReasonCount)
	for i := range d.counters {
		if spliceReason(i) == spliceReasonSuccess {
			continue
		}
		if count := d.counters[i].Load(); count > 0 {
			snapshot[spliceReason(i).String()] = count
		}
	}
	return snapshot
}

// SpliceSnapshot is an immutable view of the splice diagnostics, for tests and for
// on-device observation.
//
// Attempts, Successes and Reasons are all derived from the same counter array, so they
// cannot disagree: Attempts is its total and Successes is one of its buckets.
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

// SpliceDiagnostics returns the current UDP splice diagnostics.
//
// This is the observation hook for a real-device A/B run: a caller can read it
// before and after a video call and compare the splice ratio and the fallback
// reasons. Reading it allocates a small map and has no effect on forwarding.
func (m *ConnectionManager) SpliceDiagnostics() SpliceSnapshot {
	return m.spliceDiagnostics.view()
}

// TCPSpliceDiagnostics returns the current TCP splice diagnostics.
//
// The stream path answers a different question from the packet path, and a device run needs
// both: whether a TCP connection was handed to a socket, and if not, at which point the
// decision ended. "It was not spliced" is not an answer a report can act on, because the
// reason decides whether anything can be done about it - a source that is not a tun.GoConn
// means the flow is being proxied in userspace by design, while a target that refused
// replacement means a wrapper is standing in the way of one that could be spliced.
//
// Same cost model as the packet path: one atomic add per connection, at the moment its
// decision is final, and never per read or per byte.
func (m *ConnectionManager) TCPSpliceDiagnostics() SpliceSnapshot {
	return m.tcpSpliceDiagnostics.view()
}

// view derives a snapshot from one counter array.
func (d *spliceDiagnostics) view() SpliceSnapshot {
	return SpliceSnapshot{
		Attempts:  d.total(),
		Successes: d.successes(),
		Reasons:   d.snapshot(),
	}
}

// tcpSpliceSnapshotReason converts a target-side classification into the recorded outcome.
//
// The classifier returns the same enum the counters are indexed by, so this is an identity -
// it exists to say, at the call site, that the target-side vocabulary is deliberately shared
// with the packet path rather than mirrored.
func tcpSpliceTargetReason(reason spliceReason) spliceReason {
	return reason
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

// sameConn reports whether two values are the same connection.
//
// It replaces a direct any(a) != any(b) comparison, which PANICS when a dynamic type is
// not comparable - inside the splice decision, on a packet path. The first version of this
// recovered from that panic, but a panic used for ordinary control flow is expensive and
// obscures what the code means: the question here is simply "are these the same
// connection", and it has a direct answer.
//
// The types are compared first. Different types are never the same connection, and two
// comparable values of the same type can be compared safely with ==. Anything
// non-comparable (a slice, a map, a func) reports false, which is the safe direction: it
// refuses a splice rather than joining two flows.
func sameConn(a any, b any) bool {
	if a == nil || b == nil {
		return a == b
	}
	typeA, typeB := reflect.TypeOf(a), reflect.TypeOf(b)
	if typeA != typeB || !typeA.Comparable() {
		return false
	}
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

// SpliceSummary renders the diagnostics as one stable line.
//
// Real-device A/B is the only way to settle whether splicing is actually happening on a
// phone, and getting Go-level numbers off a device is awkward. This is the minimum that
// makes it possible: start the VPN, run the call, stop the VPN, read one line.
//
// The format is fixed and the reasons are emitted in enum order, never map order, so two
// runs can be compared by eye and by diff. It is produced once per tunnel lifetime by the
// caller - never per session and never per packet.
func (s SpliceSnapshot) SpliceSummary() string {
	return s.summary("UDP")
}

// TCPSpliceSummary renders the stream diagnostics in the same stable form.
func (s SpliceSnapshot) TCPSpliceSummary() string {
	return s.summary("TCP")
}

func (s SpliceSnapshot) summary(transport string) string {
	var summary strings.Builder
	fmt.Fprintf(&summary, "%s splice diagnostics: attempts=%d successes=%d ratio=%.3f",
		transport, s.Attempts, s.Successes, s.Ratio())

	// Enum order, so the output is stable between runs. A map would rotate key order and
	// make two device logs needlessly hard to compare.
	for i := 0; i < spliceReasonCount; i++ {
		reason := spliceReason(i)
		if reason == spliceReasonSuccess {
			continue
		}
		if count := s.Reasons[reason.String()]; count > 0 {
			fmt.Fprintf(&summary, " %s=%d", reason.String(), count)
		}
	}
	return summary.String()
}
