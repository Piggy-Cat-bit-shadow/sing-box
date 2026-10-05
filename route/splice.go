package route

import (
	"context"
	"io"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type spliceTarget struct {
	socket        tun.SpliceSocket
	offload       N.PacketOffload
	readCounters  []N.CountFunc
	writeCounters []N.CountFunc
}

func unwrapSpliceTarget(conn any, allowOffload bool) (spliceTarget, bool) {
	// Delegates to the reason-aware variant so there is a single implementation of
	// the walk. Keeping two copies would let the reason threading drift from the
	// decision it is supposed to describe.
	target, _, ok := unwrapSpliceTargetWithReason(conn, allowOffload)
	return target, ok
}

func (m *ConnectionManager) spliceClose(ctx context.Context, conn io.Closer, remote io.Closer, onClose N.CloseHandlerFunc) N.CloseHandlerFunc {
	return func(err error) {
		if err == nil {
			m.logger.DebugContext(ctx, "connection finished")
		} else if !E.IsClosedOrCanceled(err) {
			m.logger.ErrorContext(ctx, "connection closed: ", err)
		} else {
			m.logger.TraceContext(ctx, "connection closed")
		}
		if onClose != nil {
			onClose(err)
		}
		common.Close(conn, remote)
	}
}

func (m *ConnectionManager) spliceConnection(ctx context.Context, conn net.Conn, remoteConn net.Conn, onClose N.CloseHandlerFunc) (bool, error) {
	// Every path out of this function records exactly one outcome, and the caller records
	// the one case in which this function is not called at all. That is what makes
	// Attempts == Successes + sum(Reasons) hold for the stream diagnostics without a second
	// counter, and it is why the recording sits at the returns rather than in the caller.
	destination, writeCounters := N.UnwrapCountWriter(conn, nil)
	goConn, isGoConn := N.CastWriter[*tun.GoConn](destination)
	if !isGoConn {
		// Not a TUN stream: the connection is proxied in userspace by design, so there is
		// nothing that could be handed to a socket.
		m.tcpSpliceDiagnostics.recordOutcome(spliceReasonSourceNotGoConn)
		return false, nil
	}
	target, targetReason, isTarget := unwrapSpliceTargetWithReason(remoteConn, false)
	if !isTarget {
		// The outbound side refused, at one of the points the classifier can name. The
		// reason is used as recorded: it is produced by the same walk the decision uses.
		m.tcpSpliceDiagnostics.recordOutcome(tcpSpliceTargetReason(targetReason))
		return false, nil
	}
	var (
		source       io.Reader = conn
		readCounters []N.CountFunc
	)
	for {
		source, readCounters = N.UnwrapCountReader(source, readCounters)
		cachedReader, isCached := source.(N.CachedReader)
		if !isCached {
			break
		}
		buffer := cachedReader.ReadCached()
		if buffer == nil {
			break
		}
		dataLen := buffer.Len()
		_, err := remoteConn.Write(buffer.Bytes())
		buffer.Release()
		if err != nil {
			// Data that had to be forwarded before the handover could not be. The
			// connection is finished by the caller rather than falling back, so this is a
			// terminal outcome and not a rejection.
			m.tcpSpliceDiagnostics.recordOutcome(spliceReasonCachedWriteFailed)
			return false, err
		}
		for _, counter := range readCounters {
			counter(int64(dataLen))
		}
	}
	goReader, isGoReader := N.CastReader[*tun.GoConn](source)
	if !isGoReader || goReader != goConn {
		// The reader and the writer do not resolve to the same TUN stream, so splicing
		// would join one connection's download to another's upload.
		m.tcpSpliceDiagnostics.recordOutcome(spliceReasonSourceReaderWriterMismatch)
		return false, nil
	}
	if goConn.Splice(target.socket, tun.SpliceOptions{
		ReadCounters:  append(readCounters, target.writeCounters...),
		WriteCounters: append(target.readCounters, writeCounters...),
		OnClose:       m.spliceClose(ctx, conn, remoteConn, onClose),
	}) {
		m.tcpSpliceDiagnostics.recordOutcome(spliceReasonSuccess)
		return true, nil
	}
	// Splice declined and returns a bare bool. Its false paths inside sing-tun include the
	// platform lacking socket support, a stream that is not established, one that is already
	// spliced or has a handover pending, owner.Attach being refused (typically an existing
	// owner), and socket conversion failing. None of that is observable from here, so this is
	// recorded as one outcome rather than guessed at - the packet path documents the same
	// decision for the same reason.
	m.tcpSpliceDiagnostics.recordOutcome(spliceReasonSpliceRejected)
	return false, nil
}

type spliceSource struct {
	natConn       *tun.UDPNatConn
	cachedReaders []N.CachedPacketReader
	readCounters  []N.CountFunc
	writeCounters []N.CountFunc
}

func unwrapSpliceSource(conn N.PacketConn) (spliceSource, bool) {
	// Delegates to the reason-aware variant; see unwrapSpliceTarget above.
	source, _, ok := unwrapSpliceSourceWithReason(conn)
	return source, ok
}

func (s *spliceSource) takeCached() []*N.PacketBuffer {
	var cached []*N.PacketBuffer
	for _, cachedReader := range s.cachedReaders {
		packet := cachedReader.ReadCachedPacket()
		if packet == nil {
			continue
		}
		if packet.Buffer == nil {
			N.PutPacketBuffer(packet)
			continue
		}
		cached = append(cached, packet)
	}
	return cached
}

func (m *ConnectionManager) splicePacketConnection(ctx context.Context, conn N.PacketConn, remote any, metadata *adapter.InboundContext, destinationAddress netip.Addr, udpTimeout time.Duration, onClose N.CloseHandlerFunc) (N.PacketConn, bool) {
	var nat tun.PacketNAT
	source := conn
	fakeIPConn, isFakeIP := conn.(*fakeIPNATPacketConn)
	if isFakeIP {
		source = fakeIPConn.NetPacketConn
	}
	// The session records exactly one outcome, once, when its decision is final. See
	// spliceDiagnostics: attempts and successes are derived from this same array, so a
	// second write here would both cost another atomic on the session path and break the
	// invariant Attempts == Successes + sum(Reasons).
	spliceSource, sourceReason, isSpliceSource := unwrapSpliceSourceWithReason(source)
	if !isSpliceSource {
		m.spliceDiagnostics.recordOutcome(sourceReason)
		return conn, false
	}
	target, targetReason, isTarget := unwrapSpliceTargetWithReason(remote, true)
	if !isTarget {
		m.spliceDiagnostics.recordOutcome(targetReason)
		return conn, false
	}
	if destinationAddress.IsValid() {
		nat.Destination = M.SocksaddrFrom(destinationAddress, metadata.Destination.Port)
	} else {
		nat.Destination = metadata.Destination
	}
	switch {
	case isFakeIP:
		nat.Origin = metadata.OriginDestination
		nat.FakeIP = true
	case metadata.RouteOriginalDestination.IsValid() && metadata.RouteOriginalDestination != metadata.Destination:
		nat.Origin = metadata.RouteOriginalDestination
	case destinationAddress.IsValid() && metadata.Destination.IsIP():
		nat.Origin = metadata.Destination
	}
	nat.Unidirectional = !isFakeIP && metadata.UDPDisableDomainUnmapping && !metadata.Destination.IsIP()
	cached := spliceSource.takeCached()
	if spliceSource.natConn.Splice(target.socket, tun.SplicePacketOptions{
		SpliceOptions: tun.SpliceOptions{
			ReadCounters:  append(spliceSource.readCounters, target.writeCounters...),
			WriteCounters: append(target.readCounters, spliceSource.writeCounters...),
			OnClose:       m.spliceClose(ctx, conn, remote.(io.Closer), onClose),
		},
		Timeout:       udpTimeout,
		NAT:           nat,
		Cached:        cached,
		Offload:       target.offload,
		FrontHeadroom: N.CalculateFrontHeadroom(remote),
		RearHeadroom:  N.CalculateRearHeadroom(remote),
	}) {
		// The socket was found and handed over; packets now bypass userspace.
		m.spliceDiagnostics.recordOutcome(spliceReasonSuccess)
		return conn, true
	}
	// Splice() declined, and it returns a bare bool. Its false paths inside sing-tun
	// include platform support, NAT expressibility, owner.Attach being refused, socket
	// conversion and family mismatch - none of which is observable from here, so
	// inferring which one happened would mean guessing from a single fact.
	//
	// An earlier version split this into attach_failed and platform_unsupported based on
	// whether a socket was present. That distinction is not real: a socket is always
	// present whenever this line is reached, so the split could only ever have reported
	// one of the two, and it would have been wrong about the cause.
	m.spliceDiagnostics.recordOutcome(spliceReasonSpliceRejected)
	if len(cached) == 0 {
		return conn, false
	}
	for _, packet := range slices.Backward(cached) {
		for _, counter := range spliceSource.readCounters {
			counter(int64(packet.Buffer.Len()))
		}
		source = bufio.NewCachedPacketConn(source, packet.Buffer, packet.Destination)
		N.PutPacketBuffer(packet)
	}
	if isFakeIP {
		fakeIPConn.NetPacketConn = bufio.NewNetPacketConn(source)
		return conn, false
	}
	return source, false
}

func packetTimeout(metadata *adapter.InboundContext) time.Duration {
	if metadata.UDPTimeout > 0 {
		return metadata.UDPTimeout
	}
	protocol := metadata.Protocol
	if protocol == "" {
		protocol = C.PortProtocols[metadata.Destination.Port]
	}
	if protocol != "" {
		return C.ProtocolTimeouts[protocol]
	}
	return 0
}
