package route

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/sagernet/sing-box/common/tlsspoof"
	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing-box/common/trafficsched"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

var _ adapter.ConnectionManager = (*ConnectionManager)(nil)

type ConnectionManager struct {
	logger logger.ContextLogger
	access sync.Mutex
	// connections holds every dialled connection the manager owns, with the lifecycle record the
	// reclaim policies decide on. It used to be a list of bare io.Closer, which is why the only
	// thing it could do on a network change was close all of them; see conn_reclaim.go.
	connections list.List[managedConn]
	// generation counts network transitions. A connection records the value at dial time, so
	// "belongs to a path the device has left" is one integer comparison.
	generation atomic.Uint64
	// sweepAccess guards sweepTimer and closed.
	sweepAccess sync.Mutex
	sweepTimer  *time.Timer
	closed      atomic.Bool
	// reclaimLog, when set, reports each reclaim pass. Diagnostics only; nil in production.
	reclaimLog func(reason ReclaimReason, closed int, generation uint64)
	// drainIdleGraceOverride and drainSweepIntervalOverride exist so a test can exercise the drain
	// without sleeping for the production windows. Zero means "use the constant".
	drainIdleGraceOverride     time.Duration
	drainSweepIntervalOverride time.Duration
	// Session-level splice diagnostics. One atomic add per UDP session, never per
	// packet. See splice_diagnostics.go for why, and for what these numbers can and
	// cannot tell you.
	spliceDiagnostics spliceDiagnostics
	// Stream-level splice diagnostics, with the same discipline: one atomic add per TCP
	// connection that reaches the decision, never per read or per byte. A separate array
	// rather than a shared one so each transport's
	// Attempts == Successes + sum(Reasons) holds on its own.
	tcpSpliceDiagnostics spliceDiagnostics
	// scheduler arbitrates the upload write path of every managed flow.
	//
	// It lives here rather than on the Router because the connection manager is what creates a
	// flow and what finalises it, so the scheduler's flow lifetime is exactly a connection's.
	// See trafficsched.Scheduler for the ownership reasoning.
	scheduler *trafficsched.Scheduler
}

func NewConnectionManager(logger logger.ContextLogger) *ConnectionManager {
	return &ConnectionManager{
		logger: logger,
		// The production default is a scheduler that is INSTALLED but deliberately inert.
		//
		// The contention experiment in common/trafficsched measured that the models which only
		// change when a write starts - admission ordering and service slots - do not move the
		// receiver-visible p99 at all, because the bytes that delay an interactive message are
		// already inside the sender's acceptance window. Only shaping the managed upload rate
		// helps, and a rate has to come from somewhere.
		//
		// So the gate goes in the path, observes every byte, and admits all of them: shaping is
		// switched on by installing a rate source, not by changing the shape of the data path.
		// See trafficsched.Options.RateSource.
		scheduler: trafficsched.NewScheduler(trafficsched.Options{Mode: trafficsched.ModePaced}),
	}
}

func (m *ConnectionManager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(func() error {
		m.CloseAll()
		return nil
	})
	return nil
}

func (m *ConnectionManager) Count() int {
	m.access.Lock()
	defer m.access.Unlock()
	return m.connections.Len()
}

func (m *ConnectionManager) CloseAll() {
	// Release the flows first. A flow parked in the shaper is not inside a write, so closing its
	// socket does not wake it, and it can be parked for as long as the period its own last write is
	// worth at the configured rate. See trafficsched.Scheduler.ReleaseAll.
	if m.scheduler != nil {
		m.scheduler.ReleaseAll()
	}
	m.access.Lock()
	var closers []managedConn
	for element := m.connections.Front(); element != nil; {
		nextElement := element.Next()
		closers = append(closers, element.Value)
		m.connections.Remove(element)
		element = nextElement
	}
	m.access.Unlock()
	for _, closer := range closers {
		common.Close(closer)
	}
}

// SetUploadRate installs the managed upload shaping rate from the configuration.
//
// This is the one place configuration reaches the scheduler. A rate source rather than a number is
// what makes the value live: the scheduler reads it on every refill, so a controller installed here
// later changes the shaping without the connection manager, the gate or any flow being rebuilt.
//
// A zero or negative rate installs no source, which leaves the scheduler inert: it still observes
// every managed byte, and it admits all of them immediately with no queue, no lock and no timer.
// A configuration that does not ask for shaping must not get it.
func (m *ConnectionManager) SetUploadRate(bytesPerSecond int64) {
	if m.scheduler == nil {
		return
	}
	if bytesPerSecond <= 0 {
		m.scheduler.SetRateSource(nil)
		return
	}
	m.scheduler.SetRateSource(trafficsched.NewFixedRate(bytesPerSecond))
}

// UploadRate reports the shaping rate currently in effect, in bytes per second. Zero means the
// scheduler is inert. It is the read side of SetUploadRate, and what the configuration tests assert
// against, so that "the option was accepted" and "the shaper is using it" cannot drift apart.
func (m *ConnectionManager) UploadRate() int64 {
	if m.scheduler == nil {
		return 0
	}
	return m.scheduler.Rate()
}

func (m *ConnectionManager) Close() error {
	// Order matters: mark closed so a sweep in flight will not reschedule itself, stop the timer,
	// and only then tear the connections down. A timer that fired after this returned would be
	// reclaiming connections on behalf of a manager whose lifecycle has ended.
	m.closed.Store(true)
	m.stopDrainSweep()
	m.CloseAll()
	// Releasing the scheduler here is what unblocks a copy goroutine parked in the gate. Closing
	// the connections above does not: a flow waiting for a permit is not inside a write, so it
	// never observes the closed socket.
	if m.scheduler != nil {
		_ = m.scheduler.Close()
	}
	// One line per tunnel lifetime, and only when UDP actually went through the splice
	// decision. This is the only place the diagnostics are reported, deliberately: a
	// per-session or per-packet log would be the very cost the counters exist to measure.
	//
	// Emitting it here means a real-device run needs no instrumentation at all - start the
	// VPN, use the app, stop the VPN, read one line from the log.
	if snapshot := m.SpliceDiagnostics(); snapshot.Attempts > 0 {
		m.logger.Info(snapshot.SpliceSummary())
	}
	if snapshot := m.TCPSpliceDiagnostics(); snapshot.Attempts > 0 {
		m.logger.Info(snapshot.TCPSpliceSummary())
	}
	return nil
}

func (m *ConnectionManager) TrackConn(conn net.Conn) net.Conn {
	tracked := &trackedConn{
		Conn:        conn,
		socketOwner: socketOwner{original: conn},
		manager:     m,
	}
	tracked.managedConnState = m.newConnState()
	m.access.Lock()
	tracked.element = m.connections.PushBack(tracked)
	m.access.Unlock()
	return tracked
}

func (m *ConnectionManager) TrackPacketConn(conn net.PacketConn) net.PacketConn {
	tracked := &trackedPacketConn{
		NetPacketConn: bufio.NewPacketConn(conn),
		socketOwner:   socketOwner{original: conn},
		manager:       m,
	}
	tracked.managedConnState = m.newConnState()
	m.access.Lock()
	tracked.element = m.connections.PushBack(tracked)
	m.access.Unlock()
	return tracked
}

// newConnState stamps a connection with the path it was dialled on.
//
// The generation is read from the manager rather than passed in, so it cannot be forgotten at a call
// site: every tracked connection is stamped with the transition in effect at the moment it entered
// the list.
func (m *ConnectionManager) newConnState() managedConnState {
	return managedConnState{
		createdAt:  time.Now(),
		generation: m.generation.Load(),
	}
}

func (m *ConnectionManager) NewConnection(ctx context.Context, this N.Dialer, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	var (
		remoteConn net.Conn
		err        error
	)
	if len(metadata.DestinationAddresses) > 0 || metadata.Destination.IsIP() {
		remoteConn, err = dialer.DialSerialNetwork(ctx, this, N.NetworkTCP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
	} else {
		remoteConn, err = this.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	}
	if err != nil {
		var remoteString string
		if len(metadata.DestinationAddresses) > 0 {
			remoteString = "[" + strings.Join(common.Map(metadata.DestinationAddresses, netip.Addr.String), ",") + "]"
		} else {
			remoteString = metadata.Destination.String()
		}
		var dialerString string
		if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
			dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		}
		err = E.Cause(err, "open connection to ", remoteString, dialerString)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		m.logger.ErrorContext(ctx, err)
		return
	}
	err = N.ReportConnHandshakeSuccess(conn, remoteConn)
	if err != nil {
		err = E.Cause(err, "report handshake success")
		remoteConn.Close()
		N.CloseOnHandshakeFailure(conn, onClose, err)
		m.logger.ErrorContext(ctx, err)
		return
	}
	if !metadata.TLSFragment && !metadata.TLSRecordFragment && metadata.TLSSpoof == "" {
		var spliced bool
		spliced, err = m.spliceConnection(ctx, conn, remoteConn, onClose)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			remoteConn.Close()
			m.logger.ErrorContext(ctx, err)
			return
		}
		if spliced {
			return
		}
	} else {
		// The handover is deliberately not attempted while the fork has to rewrite the
		// stream, and that is a decision this call site makes rather than a failure inside
		// spliceConnection. It is recorded here so that every connection that reached the
		// decision contributes exactly one outcome, whether or not the attempt was made.
		m.tcpSpliceDiagnostics.recordOutcome(spliceReasonSkippedForTLSRewrite)
	}
	if metadata.TLSFragment || metadata.TLSRecordFragment {
		remoteConn = tf.NewConn(remoteConn, ctx, metadata.TLSFragment, metadata.TLSRecordFragment, metadata.TLSFragmentFallbackDelay)
	}
	if metadata.TLSSpoof != "" {
		spoofConn, spoofErr := tlsspoof.NewConn(remoteConn, metadata.TLSSpoofMethod, metadata.TLSSpoof)
		if spoofErr != nil {
			spoofErr = E.Cause(spoofErr, "tls_spoof setup")
			remoteConn.Close()
			N.CloseOnHandshakeFailure(conn, onClose, spoofErr)
			m.logger.ErrorContext(ctx, spoofErr)
			return
		}
		remoteConn = spoofConn
	}
	serverFirst := sniff.Skip(&metadata)
	var done atomic.Bool
	if m.kickWriteHandshake(ctx, conn, remoteConn, serverFirst, false, &done, onClose) {
		return
	}
	if m.kickWriteHandshake(ctx, remoteConn, conn, serverFirst, true, &done, onClose) {
		return
	}
	// Each copy direction resolves its OWN threshold, because the reason to grow early
	// is a property of the WRITER that copy feeds.
	//
	// The upload copy (conn -> remoteConn) ends at the outbound's writer; the download
	// copy (remoteConn -> conn) ends at the inbound's writer. Resolving once and reusing
	// the value for both - which is what an inbound-type check did - applied the inbound
	// writer's tuning to the outbound direction as well.
	uploadIncreaseBufferAfter := connectionIncreaseBufferAfter(this, conn, remoteConn)
	downloadIncreaseBufferAfter := connectionIncreaseBufferAfter(this, remoteConn, conn)
	uploadWriter, uploadFlow := m.uploadStreamGate(conn, remoteConn, metadata.TrafficClass)
	go m.connectionCopy(ctx, conn, remoteConn, false, uploadIncreaseBufferAfter, &done, onClose, uploadWriter, uploadFlow)
	go m.connectionCopy(ctx, remoteConn, conn, true, downloadIncreaseBufferAfter, &done, onClose, nil, nil)
}

// uploadStreamGate decides whether this upload flow is scheduled, and returns the writer the copy
// loop must use and the flow that must be released when it ends.
//
// # Why a kernel-splice-eligible flow is left alone
//
// bufio.copyDirect moves bytes between two syscall-capable ends without ever entering the
// userspace copy loop, so a gate there would not delay anything - it would only take the kernel
// fast path away from a flow that had it. The check below is the SAME predicate copyDirect itself
// applies, so a flow is gated only when copyDirect would have declined anyway. Managing only the
// userspace path is the stated scope of the first scheduler round, not a limitation discovered
// later.
//
// # Why the gate goes in front of the destination and not the source
//
// The copy loop's scheduling point is the write: it is the only place a flow decides to hand
// bytes to the outbound. Gating the read would leave the already-resolved writer untouched and
// make ownership of an in-flight buffer the reader's problem instead of the writer's.
func (m *ConnectionManager) uploadStreamGate(source net.Conn, destination net.Conn, class trafficclass.Class) (io.Writer, *trafficsched.Flow) {
	if m.scheduler == nil {
		return nil, nil
	}
	if N.SyscallAvailableForRead(source) && N.SyscallAvailableForWrite(destination) {
		return nil, nil
	}
	return m.gateWriter(destination, class)
}

// gateWriter installs the scheduler gate in front of destination.
//
// The destination's own write counters are extracted FIRST and carried across the gate. A
// non-replaceable gate terminates N.UnwrapCountWriter, so a gate placed outside a counter wrapper
// would make that counter read zero while the data still flowed - an accounting loss that looks
// exactly like a working connection. Counting is unchanged when the destination has no counters,
// which is the common case: upload bytes are counted on the inbound READ side by the traffic
// tracker, not here.
func (m *ConnectionManager) gateWriter(destination io.Writer, class trafficclass.Class) (io.Writer, *trafficsched.Flow) {
	flow := m.scheduler.NewFlow(class)
	upstream, counters := N.UnwrapCountWriter(destination, nil)
	if len(counters) == 0 {
		// Nothing to preserve, so there is no reason to move the gate below whatever the
		// destination is. Wrapping it directly also keeps any behaviour the destination itself
		// has: N.UnwrapCountWriter unwraps through every replaceable wrapper, not only counters,
		// and a wrapper that rewrites a write would be silently skipped if the gate sat under it.
		return trafficsched.NewGate(destination, flow), flow
	}
	return &counterPreservingWriter{gate: trafficsched.NewGate(upstream, flow), counters: counters}, flow
}

// connectionIncreaseBufferAfter reports after how many copied bytes the copy loop that
// feeds DESTINATION may switch to its larger buffer.
//
// # Why the destination writer decides, not the inbound type
//
// The copy loop is bufio.CopyWithIncreateBuffer(destination, source, threshold, ...).
// A bigger buffer only pays off when it matches the destination writer's geometry, so
// the writer is the only correct place to ask. sing's default is
// bufio.DefaultIncreaseBufferAfter (512000), which is right for an ordinary net.Conn.
//
// The previous implementation asked a different question: "is this connection's inbound
// Naive?". For Native Naive that gave the right answer on the download copy, whose
// destination is Naive's padded writer, and the WRONG answer on the upload copy, whose
// destination is an ordinary TCP or SOCKS writer. The upload copy grew early for no
// reason: it had no padding geometry to match, so the larger buffer was pure cost.
//
// Asking the writer fixes both directions at once and removes the protocol name from
// this file. Native Naive's padded writer (naiveConn, naiveH2Conn) implements
// adapter.CopyBufferGrowthTuner and opts in; every other writer - including the SOCKS
// outbound's - falls through to the default unless it opts in itself.
//
// # Precedence
//
// A destination that opts in wins, because it describes the writer in hand. Otherwise
// an outbound that opted in through adapter.ConnectionCopyTuner is honoured, which is
// how a chained SOCKS hop requests early growth without a tag or username being
// hardcoded here. `this` is the dialer actually selected for THIS connection, so a
// group resolves to the member that served it rather than to the group.
// connectionIncreaseBufferAfter reports after how many copied bytes the copy loop that
// feeds DESTINATION may switch to its larger buffer.
//
// # Why the destination writer decides, not the inbound type
//
// The copy loop is bufio.CopyWithIncreateBuffer(destination, source, threshold, ...).
// A bigger buffer only pays off when it matches the destination writer's geometry, so
// the writer is the only correct place to ask. sing's default is
// bufio.DefaultIncreaseBufferAfter (512000), which is right for an ordinary net.Conn.
//
// The previous implementation asked a different question: "is this connection's inbound
// Naive?". For Native Naive that gave the right answer on the download copy, whose
// destination is Naive's padded writer, and the WRONG answer on the upload copy, whose
// destination is an ordinary TCP or SOCKS writer. The upload copy grew early for no
// reason: it had no padding geometry to match, so the larger buffer was pure cost.
//
// Asking the writer fixes both directions at once and removes the protocol name from this
// file. Native Naive's padded writer (naiveConn, naiveH2Conn) implements
// adapter.CopyBufferGrowthTuner and opts in; every other writer - including the SOCKS
// outbound's - falls through to the default unless it opts in itself.
//
// # Precedence
//
// A destination that opts in wins, because it describes the writer in hand. Otherwise an
// outbound that opted in through adapter.ConnectionCopyTuner is honoured, which is how a
// chained SOCKS hop requests early growth without a tag or username being hardcoded here.
// `this` is the dialer actually selected for THIS connection, so a group resolves to the
// member that served it rather than to the group.
func connectionIncreaseBufferAfter(dialer N.Dialer, destination net.Conn, source net.Conn) int64 {
	// UnwrapWriter reaches past counter and other transparent wrappers to the writer
	// that actually performs the writes, which is where the capability lives. This is
	// the same unwrap the duplex half-close path above uses.
	destinationWriter, _ := N.UnwrapCountWriter(destination, nil)
	if tuner, isTuner := N.UnwrapWriter(destinationWriter).(adapter.CopyBufferGrowthTuner); isTuner {
		if tuner.EarlyCopyBufferGrowth() {
			return earlyConnectionBufferIncreaseAfter
		}
	}
	if tuner, isTuner := dialer.(adapter.ConnectionCopyTuner); isTuner {
		if tuner.EarlyConnectionBufferGrowth() {
			return earlyConnectionBufferIncreaseAfter
		}
	}
	return bufio.DefaultIncreaseBufferAfter
}

// earlyConnectionBufferIncreaseAfter is the threshold an opted-in destination or
// outbound requests: upgrade after the FIRST successful transfer instead of after
// bufio.DefaultIncreaseBufferAfter (512000) bytes.
//
// It must be positive: sing's condition is
// `IncreaseBufferAfter > 0 && n >= IncreaseBufferAfter`, so 0 means "never grow", which
// is the opposite of the intent. With 1 the first chunk is still read with the current
// default buffer and every subsequent chunk uses the larger one.
const earlyConnectionBufferIncreaseAfter = 1

func (m *ConnectionManager) NewPacketConnection(ctx context.Context, this N.Dialer, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	var (
		remotePacketConn   net.PacketConn
		remoteConn         net.Conn
		destinationAddress netip.Addr
		err                error
	)
	if metadata.UDPConnect {
		parallelDialer, isParallelDialer := this.(dialer.ParallelInterfaceDialer)
		if len(metadata.DestinationAddresses) > 0 {
			if isParallelDialer {
				remoteConn, err = dialer.DialSerialNetwork(ctx, parallelDialer, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
			} else {
				remoteConn, err = N.DialSerial(ctx, this, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses)
			}
		} else if metadata.Destination.IsIP() {
			if isParallelDialer {
				remoteConn, err = dialer.DialSerialNetwork(ctx, parallelDialer, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
			} else {
				remoteConn, err = this.DialContext(ctx, N.NetworkUDP, metadata.Destination)
			}
		} else {
			remoteConn, err = this.DialContext(ctx, N.NetworkUDP, metadata.Destination)
		}
		if err != nil {
			var remoteString string
			if len(metadata.DestinationAddresses) > 0 {
				remoteString = "[" + strings.Join(common.Map(metadata.DestinationAddresses, netip.Addr.String), ",") + "]"
			} else {
				remoteString = metadata.Destination.String()
			}
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			}
			err = E.Cause(err, "open packet connection to ", remoteString, dialerString)
			N.CloseOnHandshakeFailure(conn, onClose, err)
			m.logger.ErrorContext(ctx, err)
			return
		}
		remotePacketConn = bufio.NewUnbindPacketConn(remoteConn)
		connRemoteAddr := M.AddrFromNet(remoteConn.RemoteAddr())
		if connRemoteAddr != metadata.Destination.Addr {
			destinationAddress = connRemoteAddr
		}
	} else {
		if len(metadata.DestinationAddresses) > 0 {
			remotePacketConn, destinationAddress, err = dialer.ListenSerialNetworkPacket(ctx, this, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
		} else if packetDialer, withDestination := this.(dialer.PacketDialerWithDestination); withDestination {
			remotePacketConn, destinationAddress, err = packetDialer.ListenPacketWithDestination(ctx, metadata.Destination)
		} else {
			remotePacketConn, err = this.ListenPacket(ctx, metadata.Destination)
		}
		if err != nil {
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			}
			err = E.Cause(err, "listen packet connection using ", dialerString)
			N.CloseOnHandshakeFailure(conn, onClose, err)
			m.logger.ErrorContext(ctx, err)
			return
		}
	}
	err = N.ReportPacketConnHandshakeSuccess(conn, remotePacketConn)
	if err != nil {
		conn.Close()
		remotePacketConn.Close()
		m.logger.ErrorContext(ctx, "report handshake success: ", err)
		return
	}
	udpTimeout := packetTimeout(&metadata)
	var (
		spliceRemote any = remotePacketConn
		spliced      bool
	)
	if remoteConn != nil {
		spliceRemote = remoteConn
	}
	conn, spliced = m.splicePacketConnection(ctx, conn, spliceRemote, &metadata, destinationAddress, udpTimeout, onClose)
	if spliced {
		return
	}
	if destinationAddress.IsValid() {
		var originDestination M.Socksaddr
		if metadata.RouteOriginalDestination.IsValid() {
			originDestination = metadata.RouteOriginalDestination
		} else {
			originDestination = metadata.Destination
		}
		if natConn, loaded := common.Cast[bufio.NATPacketConn](conn); loaded {
			natConn.UpdateDestination(destinationAddress)
		} else {
			destination := M.SocksaddrFrom(destinationAddress, metadata.Destination.Port)
			if metadata.Destination != destination {
				if metadata.UDPDisableDomainUnmapping {
					remotePacketConn = bufio.NewUnidirectionalNATPacketConn(bufio.NewPacketConn(remotePacketConn), destination, originDestination)
				} else {
					remotePacketConn = bufio.NewNATPacketConn(bufio.NewPacketConn(remotePacketConn), destination, originDestination)
				}
			} else if metadata.RouteOriginalDestination.IsValid() && metadata.RouteOriginalDestination != metadata.Destination {
				remotePacketConn = bufio.NewDestinationNATPacketConn(bufio.NewPacketConn(remotePacketConn), metadata.Destination, metadata.RouteOriginalDestination)
			}
		}
	} else if metadata.RouteOriginalDestination.IsValid() && metadata.RouteOriginalDestination != metadata.Destination {
		remotePacketConn = bufio.NewDestinationNATPacketConn(bufio.NewPacketConn(remotePacketConn), metadata.Destination, metadata.RouteOriginalDestination)
	}
	if udpTimeout > 0 {
		ctx, conn = canceler.NewPacketConn(ctx, conn, udpTimeout)
	}
	destination := bufio.NewPacketConn(remotePacketConn)
	var done atomic.Bool
	uploadPacketWriter, uploadPacketFlow := m.uploadPacketGate(destination, metadata.TrafficClass)
	go m.packetConnectionCopy(ctx, conn, destination, false, &done, onClose, uploadPacketWriter, uploadPacketFlow)
	go m.packetConnectionCopy(ctx, destination, conn, true, &done, onClose, nil, nil)
}

// uploadPacketGate installs the scheduler gate on the UDP upload direction.
//
// There is no packet equivalent of copyDirect to protect: bufio.CopyPacket has no userspace
// bypass, and the syscall batch writer is reached THROUGH the gate because the gate forwards
// CreatePacketBatchWriter. So no flow is excluded here, and the batch shape is preserved rather
// than degraded.
func (m *ConnectionManager) uploadPacketGate(destination N.PacketWriter, class trafficclass.Class) (N.PacketWriter, *trafficsched.Flow) {
	if m.scheduler == nil {
		return nil, nil
	}
	flow := m.scheduler.NewFlow(class)
	upstream, counters := N.UnwrapCountPacketWriter(destination, nil)
	if len(counters) == 0 {
		// See gateWriter: with no counters to carry, wrapping the destination itself is the only
		// choice that cannot skip a destination-side rewrite. bufio's NAT packet conns are
		// exactly that kind of wrapper - they remap the per-packet destination - and they are not
		// replaceable today, which is a property to depend on rather than to assume.
		return trafficsched.NewPacketGate(destination, flow), flow
	}
	return &counterPreservingPacketWriter{gate: trafficsched.NewPacketGate(upstream, flow), counters: counters}, flow
}

// counterPreservingWriter keeps a destination's write counters visible across a non-replaceable
// gate.
//
// It unwraps to the GATE and not to the pre-gate writer, so one unwrap pass still yields
// destination=gate, counters=funcs: the counters are visible, the gate stays in the write path,
// nothing is counted twice, and the recursion terminates because the writer it returns is the
// non-replaceable gate.
type counterPreservingWriter struct {
	gate     io.Writer
	counters []N.CountFunc
}

func (w *counterPreservingWriter) Write(p []byte) (int, error) {
	return w.gate.Write(p)
}

func (w *counterPreservingWriter) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return w.gate, w.counters
}

type counterPreservingPacketWriter struct {
	gate     N.PacketWriter
	counters []N.CountFunc
}

func (w *counterPreservingPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return w.gate.WritePacket(buffer, destination)
}

func (w *counterPreservingPacketWriter) UnwrapPacketWriter() (N.PacketWriter, []N.CountFunc) {
	return w.gate, w.counters
}

func (m *ConnectionManager) connectionCopy(ctx context.Context, source net.Conn, destination net.Conn, direction bool, increaseBufferAfter int64, done *atomic.Bool, onClose N.CloseHandlerFunc, copyWriter io.Writer, flow *trafficsched.Flow) {
	if flow != nil {
		// Releasing the flow is what lets a close unblock this goroutine, and what removes it from
		// the scheduler's queues so a torn-down connection cannot hold a lane.
		defer flow.Close()
	}
	if copyWriter == nil {
		copyWriter = destination
	}
	_, err := bufio.CopyWithIncreateBuffer(copyWriter, source, increaseBufferAfter, bufio.DefaultBatchSize)
	if err != nil {
		common.Close(source, destination)
	} else {
		destinationWriter, _ := N.UnwrapCountWriter(destination, nil)
		duplexDst, isDuplex := N.UnwrapWriter(destinationWriter).(N.WriteCloser)
		if isDuplex {
			err = duplexDst.CloseWrite()
			if err != nil {
				common.Close(source, destination)
			}
		} else {
			destination.Close()
		}
	}
	if done.Swap(true) {
		if onClose != nil {
			onClose(err)
		}
		common.Close(source, destination)
	}
	if !direction {
		if err == nil {
			m.logger.DebugContext(ctx, "connection upload finished")
		} else if !E.IsClosedOrCanceled(err) {
			m.logger.ErrorContext(ctx, "connection upload closed: ", err)
		} else {
			m.logger.TraceContext(ctx, "connection upload closed")
		}
	} else {
		if err == nil {
			m.logger.DebugContext(ctx, "connection download finished")
		} else if !E.IsClosedOrCanceled(err) {
			m.logger.ErrorContext(ctx, "connection download closed: ", err)
		} else {
			m.logger.TraceContext(ctx, "connection download closed")
		}
	}
}

func (m *ConnectionManager) kickWriteHandshake(ctx context.Context, source net.Conn, destination net.Conn, serverFirst bool, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) bool {
	if !N.NeedHandshakeForWrite(destination) {
		return false
	}
	var (
		err          error
		wrotePayload bool
	)
	if serverFirst {
		_ = destination.SetWriteDeadline(time.Now().Add(C.ReadPayloadTimeout))
		_, err = destination.Write(nil)
		_ = destination.SetWriteDeadline(time.Time{})
	} else {
		var cachedBuffer *buf.Buffer
		sourceReader, readCounters := N.UnwrapCountReader(source, nil)
		destinationWriter, writeCounters := N.UnwrapCountWriter(destination, nil)
		if cachedReader, ok := sourceReader.(N.CachedReader); ok {
			cachedBuffer = cachedReader.ReadCached()
		}
		if cachedBuffer != nil {
			wrotePayload = true
			dataLen := cachedBuffer.Len()
			err = deliverCachedBuffer(destinationWriter, cachedBuffer)
			if err == nil {
				for _, counter := range readCounters {
					counter(int64(dataLen))
				}
				for _, counter := range writeCounters {
					counter(int64(dataLen))
				}
			}
		} else {
			_ = destination.SetWriteDeadline(time.Now().Add(C.ReadPayloadTimeout))
			_, err = destinationWriter.Write(nil)
			_ = destination.SetWriteDeadline(time.Time{})
		}
	}
	if err == nil {
		return false
	}
	if !wrotePayload && (E.IsMulti(err, os.ErrInvalid, context.DeadlineExceeded, io.EOF) || E.IsTimeout(err)) {
		return false
	}
	if !done.Swap(true) {
		if onClose != nil {
			onClose(err)
		}
	}
	common.Close(source, destination)
	if !direction {
		m.logger.ErrorContext(ctx, "connection upload handshake: ", err)
	} else {
		m.logger.ErrorContext(ctx, "connection download handshake: ", err)
	}
	return true
}

// writeCachedBuffer delivers a sniffed/cached first payload to the destination.
//
// It reports whether the destination TOOK OWNERSHIP of the buffer.
//
// # Why this is not just destination.Write(buffer.Bytes())
//
// A cached buffer is a pooled *buf.Buffer that already carries the geometry a framing writer needs:
// front headroom, rear headroom and a bounded length. The plain Write([]byte) path throws that away
// -- the writer receives a bare slice and, if it frames in place, has to build a new buffer and
// copy the payload into it. For Naive that is one full payload copy on the FIRST bytes of every
// connection, which is the most expensive place to spend it.
//
// # Why it is a capability test rather than a protocol test
//
// The check is on the destination WRITER, never on a protocol tag or an inbound type, and the
// requirements are the writer's own advertised geometry:
//
//	it must accept buffers (N.ExtendedWriter)
//	the payload must fit its WriterMTU
//	the buffer must already have its FrontHeadroom and RearHeadroom
//
// Any writer meeting those can be handed the buffer directly, whatever protocol it speaks, and any
// writer that does not simply keeps the old path. A Naive special case here would be a second place
// to update the next time a protocol grows the same shape.
//
// # Ownership
//
// Ownership transfers to the writer the moment WriteBuffer is ENTERED, and the error result does
// not change that. The bool therefore reports only whether the buffer was handed to WriteBuffer at
// all, so the caller knows not to release it.
//
// # Why the error return must NOT return false, and what it used to do
//
// An earlier revision returned `err, false` when WriteBuffer failed, on the reasoning that a failed
// write had not consumed the buffer. That is wrong, and it was a double release on the wire.
//
// Every N.ExtendedWriter implementation in sing releases the buffer itself, unconditionally:
//
//	ExtendedWriterWrapper.WriteBuffer:  defer buffer.Release(); return common.Error(w.Write(...))
//	ChunkWriter.WriteBuffer:            defer buffer.Release() on the oversized branch
//	naiveConn.WriteBuffer:              defer buffer.Release()
//	naiveH2Conn.WriteBuffer:            defer buffer.Release()
//
// The release is a defer, so it runs on BOTH the nil and the non-nil return. There is no
// implementation in which a failed WriteBuffer leaves the buffer with the caller, so "the writer
// rejected it, take it back" describes a contract that does not exist.
//
// Returning false made the caller Release a buffer the writer had already released. That is not a
// benign double free: buf.Buffer.Release() zeroes the struct and returns the backing array to the
// pool, so the second Release is a no-op on an already-cleared struct while the ARRAY has already
// been handed to whoever allocates next. The corruption therefore shows up later, in unrelated
// traffic, rather than at this call -- which is exactly why it survived.
//
// Note that the failure paths ABOVE this point (no ExtendedWriter, MTU, headroom) are a different
// case and return false correctly: they never enter WriteBuffer, so they never transfer ownership.
func writeCachedBuffer(destinationWriter io.Writer, cachedBuffer *buf.Buffer) (error, bool) {
	writer := N.UnwrapWriter(destinationWriter)
	extendedWriter, isExtended := writer.(N.ExtendedWriter)
	if !isExtended {
		_, err := destinationWriter.Write(cachedBuffer.Bytes())
		return err, false
	}
	// The buffer must already have the geometry the writer wants. Nothing is resized or relocated
	// to force a fit: moving the payload to gain headroom would be the very copy this avoids, so a
	// buffer that does not fit keeps the plain path.
	//
	// A writer that advertises no MTU or headroom is treated as having none to satisfy, which makes
	// the requirement vacuous and the direct hand-off correct -- the same interpretation sing's own
	// CalculateMTU applies to a plain net.Conn.
	if withMTU, hasMTU := writer.(N.WriterWithMTU); hasMTU {
		if cachedBuffer.Len() > withMTU.WriterMTU() {
			_, err := destinationWriter.Write(cachedBuffer.Bytes())
			return err, false
		}
	}
	if withFrontHeadroom, hasFront := writer.(N.FrontHeadroom); hasFront {
		if cachedBuffer.Start() < withFrontHeadroom.FrontHeadroom() {
			_, err := destinationWriter.Write(cachedBuffer.Bytes())
			return err, false
		}
	}
	if withRearHeadroom, hasRear := writer.(N.RearHeadroom); hasRear {
		if cachedBuffer.FreeLen() < withRearHeadroom.RearHeadroom() {
			_, err := destinationWriter.Write(cachedBuffer.Bytes())
			return err, false
		}
	}
	// From here the buffer is the writer's, whatever WriteBuffer returns. See the Ownership section
	// above: every implementation releases it with a defer, so the error result must NOT be used to
	// decide whether ownership moved.
	return extendedWriter.WriteBuffer(cachedBuffer), true
}

// deliverCachedBuffer writes the cached first payload and settles its ownership.
//
// # Why this is its own function
//
// The ownership rule has two halves: the helper decides WHETHER the writer took the buffer, and the
// caller decides whether to release based on that answer. The second half is the one that is easy
// to get wrong, and it is the one that cannot be checked by observing the buffer: once a writer has
// released it, buf.Buffer.Release() is a silent no-op on the zeroed struct, so an extra caller
// release leaves no trace on the buffer or the pool. A test can only see it by driving the real
// decision, which is why the decision lives here with a name rather than inline in the copy loop.
//
// The rule: release ONLY when the writer never entered WriteBuffer. A writer that entered it owns
// the buffer whatever it returned.
func deliverCachedBuffer(destinationWriter io.Writer, cachedBuffer *buf.Buffer) error {
	err, handedOver := writeCachedBuffer(destinationWriter, cachedBuffer)
	if !handedOver {
		cachedBuffer.Release()
	}
	return err
}

func (m *ConnectionManager) packetConnectionCopy(ctx context.Context, source N.PacketReader, destination N.PacketWriter, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc, copyWriter N.PacketWriter, flow *trafficsched.Flow) {
	if flow != nil {
		defer flow.Close()
	}
	if copyWriter == nil {
		copyWriter = destination
	}
	_, err := bufio.CopyPacket(copyWriter, source)
	if !direction {
		if err == nil {
			m.logger.DebugContext(ctx, "packet upload finished")
		} else if E.IsClosedOrCanceled(err) {
			m.logger.TraceContext(ctx, "packet upload closed")
		} else {
			m.logger.DebugContext(ctx, "packet upload closed: ", err)
		}
	} else {
		if err == nil {
			m.logger.DebugContext(ctx, "packet download finished")
		} else if E.IsClosedOrCanceled(err) {
			m.logger.TraceContext(ctx, "packet download closed")
		} else {
			m.logger.DebugContext(ctx, "packet download closed: ", err)
		}
	}
	if !done.Swap(true) {
		if onClose != nil {
			onClose(err)
		}
	}
	common.Close(source, destination)
}

type socketOwner struct {
	access   sync.Mutex
	original io.Closer
	owner    io.Closer
	closed   bool
}

func (o *socketOwner) Attach(closer io.Closer) (io.Closer, bool) {
	o.access.Lock()
	defer o.access.Unlock()
	if o.closed || o.owner != nil {
		return nil, false
	}
	o.owner = closer
	return o.original, true
}

func (o *socketOwner) detach() bool {
	o.access.Lock()
	defer o.access.Unlock()
	o.owner = nil
	return o.closed
}

func (o *socketOwner) close() bool {
	o.access.Lock()
	o.closed = true
	owner := o.owner
	o.access.Unlock()
	if owner == nil {
		return false
	}
	owner.Close()
	return true
}

type trackedConn struct {
	net.Conn
	socketOwner
	// Embedded, not named: promotion is what makes *trackedConn satisfy managedConn, so the
	// lifecycle record has to be part of the value rather than a field hanging off it.
	managedConnState
	manager *ConnectionManager
	element *list.Element[managedConn]
}

// Read and Write exist to observe activity, and are the only reason these two methods are declared:
// everything else is the embedded connection.
//
// A transfer that succeeds is what proves the path still works, so this is exactly the signal the
// drain policy needs, and it is recorded where the bytes already pass rather than by polling a
// socket. The missed case is a spliced connection, whose bytes move between descriptors in the
// kernel and never arrive here; that is why managedConnState treats "never observed" as protected
// rather than idle.
func (c *trackedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *trackedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *trackedConn) SyscallConn() (syscall.RawConn, error) {
	syscallConn, isSyscallConn := c.Conn.(syscall.Conn)
	if !isSyscallConn {
		return nil, os.ErrInvalid
	}
	return syscallConn.SyscallConn()
}

func (c *trackedConn) Detach() {
	if c.socketOwner.detach() {
		c.Conn.Close()
	}
}

func (c *trackedConn) Close() error {
	c.manager.access.Lock()
	c.manager.connections.Remove(c.element)
	c.manager.access.Unlock()
	if c.socketOwner.close() {
		return nil
	}
	return c.Conn.Close()
}

func (c *trackedConn) Upstream() any {
	return c.Conn
}

func (c *trackedConn) ReaderReplaceable() bool {
	return true
}

func (c *trackedConn) WriterReplaceable() bool {
	return true
}

type trackedPacketConn struct {
	N.NetPacketConn
	socketOwner
	managedConnState
	manager *ConnectionManager
	element *list.Element[managedConn]
}

func (c *trackedPacketConn) SyscallConn() (syscall.RawConn, error) {
	syscallConn, isSyscallConn := c.NetPacketConn.(syscall.Conn)
	if !isSyscallConn {
		return nil, os.ErrInvalid
	}
	return syscallConn.SyscallConn()
}

func (c *trackedPacketConn) Detach() {
	if c.socketOwner.detach() {
		c.NetPacketConn.Close()
	}
}

func (c *trackedPacketConn) Close() error {
	c.manager.access.Lock()
	c.manager.connections.Remove(c.element)
	c.manager.access.Unlock()
	if c.socketOwner.close() {
		return nil
	}
	return c.NetPacketConn.Close()
}

func (c *trackedPacketConn) Upstream() any {
	return c.NetPacketConn
}

func (c *trackedPacketConn) ReaderReplaceable() bool {
	return true
}

func (c *trackedPacketConn) WriterReplaceable() bool {
	return true
}

var (
	_ tun.SpliceSocket = (*trackedConn)(nil)
	_ tun.SpliceSocket = (*trackedPacketConn)(nil)
)
