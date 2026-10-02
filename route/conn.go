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
	logger      logger.ContextLogger
	access      sync.Mutex
	connections list.List[io.Closer]
	// Session-level splice diagnostics. One atomic add per UDP session, never per
	// packet. See splice_diagnostics.go for why, and for what these numbers can and
	// cannot tell you.
	spliceDiagnostics spliceDiagnostics
}

func NewConnectionManager(logger logger.ContextLogger) *ConnectionManager {
	return &ConnectionManager{
		logger: logger,
	}
}

func (m *ConnectionManager) Start(stage adapter.StartStage) error {
	return nil
}

func (m *ConnectionManager) Count() int {
	m.access.Lock()
	defer m.access.Unlock()
	return m.connections.Len()
}

func (m *ConnectionManager) CloseAll() {
	m.access.Lock()
	var closers []io.Closer
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

func (m *ConnectionManager) Close() error {
	m.CloseAll()
	// One line per tunnel lifetime, and only when UDP actually went through the splice
	// decision. This is the only place the diagnostics are reported, deliberately: a
	// per-session or per-packet log would be the very cost the counters exist to measure.
	//
	// Emitting it here means a real-device run needs no instrumentation at all - start the
	// VPN, use the app, stop the VPN, read one line from the log.
	if snapshot := m.SpliceDiagnostics(); snapshot.Attempts > 0 {
		m.logger.Info(snapshot.SpliceSummary())
	}
	return nil
}

func (m *ConnectionManager) TrackConn(conn net.Conn) net.Conn {
	tracked := &trackedConn{
		Conn:        conn,
		socketOwner: socketOwner{original: conn},
		manager:     m,
	}
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
	m.access.Lock()
	tracked.element = m.connections.PushBack(tracked)
	m.access.Unlock()
	return tracked
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
	go m.connectionCopy(ctx, conn, remoteConn, false, uploadIncreaseBufferAfter, &done, onClose)
	go m.connectionCopy(ctx, remoteConn, conn, true, downloadIncreaseBufferAfter, &done, onClose)
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
	go m.packetConnectionCopy(ctx, conn, destination, false, &done, onClose)
	go m.packetConnectionCopy(ctx, destination, conn, true, &done, onClose)
}

func (m *ConnectionManager) connectionCopy(ctx context.Context, source net.Conn, destination net.Conn, direction bool, increaseBufferAfter int64, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	_, err := bufio.CopyWithIncreateBuffer(destination, source, increaseBufferAfter, bufio.DefaultBatchSize)
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

func (m *ConnectionManager) packetConnectionCopy(ctx context.Context, source N.PacketReader, destination N.PacketWriter, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	_, err := bufio.CopyPacket(destination, source)
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
	manager *ConnectionManager
	element *list.Element[io.Closer]
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
	manager *ConnectionManager
	element *list.Element[io.Closer]
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
