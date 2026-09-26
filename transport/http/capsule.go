package http

import (
	std_bufio "bufio"
	"context"
	"encoding/binary"
	"errors"
	"github.com/sagernet/sing-box/adapter"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	CapsuleTypeDatagram = 0
	CapsuleHeadroom     = 1 + 4 + 1
	MaxCapsuleLength    = 1 << 20
)

func ReadVarint(reader *std_bufio.Reader) (uint64, int, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	length := 1 << (first >> 6)
	value := uint64(first & 0x3f)
	for i := 1; i < length; i++ {
		var next byte
		next, err = reader.ReadByte()
		if err != nil {
			return 0, 0, err
		}
		value = value<<8 | uint64(next)
	}
	return value, length, nil
}

func DecodeVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	length := 1 << (b[0] >> 6)
	if len(b) < length {
		return 0, 0, false
	}
	value := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		value = value<<8 | uint64(b[i])
	}
	return value, length, true
}

func VarintLen(value uint64) int {
	switch {
	case value < 1<<6:
		return 1
	case value < 1<<14:
		return 2
	case value < 1<<30:
		return 4
	default:
		return 8
	}
}

func PutVarint(b []byte, value uint64) int {
	switch VarintLen(value) {
	case 1:
		b[0] = byte(value)
		return 1
	case 2:
		binary.BigEndian.PutUint16(b, uint16(value)|0x4000)
		return 2
	case 4:
		binary.BigEndian.PutUint32(b, uint32(value)|0x80000000)
		return 4
	default:
		binary.BigEndian.PutUint64(b, value|0xC000000000000000)
		return 8
	}
}

func readDatagramCapsule(reader *std_bufio.Reader, buffer *buf.Buffer) error {
	for {
		capsuleType, _, err := ReadVarint(reader)
		if err != nil {
			return err
		}
		length, _, err := ReadVarint(reader)
		if err != nil {
			return err
		}
		if length > MaxCapsuleLength {
			return E.New("capsule too large: ", length)
		}
		if capsuleType != CapsuleTypeDatagram {
			_, err = reader.Discard(int(length))
			if err != nil {
				return err
			}
			continue
		}
		contextID, contextLength, err := ReadVarint(reader)
		if err != nil {
			return err
		}
		if uint64(contextLength) > length {
			return E.New("malformed datagram capsule")
		}
		payloadLength := int(length) - contextLength
		if contextID != 0 || payloadLength > buffer.FreeLen() {
			_, err = reader.Discard(payloadLength)
			if err != nil {
				return err
			}
			continue
		}
		_, err = buffer.ReadFullFrom(reader, payloadLength)
		return err
	}
}

func PrependContextID(buffer *buf.Buffer) *buf.Buffer {
	if buffer.Start() >= 1 {
		buffer.ExtendHeader(1)[0] = 0
		return buffer
	}
	datagram := buf.NewSize(1 + buffer.Len())
	datagram.WriteByte(0)
	datagram.Write(buffer.Bytes())
	buffer.Release()
	return datagram
}

func WriteDatagramCapsule(writer io.Writer, datagram *buf.Buffer) error {
	length := uint64(datagram.Len())
	headerLength := 1 + VarintLen(length)
	var capsule *buf.Buffer
	if datagram.Start() >= headerLength {
		header := datagram.ExtendHeader(headerLength)
		header[0] = CapsuleTypeDatagram
		PutVarint(header[1:], length)
		capsule = datagram
	} else {
		capsule = buf.NewSize(headerLength + datagram.Len())
		header := capsule.Extend(headerLength)
		header[0] = CapsuleTypeDatagram
		PutVarint(header[1:], length)
		capsule.Write(datagram.Bytes())
		datagram.Release()
	}
	defer capsule.Release()
	_, err := writer.Write(capsule.Bytes())
	return err
}

func WriteDatagramCapsules(writer io.Writer, datagrams []*buf.Buffer) error {
	if len(datagrams) == 1 {
		return WriteDatagramCapsule(writer, datagrams[0])
	}
	defer buf.ReleaseMulti(datagrams)
	var totalLength int
	for _, datagram := range datagrams {
		totalLength += 1 + VarintLen(uint64(datagram.Len())) + datagram.Len()
	}
	capsules := buf.NewSize(min(totalLength, buf.MaxPooledBufferSize))
	defer capsules.Release()
	for _, datagram := range datagrams {
		length := uint64(datagram.Len())
		headerLength := 1 + VarintLen(length)
		if headerLength+datagram.Len() > capsules.FreeLen() {
			_, err := writer.Write(capsules.Bytes())
			if err != nil {
				return err
			}
			capsules.Reset()
		}
		header := capsules.Extend(headerLength)
		header[0] = CapsuleTypeDatagram
		PutVarint(header[1:], length)
		common.Must1(capsules.Write(datagram.Bytes()))
	}
	_, err := writer.Write(capsules.Bytes())
	return err
}

type capsuleConn struct {
	reader      *std_bufio.Reader
	writer      io.Writer
	upstream    net.Conn
	destination M.Socksaddr
	writeAccess sync.Mutex
}

func newCapsuleConn(reader *std_bufio.Reader, upstream net.Conn, destination M.Socksaddr) *capsuleConn {
	return &capsuleConn{
		reader:      reader,
		writer:      upstream,
		upstream:    upstream,
		destination: destination,
	}
}

func (c *capsuleConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	err := readDatagramCapsule(c.reader, buffer)
	if err != nil {
		return M.Socksaddr{}, err
	}
	return c.destination, nil
}

func (c *capsuleConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	return WriteDatagramCapsule(c.writer, PrependContextID(buffer))
}

func (c *capsuleConn) Close() error {
	return c.upstream.Close()
}

func (c *capsuleConn) LocalAddr() net.Addr {
	return c.upstream.LocalAddr()
}

func (c *capsuleConn) SetDeadline(t time.Time) error {
	return c.upstream.SetDeadline(t)
}

func (c *capsuleConn) SetReadDeadline(t time.Time) error {
	return c.upstream.SetReadDeadline(t)
}

func (c *capsuleConn) SetWriteDeadline(t time.Time) error {
	return c.upstream.SetWriteDeadline(t)
}

func (c *capsuleConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *capsuleConn) FrontHeadroom() int {
	return CapsuleHeadroom
}

func (c *capsuleConn) Upstream() any {
	return c.upstream
}

var _ N.PacketConn = (*capsuleConn)(nil)

// IsUDPConnect reports that this CONNECT-UDP tunnel has a fixed destination.
//
// capsuleConn is built for an RFC 9298 CONNECT-UDP request, whose target is parsed once
// from the request path and never changes, so this is always true.
func (c *capsuleConn) IsUDPConnect() bool { return true }

var _ adapter.UDPConnectPacketConn = (*capsuleConn)(nil)

type DatagramStream interface {
	io.ReadWriteCloser
	SendDatagram(payload []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	// DatagramsEnabled reports whether the PEER negotiated HTTP Datagrams, i.e. whether
	// SendDatagram can succeed and ReceiveDatagram can ever deliver. The stream type
	// cannot answer that: the same concrete type satisfies every method here whether or
	// not the peer negotiated the extension.
	DatagramsEnabled() bool
}

var (
	HTTP3StreamFunc        func(ctx context.Context, writer http.ResponseWriter) (DatagramStream, bool)
	ErrDatagramUnsupported = E.New("datagram unsupported")
)

type DatagramTooLargeError struct {
	MaxPayloadSize int
}

func (e *DatagramTooLargeError) Error() string {
	return F.ToString("datagram too large, maximum payload size is ", e.MaxPayloadSize)
}

func (e *DatagramTooLargeError) Unwrap() error {
	return ErrDatagramUnsupported
}

type http3PacketConn struct {
	stream      DatagramStream
	reader      *std_bufio.Reader
	destination M.Socksaddr
	localAddr   net.Addr
	packets     chan *buf.Buffer
	ctx         context.Context
	cancel      context.CancelFunc
	closeOnce   sync.Once
	waitGroup   sync.WaitGroup
	writeAccess sync.Mutex
	err         error

	// Deferred-success state.
	//
	// For an H3 CONNECT-UDP request the HTTP response is withheld until the target
	// is actually reachable, so a setup failure can be reported as an HTTP error
	// instead of a 200 followed by silence. The router signals the outcome through
	// the handshake hooks; this connection carries the signal back to the handler
	// goroutine, which is the only goroutine allowed to touch the ResponseWriter.
	//
	// early holds datagrams that arrived while the target was still being set up. A
	// client is entitled to send immediately after the request, and dropping those
	// datagrams would lose the first packets of a tunnel that succeeds moments later.
	early      []*buf.Buffer
	earlyBytes int
	earlyMutex sync.Mutex
	// settled is closed once ready/failure has been decided.
	settled chan struct{}
	// ready reports whether the target setup succeeded.
	ready bool
	// setupErr is the failure reported by the router, if any.
	setupErr error
	// handshakeOnce guards the single settle of the outcome.
	handshakeOnce sync.Once
	// activated switches the connection from buffering to normal delivery.
	activated atomic.Bool
}

// maxEarlyDatagramPackets and maxEarlyDatagramBytes bound the datagrams buffered before
// the target is confirmed. Past the bound the excess is dropped, which is the
// correct UDP semantic and keeps a setup-time flood from spending server memory.
const (
	maxEarlyDatagramPackets = 8
	maxEarlyDatagramBytes   = 64 << 10
)

func newHTTP3PacketConn(stream DatagramStream, destination M.Socksaddr, localAddr net.Addr) *http3PacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	conn := &http3PacketConn{
		stream:      stream,
		reader:      std_bufio.NewReader(stream),
		destination: destination,
		localAddr:   localAddr,
		packets:     make(chan *buf.Buffer, 64),
		ctx:         ctx,
		cancel:      cancel,
		settled:     make(chan struct{}),
	}
	// A connection is ACTIVE by default so the non-deferred callers (and the fixtures in
	// this package) deliver immediately. The H3 CONNECT-UDP path calls
	// deferUntilTargetReady to hold datagrams until the target is confirmed.
	conn.activated.Store(true)
	conn.waitGroup.Add(2)
	go conn.loopDatagram()
	go conn.loopCapsule()
	return conn
}

func (c *http3PacketConn) loopDatagram() {
	defer c.waitGroup.Done()
	for {
		datagram, err := c.stream.ReceiveDatagram(c.ctx)
		if err != nil {
			c.closeWithError(err)
			return
		}
		contextID, contextLength, valid := DecodeVarint(datagram)
		if !valid || contextID != 0 {
			continue
		}
		// ZERO-COPY: wrap the payload slice instead of copying it into a pooled
		// buffer.
		//
		// This is safe only because of a property of the pinned quic-go that was
		// VERIFIED rather than assumed (v0.61.0-sing-box-mod.7):
		//
		//	datagram_queue.go HandleDatagramFrame:
		//	    data := make([]byte, len(f.Data)); copy(data, f.Data)
		//	http3/state_tracking_stream.go enqueueDatagram: appends that slice
		//	ReceiveDatagram: returns it and drops its own reference
		//
		// So the returned []byte is an INDEPENDENT allocation, not a window into a
		// QUIC receive scratch buffer that the transport will reuse. Nothing else
		// holds a reference to it once ReceiveDatagram returns, and the queue slot is
		// popped before the value is handed back.
		//
		// buf.As is the right wrapper for that: it is UNMANAGED, so Release() does not
		// return the slice to a pool - the backing allocation belongs to quic-go and
		// is reclaimed by the GC. Using a managed pooled buffer here would hand
		// quic-go's memory to the pool, and a later Get() could hand the same bytes to
		// an unrelated code path.
		//
		// A zero-length payload is preserved: buf.As of an empty slice yields a
		// zero-length buffer, which is a legal UDP datagram and must still be
		// delivered. An empty datagram and no datagram are different outcomes.
		buffer := buf.As(datagram[contextLength:])
		// Before the target is ready, hold the datagram instead of queueing it: the
		// tunnel has not been confirmed yet, and a client is entitled to send
		// immediately after its request.
		if !c.activated.Load() {
			if !c.bufferEarlyDatagram(buffer) {
				// Past a bound. Dropping is the UDP semantic and the only bounded
				// choice; the client will retry at the application layer if it cares.
				buffer.Release()
			}
			continue
		}
		select {
		case c.packets <- buffer:
		case <-c.ctx.Done():
			buffer.Release()
			return
		}
	}
}

func (c *http3PacketConn) loopCapsule() {
	defer c.waitGroup.Done()
	for {
		buffer := buf.NewPacket()
		err := readDatagramCapsule(c.reader, buffer)
		if err != nil {
			buffer.Release()
			c.closeWithError(err)
			return
		}
		select {
		case c.packets <- buffer:
		case <-c.ctx.Done():
			buffer.Release()
			return
		}
	}
}

func (c *http3PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	for {
		select {
		case packet := <-c.packets:
			if packet.Len() > buffer.FreeLen() {
				packet.Release()
				continue
			}
			buffer.Write(packet.Bytes())
			packet.Release()
			return c.destination, nil
		case <-c.ctx.Done():
			return M.Socksaddr{}, c.err
		}
	}
}

func (c *http3PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	datagram := PrependContextID(buffer)
	err := c.stream.SendDatagram(datagram.Bytes())
	if err == nil {
		datagram.Release()
		return nil
	}
	if !errors.Is(err, ErrDatagramUnsupported) {
		datagram.Release()
		return err
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	return WriteDatagramCapsule(c.stream, datagram)
}

// closeError reports the connection's terminal error, defaulting to net.ErrClosed so a
// caller never receives a nil error alongside an empty result.
func (c *http3PacketConn) closeError() error {
	if c.err != nil {
		return c.err
	}
	return net.ErrClosed
}

// takeEarlyDatagrams detaches and returns the datagrams buffered during target setup,
// leaving the queue empty.
//
// Detaching under earlyMutex is what makes the queue safe to claim from two racing
// callers: settle() flushes these to the packet queue, and closeWithError() releases
// them when the peer disappears before an outcome is known. A router that reports the
// outcome while the peer is disconnecting does both, so whichever arrives first takes
// ownership and the other finds nothing.
func (c *http3PacketConn) takeEarlyDatagrams() []*buf.Buffer {
	c.earlyMutex.Lock()
	defer c.earlyMutex.Unlock()
	early := c.early
	c.early = nil
	c.earlyBytes = 0
	return early
}

// releaseEarlyDatagrams releases the datagrams buffered during target setup.
//
// It is the close-time counterpart of settle()'s flush: when the connection goes away
// before the router reports an outcome, settle() never runs, and without this the
// buffers held by the setup window would never reach Release. A peer that opens a
// CONNECT-UDP request, sends datagrams and then hangs up during setup can trigger it at
// will, so it is a peer-reachable leak rather than a teardown edge case.
func (c *http3PacketConn) releaseEarlyDatagrams() {
	buf.ReleaseMulti(c.takeEarlyDatagrams())
}

func (c *http3PacketConn) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.err = err
		c.cancel()
		c.stream.Close()
		c.releaseEarlyDatagrams()
		go func() {
			c.waitGroup.Wait()
			for {
				select {
				case packet := <-c.packets:
					packet.Release()
				default:
					return
				}
			}
		}()
	})
}

func (c *http3PacketConn) Close() error {
	c.closeWithError(net.ErrClosed)
	return nil
}

func (c *http3PacketConn) wait(ctx context.Context) {
	select {
	case <-c.ctx.Done():
	case <-ctx.Done():
		c.Close()
	}
}

func (c *http3PacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *http3PacketConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *http3PacketConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *http3PacketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *http3PacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *http3PacketConn) FrontHeadroom() int {
	return CapsuleHeadroom
}

// deferUntilTargetReady holds incoming datagrams until the router reports the target
// setup outcome through the handshake hooks.
//
// It must be called BEFORE the connection is handed to the router, so no datagram can
// be delivered on the strength of a 200 that has not been sent yet.
func (c *http3PacketConn) deferUntilTargetReady() {
	c.activated.Store(false)
	c.handshakeOnce = sync.Once{}
	c.settled = make(chan struct{})
}

// IsUDPConnect reports that this H3 CONNECT-UDP tunnel has a fixed destination.
//
// http3PacketConn is built only for an RFC 9298 CONNECT-UDP request, so its
// destination is the parsed target for the tunnel's whole lifetime.
func (c *http3PacketConn) IsUDPConnect() bool { return true }

var _ adapter.UDPConnectPacketConn = (*http3PacketConn)(nil)

// PacketConnHandshakeSuccess is called by the router once the target socket is ready.
//
// This is the signal that lets the HTTP handler send a 200. It does NOT send anything
// itself: the handler goroutine owns the ResponseWriter, and writing from the router
// goroutine would race with the handler. So this only records the outcome and closes
// the settled channel.
//
// It also activates normal delivery. Everything buffered during setup is handed to the
// packet queue FIRST, in arrival order, so no early datagram is lost and none is
// delivered twice.
func (c *http3PacketConn) PacketConnHandshakeSuccess(net.PacketConn) error {
	c.settle(true, nil)
	return nil
}

// HandshakeFailure is called by the router when the target could not be set up.
//
// The error is carried to the handler so it can be mapped to an HTTP status. It is NOT
// returned to the router as a failure to write a handshake response: the handler is the
// one that must respond, and it has not had the chance yet.
func (c *http3PacketConn) HandshakeFailure(err error) error {
	c.settle(false, err)
	return nil
}

// settle records the setup outcome exactly once and releases any buffered datagrams.
//
// sync.Once is what makes double-settling safe: a router that reports success and then
// reports a failure while tearing down must not flip the result or panic on a closed
// channel.
func (c *http3PacketConn) settle(ready bool, err error) {
	c.handshakeOnce.Do(func() {
		c.ready = ready
		c.setupErr = err
		c.activated.Store(true)

		// Flush the early queue in arrival order. Buffers that no longer fit the queue
		// are released rather than leaked.
		early := c.takeEarlyDatagrams()
		for _, buffer := range early {
			select {
			case c.packets <- buffer:
			default:
				// The queue is full, so the tunnel is already behind. Dropping here is
				// the UDP semantic; blocking would stall the router goroutine.
				buffer.Release()
			}
		}
		close(c.settled)
	})
}

// AwaitReady blocks until the target setup has been decided, and reports the outcome.
//
// The handler calls this before writing a response. A context cancellation (the client
// disconnected) returns an error so the handler does not wait forever on a peer that is
// gone.
func (c *http3PacketConn) AwaitReady(ctx context.Context) error {
	select {
	case <-c.settled:
		return c.setupErr
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

// bufferEarlyDatagram holds one datagram received before the target was ready.
//
// It reports whether the datagram was retained. Once either bound is reached further
// datagrams are refused, and the caller drops them.
func (c *http3PacketConn) bufferEarlyDatagram(buffer *buf.Buffer) bool {
	c.earlyMutex.Lock()
	defer c.earlyMutex.Unlock()
	if len(c.early) >= maxEarlyDatagramPackets || c.earlyBytes+buffer.Len() > maxEarlyDatagramBytes {
		return false
	}
	c.early = append(c.early, buffer)
	c.earlyBytes += buffer.Len()
	return true
}

// CreateConnectedPacketBatchReadWaiter offers the batch read path to bufio.CopyPacket.
//
// # Why the destination being fixed is what makes this possible
//
// The standard batch waiter must return a destination per packet, because an
// unconnected socket can receive from anywhere. This connection's destination is fixed
// by the CONNECT-UDP request, so the connected form is the honest one: it returns a
// single destination for the whole batch and lets the writer use a connected socket.
//
// bufio.CopyPacket tries the batch forms BEFORE the single-packet form, so offering
// this is what moves a CONNECT-UDP tunnel off the one-packet-at-a-time path and onto
// copyConnectedPacketBatchToConnectedWaitWithPool. That path is also the only consumer
// of the zero-copy wrapping done at ingress: ReadPacket must copy into the caller's
// buffer, but the batch waiter hands the queued buffers straight to the writer.
//
// Returning false here is always safe: CopyPacket falls through to the next capability,
// and ultimately to ReadPacket/WritePacket. So this is an optimization the caller opts
// into, never a correctness requirement.
// CreateConnectedPacketBatchReadWaiter offers the batch read path to bufio.CopyPacket.
//
// # Why the destination being fixed is what makes this possible
//
// The standard batch waiter must return a destination per packet, because an
// unconnected socket can receive from anywhere. This connection's destination is fixed
// by the CONNECT-UDP request, so the connected form is the honest one: it returns a
// single destination for the whole batch and lets the writer use a connected socket.
//
// bufio.CopyPacket tries the batch forms BEFORE the single-packet form, so offering
// this is what moves a CONNECT-UDP tunnel off the one-packet-at-a-time path and onto
// copyConnectedPacketBatchToConnectedWaitWithPool. That path is also the only consumer
// of the zero-copy wrapping done at ingress: ReadPacket must copy into the caller's
// buffer, but the batch waiter hands the queued buffers straight to the writer.
//
// Returning false here is always safe: CopyPacket falls through to the next capability,
// and ultimately to ReadPacket/WritePacket. So this is an optimization the caller opts
// into, never a correctness requirement.
func (c *http3PacketConn) CreateConnectedPacketBatchReadWaiter() (N.ConnectedPacketBatchReadWaiter, bool) {
	return &connectedBatchReadWaiter{conn: c, batchSize: defaultBatchSize}, true
}

// CreateConnectedPacketBatchWriteCreator offers the batch write path to bufio.CopyPacket.
func (c *http3PacketConn) CreateConnectedPacketBatchWriter() (N.ConnectedPacketBatchWriter, bool) {
	return &connectedBatchWriter{conn: c}, true
}

// defaultBatchSize is the number of datagrams one batch read collects when the caller
// does not ask for a specific size. It matches sing's DefaultPacketReadBatchSize so a
// CONNECT-UDP tunnel batches like every other connected UDP path rather than inventing
// its own number.
const defaultBatchSize = 64

// connectedBatchReadWaiter collects queued datagrams into one batch.
type connectedBatchReadWaiter struct {
	conn      *http3PacketConn
	batchSize int
}

// InitializeReadWaiter reserves the batch slice. It reports needCopy=false because the
// queue already holds fully-formed buffers: nothing has to be copied into the waiter's
// own storage.
func (w *connectedBatchReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.batchSize = options.BatchSize
	if w.batchSize <= 0 {
		w.batchSize = defaultBatchSize
	}
	return false
}

// WaitReadConnectedPackets blocks for the first datagram, then drains what is already
// queued up to the batch bound.
//
// The first packet MAY block; every later one is taken non-blockingly, so a batch is
// whatever the tunnel actually has in flight and never waits for a slow sender to fill
// it. An empty return with ok reports a closed connection.
//
// Ownership: every buffer returned is handed to the caller, which in the CopyPacket
// path is the batch writer that releases them. On the error path nothing is returned
// and nothing is leaked, because the buffers taken from the queue are returned to the
// caller or, on a context cancellation, released here.
func (w *connectedBatchReadWaiter) WaitReadConnectedPackets() ([]*buf.Buffer, M.Socksaddr, error) {
	// The first packet may block: an idle tunnel must park here rather than spin.
	select {
	case first := <-w.conn.packets:
		buffers := make([]*buf.Buffer, 0, w.batchSize)
		buffers = append(buffers, first)
		// Drain what is ALREADY queued, without waiting for more.
		//
		// The bound is the batch size, so one slow reader cannot turn a burst into an
		// unbounded allocation. Anything left stays queued for the next round, which
		// preserves order: the channel is FIFO and this loop takes from the front.
		for len(buffers) < w.batchSize {
			select {
			case next := <-w.conn.packets:
				buffers = append(buffers, next)
			default:
				return buffers, w.conn.destination, nil
			}
		}
		return buffers, w.conn.destination, nil
	case <-w.conn.ctx.Done():
		return nil, M.Socksaddr{}, w.conn.closeError()
	}
}

// connectedBatchWriter forwards one batch of target replies to the client.
type connectedBatchWriter struct {
	conn *http3PacketConn
}

// WriteConnectedPacketBatch sends one batch, holding the write lock ONCE for the whole
// batch instead of once per packet.
//
// # Datagram vs capsule, per packet
//
// The transport decision is made per packet, because it depends on whether the peer
// negotiated HTTP Datagrams and on whether THIS payload fits:
//
//	a datagram-capable peer, payload accepted  -> HTTP Datagram
//	DatagramUnsupported                        -> DATAGRAM capsule
//	DatagramTooLarge                           -> DATAGRAM capsule (it is a size problem,
//	                                              not a capability problem: the peer can
//	                                              still read a capsule, and a capsule
//	                                              has no datagram size ceiling)
//	any other error                            -> returned to the caller
//
// That last line is deliberate and matches the single-packet path: a real QUIC
// connection error must NOT be downgraded into a capsule write, which would turn a
// transport failure into a silent protocol change.
//
// The single lock for the batch is what makes the capsule case cheaper: a run of
// fallback capsules is written under one acquisition, in order, instead of one
// lock/unlock per packet.
//
// Ownership: the batch AND everything in it belongs to this call in all cases, so it
// releases every buffer before returning, on every path.
func (w *connectedBatchWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	c := w.conn

	// Datagrams cannot be written concurrently on one stream, and the capsule fallback
	// writes to the stream too, so the whole batch takes the lock once.
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()

	defer func() {
		for _, buffer := range buffers {
			buffer.Release()
		}
	}()

	for _, buffer := range buffers {
		if err := c.writeOnePacketLocked(buffer); err != nil {
			return err
		}
	}
	return nil
}

// writeOnePacketLocked writes a single payload, datagram-first with a capsule fallback.
// The caller MUST hold writeAccess.
func (c *http3PacketConn) writeOnePacketLocked(buffer *buf.Buffer) error {
	datagram := PrependContextID(buffer)
	if c.stream.DatagramsEnabled() {
		err := c.stream.SendDatagram(datagram.Bytes())
		switch {
		case err == nil:
			// SendDatagram copies the payload into the QUIC frame, so the buffer is
			// reusable immediately; the caller's deferred release handles it.
			return nil
		case errors.Is(err, ErrDatagramUnsupported):
			// Fall through to the capsule path.
		default:
			var tooLarge *DatagramTooLargeError
			if !errors.As(err, &tooLarge) {
				// A real transport error. Returning it lets CopyPacket close the
				// session instead of silently switching transports.
				return err
			}
			// Too large for a datagram: a capsule carries it instead. This is a size
			// decision, not a capability one.
		}
	}
	return WriteDatagramCapsule(c.stream, datagram)
}

var _ N.PacketConn = (*http3PacketConn)(nil)
