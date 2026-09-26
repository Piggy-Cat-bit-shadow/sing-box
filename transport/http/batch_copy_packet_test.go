package http

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// bufio.CopyPacket must SELECT the connected batch path through the timeout wrapper.
//
// # Why the capability tests are not enough
//
// A test that asks "does CreateConnectedPacketBatchWriter return true" proves the
// capability is visible. It does not prove the copy loop uses it: the selection in
// bufio.CopyPacket depends on several further conditions - the read waiter's needCopy,
// the LowMemory flag, and the order in which the capability variants are tried - and any
// of them can route the copy back to one packet at a time while the capability itself
// remains perfectly visible.
//
// So this test drives the REAL copy function and asserts on what the far end received.
// The fixtures are instrumented so that falling back is not merely slower, it is
// OBSERVABLE, and the assertions fail on the per-packet counters rather than on timing.
//
// # The shape being exercised
//
//	instrumented batch source
//	  -> canceler.NewPacketConn        (the idle-timeout wrapper route/conn.go applies)
//	  -> instrumented batch destination
//	  -> bufio.CopyPacket
//
// The destination counts batch calls and single-packet calls separately. A correct run
// shows batches and no per-packet fallback.

// ---------------------------------------------------------------------------
// Instrumented endpoints
// ---------------------------------------------------------------------------

// instrumentedBatchSource is a connected packet reader that offers the batch capability
// and counts every read that goes through each route.
type instrumentedBatchSource struct {
	packets chan []byte
	closed  chan struct{}
	once    sync.Once

	access sync.Mutex
	// batchWaits counts WaitReadConnectedPackets calls; singleReads counts ReadPacket
	// calls. A batch-path run must show the former and no growth in the latter.
	batchWaits  int
	singleReads int
	// perBatch is how many packets each batch should deliver.
	perBatch int
	// remaining is how many packets are left to serve before EOF-like behaviour.
	remaining int
}

func newInstrumentedBatchSource(total, perBatch int) *instrumentedBatchSource {
	return &instrumentedBatchSource{
		packets:   make(chan []byte, total+8),
		closed:    make(chan struct{}),
		perBatch:  perBatch,
		remaining: total,
	}
}

// push queues one payload.
func (s *instrumentedBatchSource) push(payload []byte) {
	s.packets <- payload
}

// finish makes the source stop once everything queued has been consumed.
func (s *instrumentedBatchSource) finish() {
	s.once.Do(func() { close(s.closed) })
}

func (s *instrumentedBatchSource) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	s.access.Lock()
	s.singleReads++
	s.access.Unlock()
	select {
	case payload := <-s.packets:
		buffer.Write(payload)
		return M.ParseSocksaddr("192.0.2.10:443"), nil
	default:
		return M.Socksaddr{}, errBatchSourceDrained
	}
}

func (s *instrumentedBatchSource) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (s *instrumentedBatchSource) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (s *instrumentedBatchSource) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, errBatchSourceDrained
}

func (s *instrumentedBatchSource) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, errBatchSourceDrained
}

func (s *instrumentedBatchSource) Close() error {
	s.finish()
	return nil
}

func (s *instrumentedBatchSource) SetReadDeadline(t time.Time) error  { return os.ErrInvalid }
func (s *instrumentedBatchSource) SetWriteDeadline(t time.Time) error { return os.ErrInvalid }
func (s *instrumentedBatchSource) SetDeadline(t time.Time) error      { return os.ErrInvalid }

// CreateConnectedPacketBatchReadWaiter offers the batch read path.
func (s *instrumentedBatchSource) CreateConnectedPacketBatchReadWaiter() (N.ConnectedPacketBatchReadWaiter, bool) {
	return &instrumentedBatchReadWaiter{source: s}, true
}

// CreateConnectedPacketBatchWriter is offered too, so the source cannot be the reason a
// run falls back; the assertion is about the DESTINATION side and the wrapper.
func (s *instrumentedBatchSource) CreateConnectedPacketBatchWriter() (N.ConnectedPacketBatchWriter, bool) {
	return &discardBatchWriter{}, true
}

func (s *instrumentedBatchSource) counters() (batchWaits, singleReads int) {
	s.access.Lock()
	defer s.access.Unlock()
	return s.batchWaits, s.singleReads
}

type instrumentedBatchReadWaiter struct {
	source *instrumentedBatchSource
	size   int
}

func (w *instrumentedBatchReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.size = options.BatchSize
	if w.size <= 0 {
		w.size = 1
	}
	// The source hands over ready-made buffers, so no copy is required. Reporting true
	// here would make CopyPacket take the copy path and the batch route would not be the
	// one under test.
	return false
}

func (w *instrumentedBatchReadWaiter) WaitReadConnectedPackets() ([]*buf.Buffer, M.Socksaddr, error) {
	w.source.access.Lock()
	w.source.batchWaits++
	remaining := w.source.remaining
	w.source.access.Unlock()

	if remaining <= 0 {
		return nil, M.Socksaddr{}, errBatchSourceDrained
	}

	want := w.size
	if want > remaining {
		want = remaining
	}

	// Drain what is ALREADY queued, up to the bound, without waiting for more. This is
	// what makes the batch a property of the queued data rather than of the timing.
	buffers := make([]*buf.Buffer, 0, want)
	for len(buffers) < want {
		select {
		case payload := <-w.source.packets:
			// A zero-length payload is still a packet, so it is appended like any other;
			// skipping it would drop legitimate RFC 9298 traffic.
			packet := buf.NewSize(len(payload))
			if len(payload) > 0 {
				packet.Write(payload)
			}
			buffers = append(buffers, packet)
		default:
			// Nothing further queued: return what was collected.
			if len(buffers) == 0 {
				return nil, M.Socksaddr{}, errBatchSourceDrained
			}
			len := len(buffers)
			w.source.access.Lock()
			w.source.remaining -= len
			w.source.access.Unlock()
			return buffers, M.ParseSocksaddr("192.0.2.10:443"), nil
		}
	}

	count := len(buffers)
	w.source.access.Lock()
	w.source.remaining -= count
	w.source.access.Unlock()
	return buffers, M.ParseSocksaddr("192.0.2.10:443"), nil
}

type discardBatchWriter struct{}

func (w *discardBatchWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	buf.ReleaseMulti(buffers)
	return nil
}

// instrumentedBatchDestination records what arrived and by which route.
type instrumentedBatchDestination struct {
	access sync.Mutex
	// batches counts WriteConnectedPacketBatch calls.
	batches int
	// singleWrites counts WritePacket calls, i.e. the per-packet fallback.
	singleWrites int
	// payloads records every payload in arrival order.
	payloads [][]byte
	// destinations records the destination reported with each delivered payload.
	destinations []M.Socksaddr
	closed       chan struct{}
	once         sync.Once
}

func newInstrumentedBatchDestination() *instrumentedBatchDestination {
	return &instrumentedBatchDestination{closed: make(chan struct{})}
}

func (d *instrumentedBatchDestination) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	d.access.Lock()
	d.singleWrites++
	d.payloads = append(d.payloads, append([]byte(nil), buffer.Bytes()...))
	d.destinations = append(d.destinations, destination)
	d.access.Unlock()
	buffer.Release()
	return nil
}

func (d *instrumentedBatchDestination) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	<-d.closed
	return M.Socksaddr{}, errBatchSourceDrained
}

func (d *instrumentedBatchDestination) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (d *instrumentedBatchDestination) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, errBatchSourceDrained
}

func (d *instrumentedBatchDestination) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, errBatchSourceDrained
}

func (d *instrumentedBatchDestination) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func (d *instrumentedBatchDestination) SetReadDeadline(t time.Time) error  { return os.ErrInvalid }
func (d *instrumentedBatchDestination) SetWriteDeadline(t time.Time) error { return os.ErrInvalid }
func (d *instrumentedBatchDestination) SetDeadline(t time.Time) error      { return os.ErrInvalid }

// CreateConnectedPacketBatchWriter offers the batch write path and counts its use.
func (d *instrumentedBatchDestination) CreateConnectedPacketBatchWriter() (N.ConnectedPacketBatchWriter, bool) {
	return &countingBatchDestinationWriter{destination: d}, true
}

func (d *instrumentedBatchDestination) counters() (batches, singleWrites int, payloads [][]byte) {
	d.access.Lock()
	defer d.access.Unlock()
	return d.batches, d.singleWrites, append([][]byte(nil), d.payloads...)
}

type countingBatchDestinationWriter struct {
	destination *instrumentedBatchDestination
}

func (w *countingBatchDestinationWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	w.destination.access.Lock()
	w.destination.batches++
	for _, buffer := range buffers {
		w.destination.payloads = append(w.destination.payloads,
			append([]byte(nil), buffer.Bytes()...))
		w.destination.destinations = append(w.destination.destinations, M.Socksaddr{})
	}
	w.destination.access.Unlock()
	// The real writers consume their input; mirroring that keeps the ownership
	// expectation identical to production.
	buf.ReleaseMulti(buffers)
	return nil
}

// ---------------------------------------------------------------------------
// The integration test
// ---------------------------------------------------------------------------

// TestCopyPacketSelectsTheConnectedBatchPathThroughTheTimeoutWrapper is the acceptance
// test for the whole fix.
//
// It is the chain the task describes, driven end to end:
//
//	source -> canceler.NewPacketConn -> bufio.CopyPacket -> connected batch writer
//
// A fallback to per-packet I/O is not merely slower here, it is visible: the destination
// counts the two routes separately, and the test requires the batch route to carry every
// payload while the single-packet route is never used.
func TestCopyPacketSelectsTheConnectedBatchPathThroughTheTimeoutWrapper(t *testing.T) {
	const totalPackets = 16

	source := newInstrumentedBatchSource(totalPackets, 8)
	defer source.Close()
	destination := newInstrumentedBatchDestination()
	defer destination.Close()

	// Payloads of different lengths, so a truncated or reordered batch cannot pass by
	// accident, and one ZERO-LENGTH payload because RFC 9298 carries those as ordinary
	// traffic and a batch must not lose them.
	expected := make([][]byte, 0, totalPackets)
	for index := range totalPackets {
		size := index + 1
		if index == 3 {
			size = 0
		}
		payload := make([]byte, size)
		for position := range payload {
			payload[position] = byte('a' + index)
		}
		expected = append(expected, payload)
		source.push(payload)
	}

	// The idle-timeout wrapper route/conn.go applies, over a source that cannot take a
	// read deadline - the TimerPacketConn branch, which is the branch the HTTP/3 packet
	// connection takes.
	_, wrapped := canceler.NewPacketConn(context.Background(), source, 30*time.Second)
	_, isTimer := wrapped.(*canceler.TimerPacketConn)
	require.True(t, isTimer,
		"the fixture must exercise the TimerPacketConn branch, got %T", wrapped)

	// Run the real copy with a bounded deadline, so a regression that makes the copy
	// block would fail here rather than hanging the suite.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = bufio.CopyPacket(destination, wrapped)
	}()

	require.Eventually(t, func() bool {
		_, _, payloads := destination.counters()
		return len(payloads) >= totalPackets
	}, 10*time.Second, 10*time.Millisecond,
		"bufio.CopyPacket must deliver every queued packet through the wrapped batch path")

	batches, singleWrites, payloads := destination.counters()

	// The batch route must have carried the traffic.
	require.Greater(t, batches, 0,
		"CopyPacket must select the connected batch writer through the timeout wrapper. "+
			"A run with zero batches means the capability was visible but unused, which is "+
			"the exact production failure this fix removes")
	require.Equal(t, 0, singleWrites,
		"CopyPacket must not fall back to one packet per call when the batch path is "+
			"available and the source needs no copy")

	// Content and order must survive batching.
	require.Equal(t, totalPackets, len(payloads),
		"every queued packet must be delivered exactly once")
	for index := range expected {
		// Compared with bytes.Equal rather than require.Equal: a zero-length payload can
		// legitimately arrive as a nil slice while the fixture built an empty non-nil one,
		// and those are the same payload on the wire.
		require.True(t, bytes.Equal(expected[index], payloads[index]),
			"payload %d must arrive intact and in order: got %d bytes %q, want %d bytes %q",
			index, len(payloads[index]), payloads[index],
			len(expected[index]), expected[index])
	}

	// The read side must have gone through the batch waiter too.
	batchWaits, singleReads := source.counters()
	require.Greater(t, batchWaits, 0,
		"the read side must use the connected batch waiter through the wrapper")
	require.Equal(t, 0, singleReads,
		"the read side must not fall back to one packet per call")

	t.Logf("batch path confirmed through the timeout wrapper: %d batches, %d packets, "+
		"%d single-packet writes, %d single-packet reads",
		batches, len(payloads), singleWrites, singleReads)

	source.finish()
	<-done
}

// TestCopyPacketKeepsTheOrdinaryFallbackWithoutBatchSupport is the control.
//
// A connection with no batch capability must still be copied correctly, one packet at a
// time. Without this, a fix that forced the batch route would pass the test above while
// breaking every protocol that never offered batching.
func TestCopyPacketKeepsTheOrdinaryFallbackWithoutBatchSupport(t *testing.T) {
	const totalPackets = 8

	source := &plainPacketSource{packets: make(chan []byte, totalPackets)}
	expected := make([][]byte, 0, totalPackets)
	for index := range totalPackets {
		payload := []byte{byte(index), 0xAA}
		expected = append(expected, payload)
		source.packets <- payload
	}

	destination := newInstrumentedBatchDestination()
	defer destination.Close()

	_, wrapped := canceler.NewPacketConn(context.Background(), source, 30*time.Second)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = bufio.CopyPacket(destination, wrapped)
	}()

	require.Eventually(t, func() bool {
		_, _, payloads := destination.counters()
		return len(payloads) >= totalPackets
	}, 10*time.Second, 10*time.Millisecond,
		"the ordinary per-packet path must still deliver every packet")

	batches, singleWrites, payloads := destination.counters()
	require.Equal(t, 0, batches,
		"no batch capability exists on this connection, so the batch route must not be used")
	require.Greater(t, singleWrites, 0,
		"the ordinary per-packet route is the correct path here")
	require.Equal(t, totalPackets, len(payloads))
	for index := range expected {
		require.True(t, bytes.Equal(expected[index], payloads[index]),
			"payload %d must arrive intact on the fallback path", index)
	}
	<-done
}

// errBatchSourceDrained ends the copy once the fixture has nothing left to give.
var errBatchSourceDrained = errors.New("batch fixture drained")

// plainPacketSource is a connected packet reader with NO batch capability, used for the
// fallback control test.
type plainPacketSource struct {
	packets chan []byte
	closed  chan struct{}
	once    sync.Once
	access  sync.Mutex
	reads   int
}

func (s *plainPacketSource) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	s.access.Lock()
	s.reads++
	s.access.Unlock()
	select {
	case payload := <-s.packets:
		buffer.Write(payload)
		return M.ParseSocksaddr("192.0.2.10:443"), nil
	default:
		return M.Socksaddr{}, errBatchSourceDrained
	}
}

func (s *plainPacketSource) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (s *plainPacketSource) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (s *plainPacketSource) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, errBatchSourceDrained
}

func (s *plainPacketSource) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, errBatchSourceDrained
}

func (s *plainPacketSource) Close() error {
	if s.closed != nil {
		s.once.Do(func() { close(s.closed) })
	}
	return nil
}

func (s *plainPacketSource) SetReadDeadline(t time.Time) error  { return os.ErrInvalid }
func (s *plainPacketSource) SetWriteDeadline(t time.Time) error { return os.ErrInvalid }
func (s *plainPacketSource) SetDeadline(t time.Time) error      { return os.ErrInvalid }

var (
	_ N.PacketConn                          = (*instrumentedBatchSource)(nil)
	_ N.ConnectedPacketBatchReadWaitCreator = (*instrumentedBatchSource)(nil)
	_ N.ConnectedPacketBatchWriteCreator    = (*instrumentedBatchSource)(nil)
	_ N.PacketConn                          = (*instrumentedBatchDestination)(nil)
	_ N.ConnectedPacketBatchWriteCreator    = (*instrumentedBatchDestination)(nil)
	_ N.PacketConn                          = (*plainPacketSource)(nil)
)
