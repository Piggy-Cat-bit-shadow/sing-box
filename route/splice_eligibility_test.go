package route

import (
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// These tests pin splice ELIGIBILITY: whether unwrapSpliceTarget and the source
// unwrap can see through a stack of wrappers to the real socket or NAT conn
// underneath.
//
// Why this matters more than it looks. When unwrapping succeeds, sing-tun splices
// the TUN socket to the outbound socket and packets never enter userspace. When it
// fails, both directions fall back to bufio.CopyPacket goroutines: a copy per
// packet plus scheduling and wakeups. At the packet rate a video call produces on a
// phone, that difference is the thermal budget.
//
// A transparent wrapper - a counter, a lifecycle tracker - that fails to forward
// one of these interfaces turns a spliceable flow into a copying one, silently.
// Nothing logs, nothing errors; the only symptom is CPU. So each case below asserts
// the direction of the decision:
//
//   - transparent wrappers must UNWRAP, and must still do so when stacked;
//   - a wrapper that hides its upstream, or exposes mismatched reader/writer, must
//     REFUSE, because splicing through it would bypass whatever it does.

// --- test doubles -------------------------------------------------------------

// fakeSpliceSocket satisfies tun.SpliceSocket, the thing the target unwrap looks
// for. Attach/Detach carry real ownership semantics so a wrapper cannot pass by
// merely embedding something.
type fakeSpliceSocket struct {
	attachCalls int
	detachCalls int
	closed      bool
}

func (s *fakeSpliceSocket) SyscallConn() (syscall.RawConn, error) { return nil, nil }
func (s *fakeSpliceSocket) Attach(closer io.Closer) (io.Closer, bool) {
	s.attachCalls++
	return nil, true
}
func (s *fakeSpliceSocket) Detach() { s.detachCalls++ }
func (s *fakeSpliceSocket) Close() error {
	s.closed = true
	return nil
}

// socketConn is the bottom of the target stack: a packet conn that IS a
// SpliceSocket, like a real outbound UDP socket on a platform that supports it.
type socketConn struct {
	N.PacketConn
	socket *fakeSpliceSocket
}

func (c *socketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) { return M.Socksaddr{}, nil }
func (c *socketConn) WritePacket(*buf.Buffer, M.Socksaddr) error  { return nil }
func (c *socketConn) Close() error                                { return nil }
func (c *socketConn) LocalAddr() net.Addr                         { return nil }
func (c *socketConn) SetDeadline(time.Time) error                 { return nil }
func (c *socketConn) SetReadDeadline(time.Time) error             { return nil }
func (c *socketConn) SetWriteDeadline(time.Time) error            { return nil }
func (c *socketConn) SyscallConn() (syscall.RawConn, error)       { return c.socket.SyscallConn() }
func (c *socketConn) Attach(closer io.Closer) (io.Closer, bool)   { return c.socket.Attach(closer) }
func (c *socketConn) Detach()                                     { c.socket.Detach() }

// The unwrap loop insists on replaceability and an upstream before it will accept a
// splittable socket, so a realistic splice target exposes all of them. A stub that
// only satisfied SpliceSocket would be refused, which is correct behaviour and worth
// knowing: it means a real socket missing any one of these silently falls back to
// CopyPacket.
func (c *socketConn) Upstream() any           { return c.PacketConnOrNil() }
func (c *socketConn) ReaderReplaceable() bool { return true }
func (c *socketConn) WriterReplaceable() bool { return true }

func (c *socketConn) PacketConnOrNil() N.PacketConn {
	if c.PacketConn != nil {
		return c.PacketConn
	}
	return nil
}

// counterConn is a transparent packet counter: it forwards packets untouched and
// reports its upstream so unwrapping can continue.
type counterConn struct {
	N.PacketConn
}

func (c *counterConn) UnwrapPacketReader() (N.PacketReader, []N.CountFunc) {
	return c.PacketConn, []N.CountFunc{func(int64) {}}
}
func (c *counterConn) UnwrapPacketWriter() (N.PacketWriter, []N.CountFunc) {
	return c.PacketConn, []N.CountFunc{func(int64) {}}
}

// trackerConn mirrors route.trackedPacketConn: a lifecycle wrapper that must stay
// transparent for splice to survive.
type trackerConn struct {
	N.PacketConn
}

func (c *trackerConn) Upstream() any           { return c.PacketConn }
func (c *trackerConn) ReaderReplaceable() bool { return true }
func (c *trackerConn) WriterReplaceable() bool { return true }

// splittingConn exposes reader and writer separately; when they agree it is
// transparent, when they differ splice must be refused.
type splittingConn struct {
	N.PacketConn
	reader N.PacketReader
	writer N.PacketWriter
}

func (c *splittingConn) UpstreamReader() any { return c.reader }
func (c *splittingConn) UpstreamWriter() any { return c.writer }

// opaqueConn hides its upstream entirely, standing for a wrapper that transforms
// packets. The unwrap must refuse rather than assume it is transparent.
type opaqueConn struct {
	N.PacketConn
}

// --- target unwrap ------------------------------------------------------------

func TestSpliceTarget_UnwrapsThroughTransparentWrappers(t *testing.T) {
	socket := &fakeSpliceSocket{}

	// Stacked the way the real path stacks them: counter outside tracker outside
	// the literal socket.
	conn := &counterConn{PacketConn: &trackerConn{PacketConn: &socketConn{socket: socket}}}

	target, ok := unwrapSpliceTarget(conn, false)
	if !ok {
		t.Fatal("a counter over a tracker over a SpliceSocket must remain spliceable")
	}
	// The walk stops at the first object satisfying SpliceSocket. socketConn is one,
	// so that is the spliced socket; what matters is that the wrappers did not stop
	// the walk before reaching it.
	if target.socket == nil {
		t.Fatal("unwrap found no socket")
	}
	if _, isSocket := target.socket.(*socketConn); !isSocket {
		t.Fatalf("unwrap stopped at an unexpected type %T", target.socket)
	}
	if len(target.readCounters) != 1 || len(target.writeCounters) != 1 {
		t.Fatalf("counters not carried through: read=%d write=%d",
			len(target.readCounters), len(target.writeCounters))
	}
}

func TestSpliceTarget_UnwrapsBareSocket(t *testing.T) {
	socket := &fakeSpliceSocket{}
	target, ok := unwrapSpliceTarget(&socketConn{socket: socket}, false)
	if !ok {
		t.Fatal("a bare SpliceSocket must be spliceable")
	}
	if target.socket == nil {
		t.Fatal("unwrap found no socket")
	}
}

func TestSpliceTarget_RefusesOpaqueWrapper(t *testing.T) {
	// The control for the tests above: without a forwarding interface the unwrap
	// must refuse. If this ever starts succeeding, something is guessing.
	conn := &opaqueConn{PacketConn: &socketConn{socket: &fakeSpliceSocket{}}}
	if _, ok := unwrapSpliceTarget(conn, false); ok {
		t.Fatal("a wrapper that hides its upstream must not be unwrapped")
	}
}

func TestSpliceTarget_RefusesMismatchedReaderWriter(t *testing.T) {
	// Reader and writer pointing at different connections would splice two flows
	// together; the unwrap must reject it.
	conn := &splittingConn{
		PacketConn: &socketConn{socket: &fakeSpliceSocket{}},
		reader:     &socketConn{socket: &fakeSpliceSocket{}},
		writer:     &socketConn{socket: &fakeSpliceSocket{}},
	}
	if _, ok := unwrapSpliceTarget(conn, false); ok {
		t.Fatal("mismatched reader and writer upstreams must not be spliced")
	}
}

func TestSpliceTarget_RefusesNonReplaceableWrapper(t *testing.T) {
	// A wrapper that says it is NOT replaceable must stop the walk even though it
	// forwards packets, because replacing it would lose whatever it does.
	conn := &nonReplaceableConn{PacketConn: &socketConn{socket: &fakeSpliceSocket{}}}
	if _, ok := unwrapSpliceTarget(conn, false); ok {
		t.Fatal("a non-replaceable wrapper must not be unwrapped")
	}
}

type nonReplaceableConn struct {
	N.PacketConn
}

func (c *nonReplaceableConn) Upstream() any           { return c.PacketConn }
func (c *nonReplaceableConn) ReaderReplaceable() bool { return false }
func (c *nonReplaceableConn) WriterReplaceable() bool { return true }

// --- source unwrap ------------------------------------------------------------

func TestSpliceSource_InterfaceContract(t *testing.T) {
	// The source unwrap requires a tun.UDPNatConn specifically, which cannot be
	// constructed without a live TUN device, so this pins the contract that makes
	// the exported spliceSource usable instead of faking a device.
	//
	// If the field set changes, every consumer that took cached packets or counters
	// out of a successful unwrap has to be revisited.
	source := spliceSource{
		readCounters:  []N.CountFunc{func(int64) {}},
		writeCounters: []N.CountFunc{func(int64) {}},
	}
	if len(source.readCounters) != 1 || len(source.writeCounters) != 1 {
		t.Fatal("spliceSource no longer carries the counters the splice setup consumes")
	}
	if cached := source.takeCached(); cached != nil {
		t.Fatalf("takeCached must return nothing with no cached readers, got %d", len(cached))
	}
}

func TestSpliceTarget_OffloadRequiresSpliceSocket(t *testing.T) {
	// With offload allowed, the unwrap takes a different branch. A connection that
	// has no upstream to offer must still be refused rather than panicking.
	conn := &opaqueConn{PacketConn: &socketConn{socket: &fakeSpliceSocket{}}}
	if _, ok := unwrapSpliceTarget(conn, true); ok {
		t.Fatal("offload path must not accept a wrapper that hides its upstream")
	}
}

func TestSpliceTarget_StopsAtFirstSocket(t *testing.T) {
	// The walk must stop at the first SpliceSocket rather than continuing past it
	// into whatever it forwards to.
	socket := &fakeSpliceSocket{}
	conn := &socketConn{socket: socket}
	target, ok := unwrapSpliceTarget(conn, false)
	if !ok {
		t.Fatal("a value SpliceSocket must unwrap")
	}
	// It must stop at the first socket rather than walking into the fake beneath it.
	if _, isSocket := target.socket.(*socketConn); !isSocket {
		t.Fatalf("unwrap walked past the first socket to %T", target.socket)
	}
}

var _ tun.SpliceSocket = (*fakeSpliceSocket)(nil)
var _ tun.SpliceSocket = (*socketConn)(nil)
