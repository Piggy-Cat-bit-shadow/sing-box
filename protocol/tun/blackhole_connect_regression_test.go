package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Blackhole TCP connect coverage for the in-process Go TUN stack.
//
// # Why this file exists at all
//
// A prior audit found the blackhole-connect failure mode had no test anywhere in this repository.
// The mode is: the device emits a TCP SYN, the stack accepts it as the local endpoint and hands the
// connection to the route layer, the route layer dials the far end, and the far end never answers.
// Nothing about that is exotic - it is what every "connected to Wi-Fi with no internet" session
// looks like - and every property that keeps it from becoming a leak is a property of the stack's
// lifecycle, not of any single outbound.
//
// # Why a packet harness and not a real interface
//
// tun.MemoryTun is the stack's own in-memory link: the stack negotiates it as an ordinary device and
// the test drives both directions by writing and observing raw IP packets. That makes the whole
// test hermetic - no utun, no route table, no network - while still exercising the real engine, the
// real TCP state machine and the real teardown path rather than a fake that agrees with whatever the
// test assumed. The alternative, a real tun device, would make the assertions depend on the host's
// routing and on privileges, and would be skipped exactly where the failure matters.
//
// # Contract under test
//
// The stack hands NewConnectionEx the stack's own context (stack_go_tcp_input.go). That is what
// makes a blackholed dial cancellable by the caller, and this file pins it: cancelling the context
// must terminate the half-open connection, Close must terminate it within a bounded time, and
// neither may leave a retransmission loop or a goroutine behind.

// blackholeSYN builds the IPv4 + TCP SYN the device side emits.
//
// The Go stack negotiates MemoryTun with checksum validation enabled, so both checksums are real.
// A test that skipped them would exercise the packet parser's rejection path, not the accept path.
func blackholeSYN(source netip.Addr, sourcePort uint16, destination netip.Addr, destinationPort uint16) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     source,
		DstAddr:     destination,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcp := header.TCP(packet[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    sourcePort,
		DstPort:    destinationPort,
		SeqNum:     1_000,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	tcp.SetChecksum(^tcp.CalculateChecksum(header.PseudoHeaderChecksum(
		header.TCPProtocolNumber, source.AsSlice(), destination.AsSlice(), uint16(header.TCPMinimumSize),
	)))
	return packet
}

// blackholeHandler models exactly what the route layer does with an accepted TUN connection: it
// takes the connection and does NOT complete the handshake, because the outbound dial it started
// has not answered. It records the connection and blocks in Read, so the test observes the
// stack-side effect of cancelling or closing rather than the route layer's own bookkeeping.
type blackholeHandler struct {
	// acceptCount is the number of TCP flows the stack handed over, which is how a test tells a
	// genuine new flow from a retransmission of one it already abandoned.
	acceptCount atomic.Int64
	access      sync.Mutex
	contexts    map[uint16]context.Context
	readErrs    map[uint16]error
}

func newBlackholeHandler() *blackholeHandler {
	return &blackholeHandler{
		contexts: make(map[uint16]context.Context),
		readErrs: make(map[uint16]error),
	}
}

func (h *blackholeHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) tun.FlowVerdict {
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

func (h *blackholeHandler) NewDNSPacket([]byte, M.Socksaddr, M.Socksaddr, N.PacketWriter) {}

func (h *blackholeHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	h.access.Lock()
	h.contexts[destination.Port] = ctx
	h.access.Unlock()
	h.acceptCount.Add(1)
	go func() {
		// Read blocks until the stack tears the connection down, whichever way that happens:
		// caller cancellation, a stack Close, or an error path inside the engine. That is the
		// observable that proves the half-open flow did not survive.
		buffer := make([]byte, 16)
		_, err := conn.Read(buffer)
		h.access.Lock()
		h.readErrs[destination.Port] = err
		h.access.Unlock()
	}()
}

func (h *blackholeHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}

func (h *blackholeHandler) contextFor(port uint16) (context.Context, bool) {
	h.access.Lock()
	defer h.access.Unlock()
	ctx, loaded := h.contexts[port]
	return ctx, loaded
}

func (h *blackholeHandler) readErrorFor(port uint16) (error, bool) {
	h.access.Lock()
	defer h.access.Unlock()
	err, loaded := h.readErrs[port]
	return err, loaded
}

// blackholeStack is the harness: a MemoryTun the stack believes is a device, the stack itself, and
// a frame counter for everything the stack tries to put back on the wire.
type blackholeStack struct {
	device   *tun.MemoryTun
	stack    tun.Stack
	handler  *blackholeHandler
	outbound atomic.Int64
}

func newBlackholeStack(t *testing.T, ctx context.Context) *blackholeStack {
	t.Helper()
	harness := &blackholeStack{handler: newBlackholeHandler()}
	harness.device = tun.NewMemoryTun(tun.MemoryTunOptions{
		MTU: 1500,
		Outbound: func(packets []*buf.Buffer) {
			harness.outbound.Add(int64(len(packets)))
			buf.ReleaseMulti(packets)
		},
	})
	stack, err := tun.NewStack("go", tun.StackOptions{
		Context: ctx,
		Tun:     harness.device,
		TunOptions: tun.Options{
			MTU:          1500,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/126")},
			Logger:       logger.NOP(),
		},
		Handler:     harness.handler,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Minute,
	})
	require.NoError(t, err)
	require.NoError(t, stack.Start())
	harness.stack = stack
	t.Cleanup(func() {
		_ = stack.Close()
		_ = harness.device.Close()
	})
	return harness
}

// emit writes one SYN from the device side and waits until the stack has handed the flow over, so
// the caller's next assertion never races the engine's accept path.
func (h *blackholeStack) emit(t *testing.T, sourcePort, destinationPort uint16) {
	t.Helper()
	packet := blackholeSYN(
		netip.MustParseAddr("198.18.0.2"),
		sourcePort,
		netip.MustParseAddr("1.1.1.1"),
		destinationPort,
	)
	written, err := h.device.WritePackets([][]byte{packet})
	require.NoError(t, err)
	require.Equal(t, 1, written)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, loaded := h.handler.contextFor(destinationPort); loaded {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the stack never handed the flow on port %d to the handler", destinationPort)
}

// waitForRead blocks until the handler's Read has returned for the given flow, or fails the test.
// Every blackhole assertion is ultimately "the connection this test is holding stopped being
// blocked", so the wait is shared and bounded rather than open-coded in each test.
func (h *blackholeStack) waitForRead(t *testing.T, port uint16, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err, loaded := h.handler.readErrorFor(port); loaded {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the blackholed connection on port %d was still open after %s", port, timeout)
	return nil
}

// waitForOutbound blocks until the stack has emitted at least min frames.
//
// The engine's transmit loop is woken by the packet ring, not by the write call, so a frame can
// legitimately appear a few milliseconds after WritePackets returns. Waiting for it keeps the
// assertions about frame counts from depending on that scheduling.
func (h *blackholeStack) waitForOutbound(t *testing.T, min int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.outbound.Load() >= min {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the stack emitted %d frame(s), expected at least %d", h.outbound.Load(), min)
}

// settleGoroutines waits until the process goroutine count stops falling and returns it, so a
// baseline is never taken while a previous test's stack is still winding down.
func settleGoroutines() int {
	previous := runtime.NumGoroutine()
	for range 40 {
		time.Sleep(25 * time.Millisecond)
		current := runtime.NumGoroutine()
		if current == previous {
			return current
		}
		previous = current
	}
	return previous
}

// TestBlackholeConnectCallerContextCancelsThePendingFlow pins the contract the route layer depends
// on: the context handed to NewConnectionEx is the caller's, and cancelling it terminates the
// half-open flow without the handler having to do anything.
//
// Without this, a blackholed dial could only be stopped by the dialer's own timeout, and a caller
// that had already given up would still be holding a connection, its buffers and its goroutine.
func TestBlackholeConnectCallerContextCancelsThePendingFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	harness := newBlackholeStack(t, ctx)

	harness.emit(t, 40000, 80)

	// The context the stack passed must be the caller's, or nothing below can work.
	handlerContext, loaded := harness.handler.contextFor(80)
	require.True(t, loaded)
	require.NoError(t, handlerContext.Err())
	require.Same(t, ctx, handlerContext)

	// A whole SYN-ACK is emitted before the route layer has decided anything: the stack is the
	// local endpoint, so the device sees a completed handshake even though the far end is silent.
	// That is expected and is exactly why the flow is dangerous if nothing cancels it.
	harness.waitForOutbound(t, 1)

	cancel()

	readErr := harness.waitForRead(t, 80, 2*time.Second)
	require.Error(t, readErr)
	require.True(t,
		errors.Is(readErr, context.Canceled) || errors.Is(readErr, net.ErrClosed),
		"the cancelled flow must surface cancellation or closure, got %v", readErr)
}

// TestBlackholeConnectCloseTerminatesThePendingFlowWithinADeadline pins that Box.Close - which
// reaches the stack through the TUN inbound's Close - actually terminates a blackholed connection
// and that it does so in bounded time. A Close that returned while the connection stayed open would
// keep the process alive after the user turned the tunnel off.
func TestBlackholeConnectCloseTerminatesThePendingFlowWithinADeadline(t *testing.T) {
	harness := newBlackholeStack(t, context.Background())

	// The device stays open on purpose: the assertion must be about the stack's teardown, not about
	// the harness closing the underlying link from under it.
	harness.emit(t, 40001, 443)

	if _, loaded := harness.handler.readErrorFor(443); loaded {
		t.Fatal("the connection ended before Close, so this test would prove nothing")
	}

	closeReturned := make(chan error, 1)
	go func() {
		closeReturned <- harness.stack.Close()
	}()
	select {
	case err := <-closeReturned:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return within its hard deadline")
	}

	readErr := harness.waitForRead(t, 443, 2*time.Second)
	require.Error(t, readErr, "Close must terminate the blackholed connection, not just the engine loop")

	// Close is idempotent; a second call must not block or report a spurious failure.
	require.NoError(t, harness.stack.Close())
}

// TestBlackholeConnectAbandonedFlowLeavesNoStackInitiatedRetry is the "hidden multi-minute retry"
// assertion.
//
// Once the caller has abandoned the flow, the stack must go quiet: no timer may keep emitting
// SYN-ACKs for a peer that is gone. The observation window is bounded and the frame counter is the
// only input, so a retry loop that this test cannot see would still have to be a retry loop that
// emits nothing - which is not a retry loop.
func TestBlackholeConnectAbandonedFlowLeavesNoStackInitiatedRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	harness := newBlackholeStack(t, ctx)

	harness.emit(t, 40002, 8080)
	// The stack's own SYN-ACK must have landed before the baseline, or "the stack went quiet" would
	// be measured against a count that had not risen yet.
	harness.waitForOutbound(t, 1)
	cancel()
	require.Error(t, harness.waitForRead(t, 8080, 2*time.Second))

	// Let the teardown's own frames (a FIN or RST) land before taking the baseline, so the test
	// measures the stack going quiet rather than the cancellation itself.
	time.Sleep(250 * time.Millisecond)
	settled := harness.outbound.Load()

	time.Sleep(750 * time.Millisecond)
	require.Equal(t, settled, harness.outbound.Load(),
		"the stack kept transmitting after the caller abandoned the flow")

	// A later SYN for the same flow is new client input rather than a stack retry: the client is
	// retrying a connection the route layer already gave up on, so the stack is allowed to hand it
	// over as a fresh flow. What must not happen is the stack producing frames with no client
	// input at all, which is what the quiet-window assertion above tests. This observation is
	// logged rather than asserted because either outcome is legitimate.
	baselineAccepts := harness.handler.acceptCount.Load()
	packet := blackholeSYN(
		netip.MustParseAddr("198.18.0.2"), 40002,
		netip.MustParseAddr("1.1.1.1"), 8080,
	)
	_, err := harness.device.WritePackets([][]byte{packet})
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)
	t.Logf("OBSERVED: a post-abandon retransmitted SYN moved the accept count by %d",
		harness.handler.acceptCount.Load()-baselineAccepts)
}

// TestBlackholeConnectNetworkTransitionKeepsServingNewFlows covers the transition half of the
// failure mode.
//
// WHAT IS ASSERTED: a network transition (the stack's ResetNetwork, which is what the TUN inbound's
// InterfaceUpdated calls) must not wedge the stack. A flow started after the transition is handed
// over normally.
//
// WHAT THIS TEST DOES NOT CLAIM, AND WHY: ResetNetwork does not abort a half-open TCP flow that the
// route layer is still dialling - measured directly, the stack re-emits that flow's SYN-ACK across
// the reset rather than closing it. The route layer's own transition path drains tracked
// connections, but a dial that has not completed yet is not tracked, so nothing cancels it: the
// dial runs to its configured connect_timeout, or, for an outbound configured without one, until
// the caller cancels or the tunnel closes. That is a real gap in the "a network transition can
// invalidate it" requirement and is reported rather than papered over with an assertion that the
// current behaviour happens to satisfy.
func TestBlackholeConnectNetworkTransitionKeepsServingNewFlows(t *testing.T) {
	harness := newBlackholeStack(t, context.Background())

	harness.emit(t, 40003, 9000)

	// The transition runs with the first flow still pending, which is the state that matters.
	harness.stack.ResetNetwork()

	harness.emit(t, 40004, 9001)
	require.EqualValues(t, 2, harness.handler.acceptCount.Load(),
		"a flow started after a network transition must still reach the route layer")

	// The pre-transition flow is still pending: this is the measured behaviour the comment above
	// records, asserted nowhere as a requirement.
	if err, loaded := harness.handler.readErrorFor(9000); loaded {
		t.Logf("OBSERVED: the pre-transition flow ended during the reset with %v", err)
	} else {
		t.Log("OBSERVED: the pre-transition blackholed flow survived ResetNetwork")
	}
}

// TestBlackholeConnectLeavesNoImmortalGoroutine is the counter-based assertion.
//
// Each accepted TUN flow spawns one goroutine inside the stack that runs the route layer, plus the
// handler's own reader. Cancellation has to unwind both. The test abandons several flows at once
// because a leak that is one goroutine per flow is invisible with one flow and obvious with eight.
func TestBlackholeConnectLeavesNoImmortalGoroutine(t *testing.T) {
	baseline := settleGoroutines()

	ctx, cancel := context.WithCancel(context.Background())
	harness := newBlackholeStack(t, ctx)

	const flows = 8
	for index := range flows {
		harness.emit(t, uint16(41000+index), uint16(10000+index))
	}
	require.EqualValues(t, flows, harness.handler.acceptCount.Load())
	require.Greater(t, runtime.NumGoroutine(), baseline,
		"the accepted flows must have added goroutines, or this test cannot detect a leak")

	cancel()
	for index := range flows {
		require.Error(t, harness.waitForRead(t, uint16(10000+index), 2*time.Second))
	}

	// Close the stack as well: the per-flow goroutines are the stack's to unwind, and a test that
	// only cancelled would miss a stack that kept its engine after every flow was gone.
	require.NoError(t, harness.stack.Close())
	require.NoError(t, harness.device.Close())

	// A hand-rolled poll rather than require.Eventually: testify's helper runs the condition on a
	// ticker, and those ticker goroutines would themselves move the number this test is measuring.
	deadline := time.Now().Add(3 * time.Second)
	for {
		current := runtime.NumGoroutine()
		if current <= baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines did not return to the baseline of %d (now %d): an abandoned blackhole flow leaked",
				baseline, runtime.NumGoroutine())
		}
		time.Sleep(25 * time.Millisecond)
	}
}
