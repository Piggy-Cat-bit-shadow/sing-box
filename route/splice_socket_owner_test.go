package route

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// THE SOCKET-HANDOVER CONTRACT THE GO TUN STACK DEPENDS ON.
//
// # Why this is a fault-injection test and not an interface check
//
// sing-tun's Go stack does not merely read and write the connection it was handed. When a flow looks
// like a plain proxied stream it asks the connection to hand its file descriptor over:
//
//	original, attached := owner.Attach(splice)
//	if !attached { return false }
//	socket, err := goSpliceSocket(owner)
//	if err != nil { owner.Detach(); ... return false }
//
// and later, whenever the splice is released, `owner.Detach()`. The bytes then move in the kernel
// between two descriptors and never pass through sing-box again.
//
// That makes `socketOwner` the one place where the new default stack and this fork's connection
// lifecycle meet, and every failure mode in it is a real one:
//
//   - if Attach succeeds on an already-closed connection, the stack resurrects a socket that is
//     being torn down, and the descriptor it duplicates can be handed to an unrelated flow;
//   - if Close while attached closes the descriptor AND the release path closes it again, the
//     process closes a descriptor it may no longer own - the classic double close that corrupts an
//     unrelated connection;
//   - if a failed Attach path leaves the original unclosed, the flow leaks a descriptor on exactly
//     the error path nobody exercises by hand.
//
// The invariant asserted below is therefore "the original descriptor is closed EXACTLY once, on
// every sequence sing-tun actually performs", not "Close was called". Those differ precisely on the
// paths that hurt.

// countingCloser records how many times it was closed. A double close is the failure being hunted,
// so the counter is the assertion rather than a boolean.
type countingCloser struct {
	closed atomic.Int64
}

func (c *countingCloser) Close() error {
	c.closed.Add(1)
	return nil
}

func (c *countingCloser) closeCount() int64 { return c.closed.Load() }

// TestSocketOwnerAttachHandsTheOriginalOverExactlyOnce is the happy path, and it pins the refusal
// that makes the handover safe: a second Attach while one is outstanding.
func TestSocketOwnerAttachHandsTheOriginalOverExactlyOnce(t *testing.T) {
	original := &countingCloser{}
	owner := socketOwner{original: original}
	firstOwner := &countingCloser{}

	handed, attached := owner.Attach(firstOwner)
	require.True(t, attached)
	require.Same(t, original, handed,
		"Attach must hand the caller the pre-existing closer, because the stack's splice path has to "+
			"be able to close it itself when the platform duplicates the descriptor")

	handed, attached = owner.Attach(&countingCloser{})
	require.False(t, attached, "a second Attach while the stack already owns the socket must be refused")
	require.Nil(t, handed, "a refused Attach must not hand out a descriptor the caller would close")
	require.Zero(t, original.closeCount(), "a refused Attach must not close anything by itself")
}

// TestSocketOwnerAttachAfterCloseIsRefused closes the connection first and then offers it to the
// stack. The refusal is what stops a closing flow from being resurrected: if the stack could take
// it, the descriptor would be duplicated while the owner is tearing the connection down.
func TestSocketOwnerAttachAfterCloseIsRefused(t *testing.T) {
	original := &countingCloser{}
	owner := socketOwner{original: original}

	require.False(t, owner.close(), "close() with no owner reports that the caller must close the original")
	require.NoError(t, original.Close())
	require.EqualValues(t, 1, original.closeCount())

	lateOwner := &countingCloser{}
	handed, attached := owner.Attach(lateOwner)
	require.False(t, attached, "a closed socket must never be handed to the stack")
	require.Nil(t, handed)
	require.Zero(t, lateOwner.closeCount(),
		"the refused owner was never attached, so closing it here would close a socket sing-tun still "+
			"owns and may hand to something else")
}

// TestSocketOwnerCloseWhileAttachedClosesEachDescriptorOnce is the Close-vs-active-connection row of
// the fault matrix, on the migration's own seam.
//
// The sequence is the one sing-tun produces: the stack attached, the splice is live, and the
// connection is closed from sing-box's side. Close must delegate to the stack's splice owner (which
// is how the splice is stopped), must NOT close the original itself, and the release path's
// Detach() must then close the original exactly once. Two closes of the original here would be a
// double close of a live descriptor.
func TestSocketOwnerCloseWhileAttachedClosesEachDescriptorOnce(t *testing.T) {
	original := &countingCloser{}
	owner := socketOwner{original: original}
	spliceOwner := &countingCloser{}

	_, attached := owner.Attach(spliceOwner)
	require.True(t, attached)

	delegated := owner.close()
	require.True(t, delegated,
		"Close must report that it delegated, so trackedConn.Close does not close the original as well")
	require.EqualValues(t, 1, spliceOwner.closeCount(), "the live splice must be stopped by Close")
	require.Zero(t, original.closeCount(),
		"the original must not be closed while the stack's release path still owns the decision")

	// The release path: sing-tun calls Detach() when the splice is released. Because Close already
	// happened, Detach is what closes the original exactly once.
	wasClosed := owner.detach()
	require.True(t, wasClosed, "detach must report that Close already happened, so the fd is closed now")
	require.NoError(t, original.Close())
	require.EqualValues(t, 1, original.closeCount())
	require.EqualValues(t, 1, spliceOwner.closeCount(), "the splice owner must not be closed twice either")
}

// TestSocketOwnerFailedAttachPathLeavesNothingUnclosed is the error path that is easiest to get
// wrong and easiest to never exercise: the handover succeeded, then the stack could not use the
// socket and detached. The original must still be closed by the ordinary Close, exactly once.
func TestSocketOwnerFailedAttachPathLeavesNothingUnclosed(t *testing.T) {
	original := &countingCloser{}
	owner := socketOwner{original: original}
	spliceOwner := &countingCloser{}

	_, attached := owner.Attach(spliceOwner)
	require.True(t, attached)

	wasClosed := owner.detach()
	require.False(t, wasClosed,
		"nothing was closed yet, so detach must NOT close the original; the caller's normal Close will")
	require.Zero(t, original.closeCount())

	require.False(t, owner.close(), "with no outstanding owner, close reports that the caller closes the original")
	require.NoError(t, original.Close())
	require.EqualValues(t, 1, original.closeCount())
}

// TestTrackedConnHandsOverTheSameContractWhenOwnershipIsDelegated drives the real wrapper rather
// than socketOwner, because that is what the stack is actually given.
//
// The point of using the wrapper is the two things the unit test cannot see: the descriptor must
// survive the delegating Close, and the connection must leave the manager's tracking list so the
// drain and reclaim policies do not keep acting on a flow that no longer exists.
func TestTrackedConnHandsOverTheSameContractWhenOwnershipIsDelegated(t *testing.T) {
	manager := NewConnectionManager(nil)
	t.Cleanup(func() { _ = manager.Close() })

	raw := &countingConn{}
	tracked := manager.TrackConn(raw).(*trackedConn)
	require.Equal(t, 1, manager.Count(), "the fixture must actually be tracked")

	spliceOwner := &countingCloser{}
	handed, attached := tracked.Attach(spliceOwner)
	require.True(t, attached)
	require.NotNil(t, handed, "the wrapper must hand the stack something it can close")

	// The real teardown path, not socketOwner.close directly: trackedConn.Close is what both removes
	// the connection from the manager's list and decides who closes the descriptor.
	require.NoError(t, tracked.Close())
	require.EqualValues(t, 1, spliceOwner.closeCount(), "Close must delegate while the stack holds the socket")
	require.Zero(t, raw.closed.Load(),
		"the wrapped descriptor must stay open until the release path closes it; closing it here is the "+
			"double close this contract exists to prevent")
	require.Equal(t, 0, manager.Count(),
		"a closed connection must leave the tracking list immediately, or the reclaim policies keep "+
			"acting on a flow that no longer exists")

	tracked.Detach()
	require.EqualValues(t, 1, raw.closed.Load(),
		"the release path must close the original exactly once")
	require.EqualValues(t, 1, spliceOwner.closeCount())
}

// TestTrackedPacketConnHandsOverTheSameContract is the UDP half. The packet path has its own wrapper
// and its own Detach, and a datagram flow that is spliced must satisfy the identical exactly-once
// property - a leaked or double-closed UDP socket is worse than a TCP one because the descriptor may
// be immediately reused by the next bind.
func TestTrackedPacketConnHandsOverTheSameContract(t *testing.T) {
	manager := NewConnectionManager(nil)
	t.Cleanup(func() { _ = manager.Close() })

	raw := &fakePacketConn{}
	tracked := manager.TrackPacketConn(raw).(*trackedPacketConn)
	require.Equal(t, 1, manager.Count())

	spliceOwner := &countingCloser{}
	handed, attached := tracked.Attach(spliceOwner)
	require.True(t, attached)
	require.NotNil(t, handed)

	require.NoError(t, tracked.Close())
	require.EqualValues(t, 1, spliceOwner.closeCount(), "Close must delegate to the live splice owner")
	require.Zero(t, raw.closed.Load(), "the datagram socket must stay open until the release path closes it")
	require.Equal(t, 0, manager.Count())

	tracked.Detach()
	require.EqualValues(t, 1, raw.closed.Load(),
		"the release path must close the datagram socket exactly once")
}

// TestSocketOwnerRacingHandoverClosesEachDescriptorOnce runs the handover and the teardown against
// each other.
//
// The stack attaches from its own goroutine while sing-box can close the connection at any moment,
// so the interesting interleaving is not hypothetical. The property asserted is the one that has to
// hold for every interleaving: the splice owner is closed at most once and the original at most
// once. A refused Attach must also not have closed the owner it was handed, because the caller still
// owns that socket when the handover does not happen.
func TestSocketOwnerRacingHandoverClosesEachDescriptorOnce(t *testing.T) {
	const rounds = 200
	for round := 0; round < rounds; round++ {
		original := &countingCloser{}
		owner := socketOwner{original: original}
		spliceOwner := &countingCloser{}
		var refusedOwnerTouched atomic.Bool

		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			if _, attached := owner.Attach(spliceOwner); !attached && spliceOwner.closeCount() != 0 {
				refusedOwnerTouched.Store(true)
			}
		}()
		go func() { defer wg.Done(); owner.detach() }()
		go func() { defer wg.Done(); owner.close() }()
		wg.Wait()

		require.False(t, refusedOwnerTouched.Load(),
			"round %d: a refused Attach closed the socket the caller still owns", round)
		require.LessOrEqual(t, spliceOwner.closeCount(), int64(1),
			"round %d closed the splice owner more than once", round)
		require.LessOrEqual(t, original.closeCount(), int64(1),
			"round %d closed the original more than once", round)
	}
}

// TestSocketOwnerDoesNotReopenAClosedConnection is the no-resurrection row: after Close, the socket
// must stay unavailable for the rest of its life, no matter how many times the stack asks. A
// socketOwner that could be re-attached after Close would let a torn-down flow take traffic again.
func TestSocketOwnerDoesNotReopenAClosedConnection(t *testing.T) {
	original := &countingCloser{}
	owner := socketOwner{original: original}
	owner.close()

	for attempt := 0; attempt < 100; attempt++ {
		handed, attached := owner.Attach(&countingCloser{})
		require.False(t, attached, "attempt %d re-attached a closed socket", attempt)
		require.Nil(t, handed)
	}
	// Close after Close must never produce a second close of the original: with no outstanding
	// owner it always reports that the caller owns the close, which is the signal that keeps
	// trackedConn.Close from closing an already-closed descriptor.
	require.False(t, owner.close())
	require.Zero(t, original.closeCount())
}

// TestSocketOwnerKeepsItsStateConsistentUnderConcurrentProbes is a race-detector companion to the
// deterministic tests above: a plain -race run over the same transitions, so a lock that is dropped
// on one path shows up as a data race rather than as a rare production hang.
func TestSocketOwnerKeepsItsStateConsistentUnderConcurrentProbes(t *testing.T) {
	owner := socketOwner{original: &countingCloser{}}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); owner.Attach(&countingCloser{}) }()
		go func() { defer wg.Done(); owner.detach() }()
		go func() { defer wg.Done(); owner.close() }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the handover probes deadlocked; the socketOwner lock is held across a close")
	}
}

// countingConn is a net.Conn whose only meaningful behaviour is counting its closes.
type countingConn struct {
	closed atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error)         { return 0, io.EOF }
func (c *countingConn) Write(p []byte) (int, error)        { return 0, io.EOF }
func (c *countingConn) Close() error                       { c.closed.Add(1); return nil }
func (c *countingConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *countingConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *countingConn) SetDeadline(t time.Time) error      { return nil }
func (c *countingConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *countingConn) SetWriteDeadline(t time.Time) error { return nil }

// fakePacketConn is a net.PacketConn whose only meaningful behaviour is counting its closes.
type fakePacketConn struct {
	closed atomic.Int64
}

func (c *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, net.ErrClosed
}
func (c *fakePacketConn) Close() error                       { c.closed.Add(1); return nil }
func (c *fakePacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *fakePacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(t time.Time) error { return nil }

var (
	_ net.Conn       = (*countingConn)(nil)
	_ net.PacketConn = (*fakePacketConn)(nil)
)
