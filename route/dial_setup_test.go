package route

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// In-flight dial ownership across a network transition.
//
// # Why the connection list is not enough
//
// Every other reclaim test drives connections that already exist. This file drives the state the
// list cannot represent: NewConnection has started a dial, the dial has emitted its SYN, and the
// peer has not answered. Nothing has been tracked yet - common/dialer's TrackConn runs inside the
// dial - so Reclaim's scan sees an empty manager, and before this fix the dial ran until its own
// connect_timeout (or forever, for an outbound configured without one).
//
// # What these tests pin
//
// The setup context owns setup only:
//
//	a transition cancels a dial owned by a stale generation;
//	a transition spares a dial started after it;
//	a transition never touches a flow that is already established;
//	a caller cancel stays a caller cancel, and is not a path failure;
//	Close cancels what is in flight and nothing can be resurrected after it.
//
// The dialer below blocks on its context exactly as a blackholed connect does, so the only thing
// that can end the dial is the context under test.

// blackholeTestDialer records the setup context it was handed and blocks until that context ends.
type blackholeTestDialer struct {
	started chan context.Context
	access  sync.Mutex
	err     error
}

func newBlackholeTestDialer() *blackholeTestDialer {
	// Buffered so a dial can publish its context without needing a reader at that instant.
	return &blackholeTestDialer{started: make(chan context.Context, 16)}
}

func (d *blackholeTestDialer) wait(ctx context.Context) error {
	select {
	case d.started <- ctx:
	default:
	}
	<-ctx.Done()
	d.access.Lock()
	d.err = ctx.Err()
	d.access.Unlock()
	return ctx.Err()
}

func (d *blackholeTestDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return nil, d.wait(ctx)
}

func (d *blackholeTestDialer) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return nil, d.wait(ctx)
}

// waitForDial returns the setup context of the next dial to start, or fails the test.
func (d *blackholeTestDialer) waitForDial(t *testing.T) context.Context {
	t.Helper()
	select {
	case ctx := <-d.started:
		return ctx
	case <-time.After(2 * time.Second):
		t.Fatal("the dial never started")
		return nil
	}
}

func (d *blackholeTestDialer) dialError() error {
	d.access.Lock()
	defer d.access.Unlock()
	return d.err
}

// singleShotDialer hands NewConnection a remote pipe end once, and blocks forever afterwards.
type singleShotDialer struct {
	remote net.Conn
	once   sync.Once
	// ctx is the setup context the successful dial was handed, so a test can assert that its
	// release really did cancel setup authority.
	ctx context.Context
}

func (d *singleShotDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.once.Do(func() {
		d.ctx = ctx
	})
	return d.remote, nil
}

func (d *singleShotDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not a packet dialer")
}

// transitionManager builds the production manager with a non-nil logger, because the dial-failure
// path logs and a nil logger would panic before any assertion runs.
func transitionManager(t *testing.T) *ConnectionManager {
	t.Helper()
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = manager.Close() })
	return manager
}

// startBlackholedDial runs one NewConnection in the background and returns the setup context the
// dial is blocked under, plus a channel that closes when NewConnection returns.
func startBlackholedDial(t *testing.T, manager *ConnectionManager, dialer *blackholeTestDialer, destination M.Socksaddr) (context.Context, <-chan struct{}) {
	t.Helper()
	inbound, inboundPeer := net.Pipe()
	t.Cleanup(func() { _ = inboundPeer.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.NewConnection(context.Background(), dialer, inbound, adapter.InboundContext{Destination: destination}, nil)
	}()
	return dialer.waitForDial(t), done
}

// TestNetworkTransitionCancelsAnInFlightBlackholedDial is the regression this file exists for.
//
// RED on the pre-fix base: Reclaim sees an empty connection list, the dial is never cancelled, and
// the wait below times out. GREEN with the setup gate: the transition cancels the setup context of
// the stale generation and the dial returns context.Canceled.
func TestNetworkTransitionCancelsAnInFlightBlackholedDial(t *testing.T) {
	manager := transitionManager(t)
	dialer := newBlackholeTestDialer()

	setupContext, done := startBlackholedDial(t, manager, dialer, M.ParseSocksaddrHostPort("example.com", 443))
	require.NoError(t, setupContext.Err(), "the dial must be in flight before the transition")

	manager.Reclaim(ReclaimNetworkTransition)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a network transition did not cancel the in-flight blackholed dial")
	}
	require.ErrorIs(t, dialer.dialError(), context.Canceled,
		"the cancelled setup must surface as a caller-style cancellation, not as a timeout or a path error")
	require.Error(t, setupContext.Err(), "the setup context itself must be released")
}

// TestNetworkTransitionSparesADialStartedAfterIt is the other side of the generation comparison.
//
// A transition cancels what belongs to the generation being left, not what is dialled on the
// network that replaced it. Without the per-generation boundary, the second dial below would be
// cancelled by the first transition's sweep - which on a device is every reconnect the transition
// itself triggers.
func TestNetworkTransitionSparesADialStartedAfterIt(t *testing.T) {
	manager := transitionManager(t)
	dialer := newBlackholeTestDialer()

	staleContext, staleDone := startBlackholedDial(t, manager, dialer, M.ParseSocksaddrHostPort("stale.example", 443))
	manager.Reclaim(ReclaimNetworkTransition)
	select {
	case <-staleDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the pre-transition dial was not cancelled")
	}
	require.ErrorIs(t, staleContext.Err(), context.Canceled)

	freshContext, freshDone := startBlackholedDial(t, manager, dialer, M.ParseSocksaddrHostPort("fresh.example", 443))
	// Give a wrongly-scoped cancellation time to land.
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, freshContext.Err(),
		"a dial that began after the transition belongs to the new network and must not be cancelled by it")
	select {
	case <-freshDone:
		t.Fatal("the post-transition dial was cancelled by the transition it started after")
	default:
	}

	// And a SECOND transition must cancel it: that is what makes the boundary a generation rather
	// than a one-shot release.
	manager.Reclaim(ReclaimNetworkTransition)
	select {
	case <-freshDone:
	case <-time.After(2 * time.Second):
		t.Fatal("a later transition did not cancel a dial that had become stale")
	}
	require.ErrorIs(t, freshContext.Err(), context.Canceled)
}

// TestNetworkTransitionDoesNotKillAnEstablishedFlow pins the ownership transfer.
//
// The dial succeeds, so the setup context's authority is over. The test asserts both halves: the
// setup context is released at establishment (so a long-lived caller context does not accumulate
// dead child registrations), and the flow still moves bytes after a transition arrives. A
// transition that reached an established flow would be the retroactive kill this rule forbids.
func TestNetworkTransitionDoesNotKillAnEstablishedFlow(t *testing.T) {
	manager := transitionManager(t)
	inbound, inboundPeer := net.Pipe()
	remote, remotePeer := net.Pipe()
	t.Cleanup(func() {
		_ = inboundPeer.Close()
		_ = remotePeer.Close()
	})
	dialer := &singleShotDialer{remote: remote}

	established := make(chan struct{})
	go func() {
		defer close(established)
		manager.NewConnection(context.Background(), dialer, inbound, adapter.InboundContext{Destination: M.ParseSocksaddrHostPort("example.com", 443)}, nil)
	}()
	select {
	case <-established:
	case <-time.After(2 * time.Second):
		t.Fatal("the dial did not establish")
	}

	// The setup context was released: the caller's own context, not the setup's, governs the flow.
	require.NotNil(t, dialer.ctx)
	require.Error(t, dialer.ctx.Err(),
		"establishment must release the setup context; leaving it live would leak a child registration per dial")

	// A transition after establishment must not disturb the flow.
	manager.Reclaim(ReclaimNetworkTransition)

	payload := []byte("still moving after the transition")
	writeReturned := make(chan error, 1)
	go func() {
		_, err := inboundPeer.Write(payload)
		writeReturned <- err
	}()
	buffer := make([]byte, len(payload))
	require.NoError(t, remotePeer.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err := remotePeer.Read(buffer)
	require.NoError(t, err, "an established flow must survive a network transition")
	require.Equal(t, payload, buffer)
	require.NoError(t, <-writeReturned)
}

// TestTransitionCancelledDialIsNotAPathFailure is the classification requirement.
//
// This fork distinguishes a caller cancellation from a path failure on purpose: a withdrawal must
// not consume a failover alternate and must not demote a member in the load balance ledger. A
// transition's cancellation travels the same context path as a caller's, so it must land on the
// same side of both classifiers. Asserting only errors.Is would not catch a transport that rewrote
// the cause into something the classifiers read as a dead path, so the classifiers themselves are
// exercised.
func TestTransitionCancelledDialIsNotAPathFailure(t *testing.T) {
	manager := transitionManager(t)
	dialer := newBlackholeTestDialer()

	_, done := startBlackholedDial(t, manager, dialer, M.ParseSocksaddrHostPort("example.com", 443))
	manager.Reclaim(ReclaimNetworkTransition)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the dial was not cancelled")
	}

	err := dialer.dialError()
	require.ErrorIs(t, err, context.Canceled)
	member := &namedOutbound{tag: "member", typeName: "socks"}
	require.False(t, group.RetryThisFlow(err),
		"a transition cancellation is not a reason to spend the flow's alternate")
	require.False(t, group.PenalizeMemberGlobally(member, err),
		"a transition cancellation says nothing about the member's own first hop")
}

// TestCallerCancellationStillCancelsTheDialAndNothingElse keeps the caller's authority unchanged.
//
// The setup context is derived from the caller's, so cancelling the caller must cancel the dial
// exactly as it did before the gate existed - and the dial's failure must still be the caller's
// cancellation, not a path verdict.
func TestCallerCancellationStillCancelsTheDialAndNothingElse(t *testing.T) {
	manager := transitionManager(t)
	dialer := newBlackholeTestDialer()

	callerContext, cancelCaller := context.WithCancel(context.Background())
	inbound, inboundPeer := net.Pipe()
	t.Cleanup(func() { _ = inboundPeer.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.NewConnection(callerContext, dialer, inbound, adapter.InboundContext{Destination: M.ParseSocksaddrHostPort("example.com", 443)}, nil)
	}()
	setupContext := dialer.waitForDial(t)

	cancelCaller()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling the caller did not cancel the dial")
	}
	require.ErrorIs(t, setupContext.Err(), context.Canceled)
	require.ErrorIs(t, dialer.dialError(), context.Canceled)
	member := &namedOutbound{tag: "member", typeName: "socks"}
	require.False(t, group.RetryThisFlow(dialer.dialError()))
	require.False(t, group.PenalizeMemberGlobally(member, dialer.dialError()))
}

// TestCloseCancelsInFlightDialsAndPreventsResurrection pins the teardown ordering.
//
// Close must reach a dial the connection list cannot see, and a dial begun after Close must not be
// able to establish: a connection installed after the manager was torn down would outlive the
// lifecycle that owns it.
func TestCloseCancelsInFlightDialsAndPreventsResurrection(t *testing.T) {
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	dialer := newBlackholeTestDialer()

	setupContext, done := startBlackholedDial(t, manager, dialer, M.ParseSocksaddrHostPort("example.com", 443))
	require.NoError(t, manager.Close())
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel the in-flight dial")
	}
	require.ErrorIs(t, setupContext.Err(), context.Canceled)

	// A late dial: the setup it is handed is already dead, so the dial returns at once rather than
	// establishing on a closed manager.
	lateDialer := newBlackholeTestDialer()
	lateSetup, lateDone := startBlackholedDial(t, manager, lateDialer, M.ParseSocksaddrHostPort("late.example", 443))
	select {
	case <-lateDone:
	case <-time.After(2 * time.Second):
		t.Fatal("a dial started after Close was allowed to establish")
	}
	require.ErrorIs(t, lateSetup.Err(), context.Canceled)
}

// TestRepeatedTransitionsWithDialsInFlightLeakNothing is the stress assertion.
//
// One transition cancelling one dial proves the mechanism. A hundred transitions each cancelling a
// dial that was genuinely in flight is what proves there is no map entry, goroutine or context
// registration left behind per transition - so the count has to come back to the baseline instead
// of growing by one per round.
func TestRepeatedTransitionsWithDialsInFlightLeakNothing(t *testing.T) {
	baseline := settleTestGoroutines()
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	dialer := newBlackholeTestDialer()

	const rounds = 100
	for round := range rounds {
		setupContext, done := startBlackholedDial(t, manager, dialer, M.ParseSocksaddrHostPort("example.com", 443))
		require.NoError(t, setupContext.Err(), "round %d: the dial must be in flight", round)
		manager.Reclaim(ReclaimNetworkTransition)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("round %d: the transition did not cancel the in-flight dial", round)
		}
		require.ErrorIs(t, setupContext.Err(), context.Canceled)
	}

	require.NoError(t, manager.Close())

	deadline := time.Now().Add(5 * time.Second)
	for {
		current := runtime.NumGoroutine()
		if current <= baseline {
			t.Logf("OBSERVED: goroutines %d before and %d after %d transitions with a dial in flight",
				baseline, current, rounds)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines did not return to the baseline of %d (now %d) after %d transitions",
				baseline, current, rounds)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// settleTestGoroutines waits until the process goroutine count stops falling, so the baseline is
// not taken while a previous test's copy loops are still winding down.
func settleTestGoroutines() int {
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

// namedOutbound is the minimum adapter.Outbound the load balance classifiers read: a tag and a
// kind. It is deliberately NOT direct or block, which is the case where a global penalty is
// possible at all.
type namedOutbound struct {
	adapter.Outbound
	tag      string
	typeName string
}

func (o *namedOutbound) Type() string           { return o.typeName }
func (o *namedOutbound) Tag() string            { return o.tag }
func (o *namedOutbound) Network() []string      { return []string{N.NetworkTCP} }
func (o *namedOutbound) Dependencies() []string { return nil }
func (o *namedOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("not dialled")
}
func (o *namedOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not dialled")
}
