package group

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for what a round abort does to the members it already started.
//
// # The defect these pin
//
// A round starts a batch and then walks the members recursively. Each member probe runs on its own
// goroutine, and the batch is joined only on the normal path:
//
//	testBatch.test(outbounds, ...)   // recursion; may panic
//	b.Wait()                          // never reached
//
// So a panic in the traversal - a nested group's All() or Selected(), a cycle, anything outside the
// per-member boundary - unwinds past the join while probes started earlier are still running. The
// round reports failure to its caller and then those probes finish and write health or display
// history, so evidence changes AFTER the round has said it failed.
//
// Confirming a round's failure is therefore not enough on its own. The round must also stop and join
// everything it started before it returns.

// gatedMeasurementOutbound blocks inside its probe until released, and counts history-relevant
// events, so "did work continue after the round returned" is observable rather than inferred.
type gatedMeasurementOutbound struct {
	adapter.Outbound
	tag string

	entered   chan struct{}
	release   chan struct{}
	dials     atomic.Int32
	completed atomic.Int32
}

func (o *gatedMeasurementOutbound) Type() string      { return "gated" }
func (o *gatedMeasurementOutbound) Tag() string       { return o.tag }
func (o *gatedMeasurementOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *gatedMeasurementOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dials.Add(1)
	select {
	case o.entered <- struct{}{}:
	default:
	}
	select {
	case <-o.release:
		o.completed.Add(1)
		return nil, net.ErrClosed
	case <-ctx.Done():
		// The round was cancelled, which is the correct outcome for an aborted round.
		return nil, ctx.Err()
	}
}

func (o *gatedMeasurementOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// TestRoundAbortCancelsAndJoinsStartedMembers is §15/§17/§21.
//
// A member is held mid-probe; the traversal then panics. The round must not return until that
// member's goroutine has stopped, and nothing may be written afterwards.
func TestRoundAbortCancelsAndJoinsStartedMembers(t *testing.T) {
	server := newRecordingServer(t)
	link := "http://127.0.0.1:" + portOf(t, server.address) + "/a"

	// A is measured and blocks; B panics during traversal.
	memberA := &gatedMeasurementOutbound{
		tag:     "member-a",
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	nested := &panickingGroup{tag: "nested-b"}
	nested.panics.Store(true)

	group, storage := newGroupFixture(t, link, memberA, nested)

	// The override runs the REAL round body rather than a stub, so the batch mechanics under test
	// are the production ones.
	roundDone := make(chan struct{})
	var roundErr error
	go func() {
		defer close(roundDone)
		_, roundErr = group.runHealthRound(group.ctx, true)
	}()

	// Wait until A is genuinely inside its probe.
	select {
	case <-memberA.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("member A never started probing")
	}

	// The traversal panic happens after A started. The round must now abort.
	select {
	case <-roundDone:
	case <-time.After(10 * time.Second):
		close(memberA.release)
		t.Fatal("the round never returned after the traversal panic")
	}

	require.Error(t, roundErr, "the aborted round reports an error")

	// The critical assertion: A must already be finished. Its goroutine must not still be running
	// after the round has told its caller it failed.
	require.EqualValues(t, 0, memberA.completed.Load(),
		"member A completed its probe AFTER the round returned. The round reported failure to its "+
			"caller and then let a member it had already started finish, so a probe continues to run "+
			"- and to write history - for a round that is over")

	healthAfterReturn := storage.LoadURLTestHistoryFor("member-a", group.scope)
	displayAfterReturn := storage.LoadURLTestHistory("member-a")

	// Release A. If its goroutine is still alive, this unblocks it and it writes history now.
	close(memberA.release)
	time.Sleep(200 * time.Millisecond)

	require.Equal(t, healthAfterReturn, storage.LoadURLTestHistoryFor("member-a", group.scope),
		"a late write changed health evidence after the round had returned")
	require.Equal(t, displayAfterReturn, storage.LoadURLTestHistory("member-a"),
		"a late write changed display history after the round had returned")
	require.EqualValues(t, 0, memberA.completed.Load(),
		"member A's probe completed only after its release, which means it was still running when "+
			"the round returned")
}

// TestRoundAbortDoesNotLeaveActiveGoroutines is the join statement on its own.
func TestRoundAbortDoesNotLeaveActiveGoroutines(t *testing.T) {
	link := "https://probe.example/generate_204"

	memberA := &gatedMeasurementOutbound{
		tag:     "member-a",
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	nested := &panickingGroup{tag: "nested-b"}
	nested.panics.Store(true)

	group, _ := newGroupFixture(t, link, memberA, nested)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = group.runHealthRound(group.ctx, true)
	}()

	select {
	case <-memberA.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("member A never started")
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		close(memberA.release)
		t.Fatal("the round never returned")
	}

	// Hand back the ability to finish, then confirm the probe honoured the cancellation instead.
	close(memberA.release)
	time.Sleep(100 * time.Millisecond)

	require.EqualValues(t, 0, memberA.completed.Load(),
		"an aborted round left a member probe running: the round's context must be cancelled and "+
			"the member joined before the round returns")
}

var _ = urltest.MeasurementScope{}
var _ = context.Background
