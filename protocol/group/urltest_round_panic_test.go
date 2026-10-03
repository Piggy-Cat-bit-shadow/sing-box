package group

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for panic containment across a whole health round.
//
// # The boundary that was missing
//
// A member's own probe is contained: a panic inside DialContext becomes that member's error, so one
// bad node cannot kill the process. But substantial work runs OUTSIDE that boundary and on a
// goroutine that recovers nothing:
//
//	batch traversal      nested.All(), Selected(), RealTag
//	post-processing      performUpdateCheck, history reads
//
// A panic in any of those reaches the runtime and terminates the whole process, because batch.Go
// runs its closure on a fresh goroutine with no recover. A configuration that describes a cycle, or
// a group whose selection logic misbehaves, is therefore enough to take sing-box down rather than
// failing one round.
//
// Three boundaries are needed and they are separate: member, round, worker.

// panickingGroup is an outbound group whose traversal panics.
type panickingGroup struct {
	adapter.Outbound
	tag string
	// panics, when set, makes All() panic. This is the traversal path.
	panics atomic.Bool
	// selectedPanics makes Selected() panic. This is the selection path.
	selectedPanics atomic.Bool
	child          adapter.Outbound
}

func (g *panickingGroup) Type() string           { return "panicking-group" }
func (g *panickingGroup) Tag() string            { return g.tag }
func (g *panickingGroup) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (g *panickingGroup) Dependencies() []string { return nil }

func (g *panickingGroup) All() []string {
	if g.panics.Load() {
		panic("injected panic in nested group All()")
	}
	if g.child == nil {
		return nil
	}
	return []string{g.child.Tag()}
}

func (g *panickingGroup) Selected(network string) adapter.Outbound {
	if g.selectedPanics.Load() {
		panic("injected panic in nested group Selected()")
	}
	return g.child
}

func (g *panickingGroup) AttachConnection(closer io.Closer) func() { return func() {} }

// TestNestedTraversalPanicDoesNotKillTheProcess is the release blocker (§12.1 round-level).
func TestNestedTraversalPanicDoesNotKillTheProcess(t *testing.T) {
	server := newRecordingServer(t)
	link := "http://127.0.0.1:" + portOf(t, server.address) + "/a"

	leaf := &observingOutbound{tag: "leaf"}
	nested := &panickingGroup{tag: "nested", child: leaf}
	nested.panics.Store(true)

	group, _ := newGroupFixture(t, link, nested, leaf)

	// The round must complete rather than terminating the process.
	done := make(chan struct{})
	go func() {
		defer close(done)
		group.CheckOutbounds(group.ctx, true)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the round never returned")
	}

	// The checking guard must be released so the group remains usable.
	require.False(t, group.checking.Load(),
		"a panic in nested traversal left the checking guard held, so no later round can run")
}

// TestRoundPanicRecoversAndNextRoundSucceeds is the recovery statement.
func TestRoundPanicRecoversAndNextRoundSucceeds(t *testing.T) {
	server := newRecordingServer(t)
	link := "http://127.0.0.1:" + portOf(t, server.address) + "/a"

	leaf := &observingOutbound{tag: "leaf"}
	nested := &panickingGroup{tag: "nested", child: leaf}
	nested.panics.Store(true)

	group, storage := newGroupFixture(t, link, nested, leaf)

	group.CheckOutbounds(group.ctx, true)

	// The fault is gone. The next round must measure normally.
	nested.panics.Store(false)

	require.Eventually(t, func() bool {
		group.CheckOutbounds(group.ctx, true)
		return storage.LoadURLTestHistoryFor("leaf", group.scope) != nil
	}, 10*time.Second, 50*time.Millisecond,
		"after a round-level panic the group must be able to measure again; a contained panic "+
			"that leaves the subsystem unusable has only moved the failure")

	require.False(t, group.checking.Load())
}

// TestSelectionPanicDoesNotKillTheProcess covers the Selected() path.
func TestSelectionPanicDoesNotKillTheProcess(t *testing.T) {
	server := newRecordingServer(t)
	link := "http://127.0.0.1:" + portOf(t, server.address) + "/a"

	leaf := &observingOutbound{tag: "leaf"}
	nested := &panickingGroup{tag: "nested", child: leaf}
	nested.selectedPanics.Store(true)

	group, _ := newGroupFixture(t, link, nested, leaf)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// RealTag walks Selected(), which is where this panic originates.
		group.CheckOutbounds(group.ctx, true)
		_ = RealTag(nested, N.NetworkTCP)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the round never returned")
	}
}

var _ = context.Background
var _ M.Socksaddr
var _ net.Conn
