package tun

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"

	"github.com/stretchr/testify/require"
)

// Tests for the ACTIVATION window of StartStatePostStart.
//
// # The window
//
// StartStateStart acquires the tun interface and the stack and hands both releases to the Scope at
// the acquisition. StartStatePostStart then activates them: stack.Start, and If.Start, which is
// where the platform routing table is programmed (NativeTun.Start -> setRoutes).
//
// Scope.Close does not wait for a Start that is already running. A drain that happens while that
// activation is in flight runs those two releases and returns, and the activation then runs against
// objects that are already closed. The stack refuses a restart on its own, but the interface has no
// such check: setRoutes adds routes unconditionally, and the cleanup that would have removed them
// has already run - so the entries outlive the Scope, the Box and the whole teardown path.
//
// # The handoff these pin
//
// The release is registered through Inbound.stackStartup / Inbound.interfaceStartup. Neither side
// waits for the other: the Scope's cleanup releases the resource when no activation is in flight,
// and when one is it records the decision and leaves the release to that activation, which performs
// it as soon as the platform call returns. `once` keeps it exactly-once either way.
//
// The doubles are only doubles because a real interface cannot be opened here; every object whose
// ordering is asserted is production state (*Inbound, the gates and the real Scope).

// boundaryStack is a tun.Stack whose Start can be held at the moment StartStatePostStart is between
// the stack and the interface.
type boundaryStack struct {
	tun.Stack
	startEntered chan struct{}
	startRelease chan struct{}
	startCalls   atomic.Int32
	closeCalls   atomic.Int32
}

func (s *boundaryStack) Start() error {
	s.startCalls.Add(1)
	if s.startEntered != nil {
		close(s.startEntered)
	}
	if s.startRelease != nil {
		<-s.startRelease
	}
	return nil
}

func (s *boundaryStack) Close() error {
	s.closeCalls.Add(1)
	return nil
}

func (s *boundaryStack) ResetNetwork() {}

// boundaryInterface stands in for the tun interface. Start is the call that programmes the platform
// routing table on the real object.
type boundaryInterface struct {
	tun.Tun
	startEntered chan struct{}
	startRelease chan struct{}
	startCalls   atomic.Int32
	closeCalls   atomic.Int32
}

func (i *boundaryInterface) Start() error {
	i.startCalls.Add(1)
	if i.startEntered != nil {
		close(i.startEntered)
	}
	if i.startRelease != nil {
		<-i.startRelease
	}
	return nil
}

func (i *boundaryInterface) Close() error {
	i.closeCalls.Add(1)
	return nil
}

// newBoundaryInbound wires the two gates exactly as StartStateStart does, for a PostStart that runs
// against the same Scope.
func newBoundaryInbound(scope *adapter.Scope, iface tun.Tun, stack tun.Stack) *Inbound {
	inbound := &Inbound{
		tag:      "tun-close-boundary",
		logger:   log.NewNOPFactory().Logger(),
		tunIf:    iface,
		tunStack: stack,
	}
	inbound.interfaceStartup.acquire(iface.Close)
	inbound.stackStartup.acquire(stack.Close)
	scope.Add(inbound.interfaceStartup.releaseByScope)
	scope.Add(inbound.stackStartup.releaseByScope)
	return inbound
}

// TestPostStartRefusesInterfaceActivationAfterScopeClose is the ordering the gate exists for.
//
// PostStart is held inside stack.Start until Scope.Close has returned, so the Scope's release has
// certainly been decided by the time the interface would be activated. The stack is released by the
// activation that was in flight; the interface is refused, so no route is ever added.
func TestPostStartRefusesInterfaceActivationAfterScopeClose(t *testing.T) {
	stack := &boundaryStack{
		startEntered: make(chan struct{}),
		startRelease: make(chan struct{}),
	}
	iface := &boundaryInterface{}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	inbound := newBoundaryInbound(scope, iface, stack)

	postStartDone := make(chan error, 1)
	go func() { postStartDone <- inbound.Start(adapter.StartStatePostStart, scope) }()

	<-stack.startEntered
	require.NoError(t, scope.Close(),
		"the drain must not wait for the activation that is in flight")
	require.Equal(t, int32(1), iface.closeCalls.Load(),
		"the interface was not being activated, so the Scope's cleanup must have released it")
	require.Equal(t, int32(0), stack.closeCalls.Load(),
		"the stack's release belongs to the activation that was in flight, not to the drain")

	// Only now may the in-flight activation finish.
	close(stack.startRelease)
	require.Error(t, <-postStartDone,
		"PostStart must not report success for objects the Scope released while it was starting")

	require.Equal(t, int32(1), stack.closeCalls.Load(),
		"the in-flight activation must have released the stack exactly once after its start returned")
	require.Equal(t, int32(0), iface.startCalls.Load(),
		"the interface must not be activated after the Scope claimed its release: If.Start programmes "+
			"the platform routing table and the cleanup that would remove those entries has already run")
	require.Equal(t, int32(1), iface.closeCalls.Load(),
		"the interface must not be released twice")
}

// TestPostStartReleasesInterfaceItActivatedDuringClose is the other half of the handoff.
//
// Here the interface's own activation is the one in flight when the Scope closes. The gate cannot
// refuse it - it has already started - so it must own the release: the routes that Start adds are
// removed again, exactly once, instead of being left behind by a cleanup that has already run.
func TestPostStartReleasesInterfaceItActivatedDuringClose(t *testing.T) {
	stack := &boundaryStack{}
	iface := &boundaryInterface{
		startEntered: make(chan struct{}),
		startRelease: make(chan struct{}),
	}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	inbound := newBoundaryInbound(scope, iface, stack)

	postStartDone := make(chan error, 1)
	go func() { postStartDone <- inbound.Start(adapter.StartStatePostStart, scope) }()

	<-iface.startEntered
	require.Equal(t, int32(1), stack.startCalls.Load(), "the stack is started first and is already up")
	require.NoError(t, scope.Close())
	require.Equal(t, int32(1), stack.closeCalls.Load(),
		"the stack was not being activated, so the Scope released it")
	require.Equal(t, int32(0), iface.closeCalls.Load(),
		"the interface is being activated: releasing the fd under it is the drain's job only when no "+
			"activation is in flight")

	close(iface.startRelease)
	require.Error(t, <-postStartDone,
		"PostStart must not report success: the Scope closed while it was activating the interface")
	require.Equal(t, int32(1), iface.closeCalls.Load(),
		"the activation must release the interface it just programmed, exactly once")
}

// TestPostStartActivatesBothWhileTheScopeIsOpen keeps the gate honest: the refusal above must be
// about the Scope's teardown, not about the activation being broken.
func TestPostStartActivatesBothWhileTheScopeIsOpen(t *testing.T) {
	stack := &boundaryStack{}
	iface := &boundaryInterface{}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	inbound := newBoundaryInbound(scope, iface, stack)

	require.NoError(t, inbound.Start(adapter.StartStatePostStart, scope))
	require.Equal(t, int32(1), stack.startCalls.Load(), "the stack must be started")
	require.Equal(t, int32(1), iface.startCalls.Load(), "the interface must be started")
	require.Equal(t, int32(0), iface.closeCalls.Load(), "nothing may be released while the Scope is open")

	require.NoError(t, scope.Close())
	require.Equal(t, int32(1), stack.closeCalls.Load(), "the Scope must release the stack once")
	require.Equal(t, int32(1), iface.closeCalls.Load(), "the Scope must release the interface once")

	// The explicit close path (adapter/inbound/manager.go's duplicate-tag loser) must not release
	// either object a second time.
	require.NoError(t, inbound.Close())
	require.Equal(t, int32(1), stack.closeCalls.Load())
	require.Equal(t, int32(1), iface.closeCalls.Load())
}
