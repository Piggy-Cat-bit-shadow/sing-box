package route

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for the UDPConnect capability reaching the InboundDetour path.
//
// # The gap these close
//
// routePacketConnection read the UDPConnectPacketConn capability near the END of the function,
// after the InboundDetour early return. A fixed-destination tunnel routed to a detour therefore
// reached the detour with metadata.UDPConnect unset, and took the unconnected UDP path despite
// declaring a fixed target.
//
// The read now happens FIRST, before anything can return early, so the capability is converted
// into metadata while the original connection is still visible.

// fixedTargetConn declares a fixed destination.
type fixedTargetConn struct{}

func (fixedTargetConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) { return M.Socksaddr{}, nil }
func (fixedTargetConn) WritePacket(*buf.Buffer, M.Socksaddr) error  { return nil }
func (fixedTargetConn) Close() error                                { return nil }
func (fixedTargetConn) LocalAddr() net.Addr                         { return nil }
func (fixedTargetConn) SetDeadline(time.Time) error                 { return nil }
func (fixedTargetConn) SetReadDeadline(time.Time) error             { return nil }
func (fixedTargetConn) SetWriteDeadline(time.Time) error            { return nil }

func (fixedTargetConn) IsUDPConnect() bool { return true }

// plainPacketConn is an ordinary per-datagram connection with no declaration.
type plainPacketConn struct{ fixedTargetConn }

func (plainPacketConn) IsUDPConnect() bool { return false }

// capturingInbound records the metadata it is handed as a detour target.
type capturingInbound struct {
	adapter.Inbound
	metadata adapter.InboundContext
	called   bool
}

func (i *capturingInbound) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	i.metadata = metadata
	i.called = true
}

func (i *capturingInbound) Type() string { return "capturing" }
func (i *capturingInbound) Tag() string  { return "detour" }

// stubInboundManager serves a single detour inbound by tag.
type stubInboundManager struct {
	target adapter.Inbound
}

func (m *stubInboundManager) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (m *stubInboundManager) Close() error                                               { return nil }
func (m *stubInboundManager) Inbounds() []adapter.Inbound                                { return nil }
func (m *stubInboundManager) Remove(tag string) error                                    { return nil }
func (m *stubInboundManager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	return nil
}

func (m *stubInboundManager) Get(tag string) (adapter.Inbound, bool) {
	if m.target != nil && tag == "detour" {
		return m.target, true
	}
	return nil, false
}

// detourRouter builds a Router whose detour target records what it receives.
func detourRouter(t *testing.T) (*Router, *capturingInbound) {
	t.Helper()
	target := &capturingInbound{}
	router := &Router{
		ctx:     context.Background(),
		logger:  log.NewNOPFactory().Logger(),
		inbound: &stubInboundManager{target: target},
	}
	return router, target
}

// TestUDPConnectCapabilityReachesTheDetour is the regression for the detour gap.
//
// A fixed-destination connection routed to a detour must arrive with UDPConnect set. Before the
// fix the early return happened first, so the detour saw UDPConnect == false.
func TestUDPConnectCapabilityReachesTheDetour(t *testing.T) {
	router, target := detourRouter(t)

	metadata := adapter.InboundContext{
		Inbound:       "tunnel",
		InboundDetour: "detour",
	}

	err := router.routePacketConnection(context.Background(), fixedTargetConn{}, metadata, nil)
	require.NoError(t, err)
	require.True(t, target.called, "the detour must have been reached")

	require.True(t, target.metadata.UDPConnect,
		"a fixed-destination connection must reach the detour with UDPConnect set; the "+
			"capability read must happen BEFORE the InboundDetour early return")
}

// TestUndeclaredConnectionReachesTheDetourUnconnected is the negative control.
func TestUndeclaredConnectionReachesTheDetourUnconnected(t *testing.T) {
	router, target := detourRouter(t)

	metadata := adapter.InboundContext{
		Inbound:       "tunnel",
		InboundDetour: "detour",
	}

	err := router.routePacketConnection(context.Background(), plainPacketConn{}, metadata, nil)
	require.NoError(t, err)
	require.True(t, target.called)

	require.False(t, target.metadata.UDPConnect,
		"a connection that does not declare a fixed destination must not be connected")
}

// TestUoTDynamicDestinationIsNotAutoConnectedOnTheDetourPath is the safety boundary.
//
// A UoT session carrying a destination on every datagram is explicitly NOT fixed-destination.
// Connecting it would pin the session to whichever address the first datagram used. The detour
// path used to skip this guard entirely along with the rest of the read, so checking it here is
// part of the fix rather than an extra.
func TestUoTDynamicDestinationIsNotAutoConnectedOnTheDetourPath(t *testing.T) {
	router, target := detourRouter(t)

	metadata := adapter.InboundContext{
		Inbound:                 "tunnel",
		InboundDetour:           "detour",
		UoTDatagramDestinations: true,
	}

	err := router.routePacketConnection(context.Background(), fixedTargetConn{}, metadata, nil)
	require.NoError(t, err)
	require.True(t, target.called)

	require.False(t, target.metadata.UDPConnect,
		"a per-datagram UoT session must not be auto-connected even when the connection "+
			"declares a fixed destination; its declared target does not describe the session")
}

// TestExplicitRuleSurvivesTheDetourPath confirms an upstream decision is not cleared.
//
// metadata.UDPConnect may already be true from configuration. The capability helper can only
// promote false to true, so a connection that does not declare a fixed destination must not
// undo the user's explicit setting.
func TestExplicitRuleSurvivesTheDetourPath(t *testing.T) {
	router, target := detourRouter(t)

	metadata := adapter.InboundContext{
		Inbound:       "tunnel",
		InboundDetour: "detour",
		UDPConnect:    true,
	}

	err := router.routePacketConnection(context.Background(), plainPacketConn{}, metadata, nil)
	require.NoError(t, err)
	require.True(t, target.called)

	require.True(t, target.metadata.UDPConnect,
		"an explicitly configured UDPConnect must survive even for a connection that does "+
			"not declare the capability")
}

var _ adapter.UDPInjectableInbound = (*capturingInbound)(nil)
