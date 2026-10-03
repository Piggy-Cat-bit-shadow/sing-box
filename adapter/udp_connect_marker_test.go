package adapter

import (
	"testing"

	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Contract tests for the fixed-destination UDP marker.
//
// # What the marker means, and what it must never mean
//
// UDPConnectPacketConn marks a packet connection whose destination is FIXED for the lifetime of the
// session, so the session may be promoted to a connected socket. Only a protocol layer that KNOWS
// the destination is fixed may set it: the router must never infer it from the connection's shape,
// from a current datagram's destination, or from the session's original destination.
//
// Inferring it would be wrong for an ordinary SOCKS UDP association, which carries a destination on
// every datagram and would be pinned to whichever address arrived first.

// markerConn implements the marker.
type markerConn struct {
	N.PacketConn
	fixed bool
}

func (c *markerConn) IsUDPConnect() bool { return c.fixed }

// plainPacketConn does NOT implement the marker.
type plainPacketConn struct {
	N.PacketConn
}

func (c *plainPacketConn) Close() error { return nil }

// TestMarkerRequiresAnExplicitDeclaration is the core contract.
func TestMarkerRequiresAnExplicitDeclaration(t *testing.T) {
	metadata := &InboundContext{}

	// A connection that does not implement the interface must leave the flag alone, however
	// ordinary it looks.
	ApplyUDPConnect(metadata, &plainPacketConn{})
	require.False(t, metadata.UDPConnect,
		"an ordinary packet connection must never be promoted to connected; only an explicit "+
			"declaration may do that")

	// An explicit declaration is honoured.
	metadata = &InboundContext{}
	ApplyUDPConnect(metadata, &markerConn{fixed: true})
	require.True(t, metadata.UDPConnect,
		"a connection that declares a fixed destination must be promoted")
}

// TestUoTDynamicDestinationsAreNeverPromoted is the guard that matters most.
//
// A UoT session carrying a destination on every datagram is explicitly NOT fixed-destination.
// Connecting it would pin the session to whichever address arrived first and break every later one.
func TestUoTDynamicDestinationsAreNeverPromoted(t *testing.T) {
	metadata := &InboundContext{UoTDatagramDestinations: true}
	applyUDPConnectGuarded(metadata, &markerConn{fixed: true})

	require.False(t, metadata.UDPConnect,
		"a per-datagram session must not be auto-connected even when the connection declares a "+
			"fixed destination; its declared target does not describe the session")
}

// TestExplicitUDPConnectIsNotCleared is the other direction.
//
// The helper only ever SETS the flag. A configuration that declared connected UDP explicitly must
// not have it removed by a connection that happens not to implement the marker.
func TestExplicitUDPConnectIsNotCleared(t *testing.T) {
	metadata := &InboundContext{UDPConnect: true}
	ApplyUDPConnect(metadata, &plainPacketConn{})

	require.True(t, metadata.UDPConnect,
		"an explicit UDPConnect must survive a connection that does not declare one")
}
