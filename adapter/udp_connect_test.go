package adapter

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Tests for consuming the UDPConnectPacketConn capability (P1-1).
//
// # The gap this closes
//
// A packet connection that declares a FIXED destination must take the connected-UDP path. The
// declaration was only read by two handler wrappers, but roughly two dozen inbound protocols
// call RoutePacketConnectionEx directly and bypass them entirely - so a CONNECT-UDP tunnel
// arriving through one of those paths silently lost its fixed-destination declaration.
//
// The router now reads the capability at its own packet entry point, where the original
// connection is still visible and every caller passes through.

// fixedDestinationPacketConn declares a fixed destination.
type fixedDestinationPacketConn struct{}

func (fixedDestinationPacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, nil
}
func (fixedDestinationPacketConn) WritePacket(*buf.Buffer, M.Socksaddr) error { return nil }
func (fixedDestinationPacketConn) Close() error                               { return nil }
func (fixedDestinationPacketConn) LocalAddr() net.Addr                        { return nil }
func (fixedDestinationPacketConn) SetDeadline(time.Time) error                { return nil }
func (fixedDestinationPacketConn) SetReadDeadline(time.Time) error            { return nil }
func (fixedDestinationPacketConn) SetWriteDeadline(time.Time) error           { return nil }

// IsUDPConnect reports the fixed destination.
func (fixedDestinationPacketConn) IsUDPConnect() bool { return true }

// dynamicPacketConn is an ordinary per-datagram connection with no declaration.
type dynamicPacketConn struct{ fixedDestinationPacketConn }

func (dynamicPacketConn) IsUDPConnect() bool { return false }

// TestApplyUDPConnectFromCapability is the positive case.
func TestApplyUDPConnectFromCapability(t *testing.T) {
	metadata := &InboundContext{}
	ApplyUDPConnect(metadata, fixedDestinationPacketConn{})

	if !metadata.UDPConnect {
		t.Fatal("a connection declaring a fixed destination must set UDPConnect")
	}
}

// TestApplyUDPConnectIgnoresUndeclaredConnections is the critical negative case.
//
// An ordinary packet connection must NOT be marked connected. Inferring a fixed destination
// from "the session seems to have one destination" would misfire for ordinary SOCKS UDP, where
// the first datagram's destination says nothing about the rest.
func TestApplyUDPConnectIgnoresUndeclaredConnections(t *testing.T) {
	metadata := &InboundContext{}
	ApplyUDPConnect(metadata, dynamicPacketConn{})

	if metadata.UDPConnect {
		t.Fatal("a connection that does not declare a fixed destination must not be connected")
	}
}

// TestApplyUDPConnectExplicitDeclarationIsFalse covers a connection that implements the
// interface but explicitly reports false.
func TestApplyUDPConnectExplicitDeclarationIsFalse(t *testing.T) {
	metadata := &InboundContext{}
	var conn N.PacketConn = dynamicPacketConn{}
	ApplyUDPConnect(metadata, conn)

	if metadata.UDPConnect {
		t.Fatal("an explicit false must not set UDPConnect")
	}
}

// TestApplyUDPConnectNeverClearsAnExplicitRule is the interaction requirement.
//
// A user may configure `udp_connect: true` as a route action. The capability must be able to
// ADD to that decision but never to take it away - a capability that silently disabled a user's
// explicit configuration would be worse than not reading it at all.
func TestApplyUDPConnectNeverClearsAnExplicitRule(t *testing.T) {
	metadata := &InboundContext{UDPConnect: true}
	ApplyUDPConnect(metadata, dynamicPacketConn{})

	if !metadata.UDPConnect {
		t.Fatal("a non-declaring connection must not clear an explicitly configured UDPConnect")
	}
}

// TestApplyUDPConnectHandlesNilInputs keeps the helper total, since the router calls it on
// every packet connection.
func TestApplyUDPConnectHandlesNilInputs(t *testing.T) {
	metadata := &InboundContext{}
	ApplyUDPConnect(metadata, nil)
	if metadata.UDPConnect {
		t.Fatal("a nil connection must not set UDPConnect")
	}

	// A nil metadata pointer must not panic.
	ApplyUDPConnect(nil, fixedDestinationPacketConn{})
}
