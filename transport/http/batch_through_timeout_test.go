package http

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The timeout wrappers currently DROP the batch capabilities.
//
// # Why this test exists
//
// route/conn.go wraps a packet connection in canceler.NewPacketConn for the UDP idle
// timeout. sing's wrappers (TimerPacketConn, TimeoutPacketConn) implement only
// ReadPacket/WritePacket and expose neither CreateConnectedPacketBatchReadWaiter nor
// CreateConnectedPacketBatchWriter, so a tunnel that offers the batch capabilities
// loses them the moment it is wrapped:
//
//	http3PacketConn  -> offers batch
//	canceler wrapper -> batch invisible
//	bufio.CopyPacket -> falls back to one packet at a time
//
// The connection keeps working, so nothing fails; the tunnel is just slow. That is the
// exact failure mode a batching change must not ship with, which is why this test
// exists: it makes the loss VISIBLE and fails if and when the wrappers start
// forwarding, so the optimization can be enabled deliberately rather than by accident.
//
// # Current status: BLOCKED on the sing dependency
//
// For the batch path to survive the wrapper, sing's canceler package must forward the
// batch creators while still doing its activity accounting once per BATCH rather than
// once per packet (a per-packet Update would defeat the point, and simply marking the
// wrapper replaceable would bypass the timeout tracking entirely). There is no
// replace directive and no writable fork of github.com/sagernet/sing in this
// repository, and the task forbids vendoring or a local replace, so this is recorded as
// a blocked dependency phase rather than worked around.

// TestTimeoutWrapperDropsBatchCapabilities documents the current behaviour.
//
// It asserts the DROP deliberately. When the dependency is fixed this test flips, and
// the flip is the signal that the last hop is available - which is a better record than
// a comment that silently goes stale.
func TestTimeoutWrapperDropsBatchCapabilities(t *testing.T) {
	inner := newHTTP3PacketConn(&datagramFeedingStream{}, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer inner.Close()

	// The unwrapped connection DOES offer the capabilities, so the loss below is
	// attributable to the wrapper and not to the connection.
	_, isReadWaiter := bufio.CreateConnectedPacketBatchReadWaiter(inner)
	_, isWriter := bufio.CreateConnectedPacketBatchWriter(inner)
	require.True(t, isReadWaiter, "precondition: the bare connection offers batch read")
	require.True(t, isWriter, "precondition: the bare connection offers batch write")

	// A read deadline must be settable for the TimeoutPacketConn path to be chosen; the
	// in-memory fixture reports the error a real socket would not.
	_, wrapped := canceler.NewPacketConn(context.Background(), inner, 30*time.Second)

	_, wrappedReadWaiter := bufio.CreateConnectedPacketBatchReadWaiter(wrapped)
	_, wrappedWriter := bufio.CreateConnectedPacketBatchWriter(wrapped)

	// MEASURED CURRENT BEHAVIOUR: both are lost through the wrapper.
	if wrappedReadWaiter || wrappedWriter {
		t.Fatalf("the canceler wrapper now forwards batch capabilities "+
			"(read=%v write=%v). That is the change this test was waiting for: the "+
			"CONNECT-UDP batch path can now survive the idle-timeout wrapper, so update "+
			"this test and confirm the wrapper still does its activity accounting once "+
			"per BATCH rather than once per packet",
			wrappedReadWaiter, wrappedWriter)
	}

	t.Log("CONFIRMED: the canceler wrapper drops both batch capabilities, so a wrapped " +
		"CONNECT-UDP tunnel falls back to one packet at a time. This is the blocked " +
		"dependency phase: sing's canceler package must forward the batch creators " +
		"without losing its per-batch activity accounting.")
}
