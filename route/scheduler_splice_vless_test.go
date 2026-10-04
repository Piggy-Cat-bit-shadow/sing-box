package route

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// TestLiveVLESSConnIsNotARouteSpliceTarget closes the Phase 2A.1 question with a real object.
//
// # What is under test
//
// ConnectionManager receives, for a VLESS flow, exactly the conn that
// `vless.Outbound.DialContext` returns. That method is a thin wrapper:
//
//	conn = <dial or TLS to the server>
//	return h.client.DialEarlyConn(conn, destination)
//
// so the object that route splice inspects is the OUTPUT of DialEarlyConn. That is the object built
// here, through the same production client constructor with the same call, rather than a hand-made
// stand-in or a method-set guess.
//
// The raw dial is a local listener that accepts and discards, so the fixture is local-only and has
// no Internet dependency. VLESS writes its request header and returns early, so no server response
// is required.
//
// # Why this matters
//
// If this conn were a splice target, route splice would consume the flow before
// connectionCopy ran and a route-level scheduler gate would be dead code for the AI path.
func TestLiveVLESSConnIsNotARouteSpliceTarget(t *testing.T) {
	rawConn := dialDiscardListener(t)

	client, err := vless.NewClient("2f0e6a1c-9f4b-4c1e-9b1a-7d3e5f8a0c22", "", log.NewNOPFactory().Logger())
	require.NoError(t, err, "the production VLESS client must construct")

	finalConn, err := client.DialEarlyConn(rawConn, M.ParseSocksaddrHostPort("example.com", 443))
	require.NoError(t, err, "DialEarlyConn must return the conn the outbound would hand to route")
	require.NotNil(t, finalConn)
	t.Cleanup(func() { _ = finalConn.Close() })

	t.Logf("final VLESS conn type: %T", finalConn)

	target, reason, ok := unwrapSpliceTargetWithReason(finalConn, false)

	require.False(t, ok,
		"a live VLESS conn must NOT be a route splice target: if it is, splice consumes the flow "+
			"before connectionCopy and a route-level scheduler gate never runs for VLESS traffic")
	require.Nil(t, target.socket)
	require.Equal(t, spliceReasonTargetNotReplaceable, reason,
		"the refusal must come from the replaceable-upstream gate. Any other reason means the "+
			"VLESS conn blocked the unwrap somewhere unexpected and the model needs revisiting")
}

// TestLiveVLESSConnIsNotSyscallCapable records the second, independent reason the AI path cannot use
// a kernel fast path: even the destination side of copyDirect fails, which is consistent with the
// TUN-source finding in the copy matrix.
func TestLiveVLESSConnIsNotSyscallCapable(t *testing.T) {
	rawConn := dialDiscardListener(t)

	client, err := vless.NewClient("2f0e6a1c-9f4b-4c1e-9b1a-7d3e5f8a0c22", "", log.NewNOPFactory().Logger())
	require.NoError(t, err)
	finalConn, err := client.DialEarlyConn(rawConn, M.ParseSocksaddrHostPort("example.com", 443))
	require.NoError(t, err)
	t.Cleanup(func() { _ = finalConn.Close() })

	require.False(t, N.SyscallAvailableForWrite(finalConn),
		"a VLESS conn transforms the byte stream, so it must not claim syscall write capability; "+
			"if it ever does, copyDirect would try to splice around its framing")
	require.False(t, N.SyscallAvailableForRead(finalConn),
		"a VLESS conn must not claim syscall read capability either")

	// And the raw conn underneath IS capable, so the difference is the VLESS wrapper and not a
	// broken predicate.
	require.True(t, N.SyscallAvailableForWrite(rawConn),
		"control: the undecorated socket is syscall-capable, so the wrapper is what changed the "+
			"answer")
}

// dialDiscardListener returns a connected socket whose peer accepts and discards. Local-only.
func dialDiscardListener(t *testing.T) net.Conn {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Drain so a header write never blocks on a full socket buffer.
				_, _ = conn.Read(make([]byte, 4096))
			}()
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// A deadline keeps a handshake-shaped surprise from hanging the suite. It is a watchdog, not
	// synchronisation: VLESS returns after writing its header, so nothing here waits on a timer.
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	return conn
}
