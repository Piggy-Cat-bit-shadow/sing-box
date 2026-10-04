package route

import (
	"testing"

	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// This file is the Phase 2A capability matrix: it answers whether a scheduler gate installed at the
// route copy layer would cost the real AI path anything.
//
// # Why the question is not obvious
//
// `copyDirect` is the kernel-splice fast path, and it requires BOTH sides to be syscall-capable:
//
//	func copyDirect(source io.Reader, destination io.Writer, ...) (handed bool, ...) {
//	    if !N.SyscallAvailableForRead(source) || !N.SyscallAvailableForWrite(destination) { return }
//	    sourceReader, sourceConn := N.SyscallConnForRead(source)
//	    destinationWriter, destinationConn := N.SyscallConnForWrite(destination)
//	    if sourceConn == nil || destinationConn == nil { return }
//	    ...
//	}
//
// A non-replaceable scheduler gate makes the DESTINATION look non-syscall-capable, which is why
// commit 940660d5a measured the loss against a bare TCP socket. But the loss only matters if the
// flow would otherwise have used copyDirect at all - and every check above is an interface
// assertion on the CONCRETE types involved.
//
// # What this measures
//
// The predicates below are sing's own, called through a typed nil so no live connection is needed:
// the checks are method-set assertions, so the value is irrelevant. That makes this an exact probe
// of the engine's path selection rather than a re-implementation of it.

// TestTUNGoConnCannotUseCopyDirect is the finding that decides the scheduler's cost on the AI path.
//
// The upload copy is `connectionCopy(source=conn, destination=remoteConn)` where `conn` is the
// INBOUND connection, and the download copy is the reverse. For a TUN-inbound flow that inbound
// connection is a *tun.GoConn - a userspace netstack connection, not a file descriptor.
//
// If a GoConn is not syscall-capable, `copyDirect` returns before doing anything, in BOTH
// directions, for EVERY destination protocol. That would mean the AI path never had the kernel
// splice to lose.
func TestTUNGoConnCannotUseCopyDirect(t *testing.T) {
	// Typed nil: the assertions under test inspect the method set, not the value.
	var goConn *tun.GoConn

	require.False(t, N.SyscallAvailableForRead(goConn),
		"a TUN GoConn must not be syscall-readable; if this ever becomes true, a gate on the "+
			"upload copy would start costing kernel splice on every TUN flow")
	require.False(t, N.SyscallAvailableForWrite(goConn),
		"a TUN GoConn must not be syscall-writable; if this ever becomes true, a gate on the "+
			"download copy would start costing kernel splice")

	// Each call returns (SyscallReader, syscall.RawConn). Both must be nil: a bare socket returns
	// a nil SyscallReader with a non-nil RawConn, so checking only the first would pass for
	// everything and prove nothing.
	readReader, readConn := N.SyscallConnForRead(goConn)
	writeWriter, writeConn := N.SyscallConnForWrite(goConn)
	require.Nil(t, readReader, "GoConn must not implement SyscallReader")
	require.Nil(t, readConn, "GoConn must not expose a syscall raw conn for reading")
	require.Nil(t, writeWriter, "GoConn must not implement SyscallWriter")
	require.Nil(t, writeConn, "GoConn must not expose a syscall raw conn for writing")

	// And it does not advertise a replaceable upstream either, which is the other route to
	// syscall capability (and the route route.spliceConnection uses).
	_, isReplaceableReader := any(goConn).(N.ReaderWithUpstream)
	_, isReplaceableWriter := any(goConn).(N.WriterWithUpstream)
	require.False(t, isReplaceableReader, "GoConn must not advertise a replaceable reader upstream")
	require.False(t, isReplaceableWriter, "GoConn must not advertise a replaceable writer upstream")
}

// TestBareTCPSocketIsSyscallCapable is the control. Without it the test above would also pass if
// the predicates were broken and always returned false, which would make the whole matrix
// meaningless.
func TestBareTCPSocketIsSyscallCapable(t *testing.T) {
	client, server := tcpPair(t)

	require.True(t, N.SyscallAvailableForRead(server), "a real socket is syscall-readable")
	require.True(t, N.SyscallAvailableForWrite(server), "a real socket is syscall-writable")

	// A plain socket yields a nil SyscallReader but a real RawConn, which is exactly what
	// copyDirect consumes (`sourceReader, sourceConn := N.SyscallConnForRead(source)` then checks
	// sourceConn).
	_, readConn := N.SyscallConnForRead(server)
	_, writeConn := N.SyscallConnForWrite(server)
	require.NotNil(t, readConn, "a real socket exposes a read syscall conn")
	require.NotNil(t, writeConn, "a real socket exposes a write syscall conn")

	_ = client
}

// TestCopyDirectNeedsBothSides pins the two-sided condition, so a later change cannot make one side
// syscall-capable and silently widen the fast path.
func TestCopyDirectNeedsBothSides(t *testing.T) {
	_, server := tcpPair(t)
	var goConn *tun.GoConn

	// Destination splices, source does not.
	require.False(t, N.SyscallAvailableForRead(goConn) && N.SyscallAvailableForWrite(server),
		"TUN source -> any destination must not qualify for copyDirect")

	// Source splices, destination does not (the AI upload shape, where the destination would be a
	// protocol's framed writer rather than this socket).
	require.False(t, N.SyscallAvailableForRead(server) && N.SyscallAvailableForWrite(goConn),
		"any source -> TUN destination must not qualify for copyDirect")
}

// TestSpliceRequiresGoConnPinsTheInboundCondition records the OTHER fast path's entry condition, so
// the two are not confused with each other.
//
// route.spliceConnection and bufio.copyDirect are different layers with different conditions. The
// first requires the INBOUND side to cast to *tun.GoConn; the second requires both sides to be
// syscall-capable. A flow can pass one and fail the other, so a conclusion about one says nothing
// about the other and the matrix reports them separately.
func TestSpliceRequiresGoConnPinsTheInboundCondition(t *testing.T) {
	var goConn *tun.GoConn
	cast, isGoConn := N.CastWriter[*tun.GoConn](goConn)
	require.True(t, isGoConn, "the TUN inbound is what route splice looks for")
	require.Nil(t, cast, "typed nil")

	// A bare socket is NOT a GoConn, so a local-proxy inbound cannot satisfy route splice no matter
	// what the destination is - which is the probe result recorded before this phase.
	_, server := tcpPair(t)
	_, isGoConn2 := N.CastWriter[*tun.GoConn](server)
	require.False(t, isGoConn2, "an ordinary socket must not satisfy the splice inbound condition")
}
