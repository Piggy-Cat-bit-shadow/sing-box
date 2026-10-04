package route

import (
	"io"
	"net"
	"syscall"
	"testing"

	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// This file closes the route-splice reachability question for the scheduler landing point.
//
// # The question
//
// A gate installed at ConnectionManager.connectionCopy only runs if the copy loop runs. Route
// splice runs BEFORE it:
//
//	spliceConnection(conn, remoteConn) -> spliced? then connectionCopy is never called
//
// So the gate is dead code for any flow whose remote conn satisfies the splice target contract.
//
// # The contract, read from unwrapSpliceTargetWithReason
//
// Walking the chain, a conn is a splice target only if it unwraps through BOTH
//
//	N.ReaderWithUpstream with ReaderReplaceable() == true
//	N.WriterWithUpstream with WriterReplaceable() == true
//
// until it reaches a tun.SpliceSocket (syscall.Conn + io.Closer + Attach + Detach). Anything else
// terminates with spliceReasonTargetNotReplaceable.

// TestRawTCPSocketIsNotASpliceTarget is the finding.
//
// It is not obvious: a raw OS socket looks like the most spliceable thing there is, and it IS
// syscall-capable. But syscall capability is not the test here - the unwrap requires an
// UPSTREAM-REPLACEABLE chain ending in a tun.SpliceSocket, and an ordinary *net.TCPConn is neither
// replaceable nor a tun socket.
//
// The consequence matters for the scheduler: any conn that unwraps down to an ordinary OS socket
// fails here, because the unwrap keeps going until it finds a tun.SpliceSocket and there is none.
// A protocol conn is strictly further from the contract, so it cannot fare better.
func TestRawTCPSocketIsNotASpliceTarget(t *testing.T) {
	_, server := tcpPair(t)

	_, reason, ok := unwrapSpliceTargetWithReason(server, false)
	require.False(t, ok,
		"a bare OS socket must not satisfy the route splice target contract; if this becomes "+
			"true, route splice starts consuming flows before connectionCopy runs")
	require.Equal(t, spliceReasonTargetNotReplaceable, reason,
		"the refusal must be the replaceable-upstream check, which is the first gate an ordinary "+
			"socket fails. A different reason would mean the model of the contract is wrong")
}

// spliceTargetControl implements exactly the contract unwrapSpliceTargetWithReason documents, so the
// test above cannot pass by the helper being vacuously false.
//
// It is a test-only type rather than a real tun socket: sing-tun does not export a constructor for
// one, and building a virtual stack to obtain it would be plumbing this characterisation does not
// need. The control's job is to prove the helper CAN return true for a conforming conn.
type spliceTargetControl struct{}

func (spliceTargetControl) Read([]byte) (int, error)              { return 0, io.EOF }
func (spliceTargetControl) Write(p []byte) (int, error)           { return len(p), nil }
func (spliceTargetControl) Close() error                          { return nil }
func (spliceTargetControl) Attach(io.Closer) (io.Closer, bool)    { return nil, false }
func (spliceTargetControl) Detach()                               {}
func (spliceTargetControl) SyscallConn() (syscall.RawConn, error) { return nil, nil }
func (spliceTargetControl) ReaderReplaceable() bool               { return true }
func (spliceTargetControl) WriterReplaceable() bool               { return true }

var (
	_ N.ReaderWithUpstream = spliceTargetControl{}
	_ N.WriterWithUpstream = spliceTargetControl{}
	_ syscall.Conn         = spliceTargetControl{}
	_ io.ReadWriteCloser   = spliceTargetControl{}
)

// TestSpliceTargetContractControl proves the helper returns success for a conforming conn.
func TestSpliceTargetContractControl(t *testing.T) {
	target, reason, ok := unwrapSpliceTargetWithReason(spliceTargetControl{}, false)
	require.True(t, ok,
		"a conn meeting the documented contract must be accepted, or the target test is "+
			"vacuously false and proves nothing about real flows")
	require.Equal(t, spliceReasonSuccess, reason)
	require.NotNil(t, target.socket, "a successful unwrap must produce the splice socket")
}

// TestSpliceTargetRefusesAReplaceableWrapperOverAnOrdinarySocket is the case that decides the
// scheduler question for proxy protocols.
//
// A protocol conn is typically a transparent wrapper over the dialled socket, and such a wrapper
// CAN advertise a replaceable upstream. That is the one shape that would let the unwrap continue -
// and it still fails, because the unwrap then lands on the ordinary socket tested above, which is
// not a tun.SpliceSocket. So the wrapper's transparency does not help it.
func TestSpliceTargetRefusesAReplaceableWrapperOverAnOrdinarySocket(t *testing.T) {
	_, server := tcpPair(t)

	wrapper := &replaceableSocketWrapper{upstream: server}
	_, reason, ok := unwrapSpliceTargetWithReason(wrapper, false)

	require.False(t, ok,
		"a replaceable wrapper over an ordinary socket must still be refused: the unwrap reaches "+
			"the socket and the socket is not a tun.SpliceSocket")
	require.Equal(t, spliceReasonTargetNotReplaceable, reason,
		"the refusal happens one layer deeper than for a bare socket, which is exactly why a "+
			"transparent protocol wrapper does not make a flow spliceable")
}

// replaceableSocketWrapper models a transparent, replaceable protocol wrapper over a real socket.
type replaceableSocketWrapper struct {
	upstream net.Conn
}

func (w *replaceableSocketWrapper) Read(p []byte) (int, error)  { return w.upstream.Read(p) }
func (w *replaceableSocketWrapper) Write(p []byte) (int, error) { return w.upstream.Write(p) }
func (w *replaceableSocketWrapper) Close() error                { return w.upstream.Close() }
func (w *replaceableSocketWrapper) ReaderReplaceable() bool     { return true }
func (w *replaceableSocketWrapper) WriterReplaceable() bool     { return true }
func (w *replaceableSocketWrapper) UpstreamReader() any         { return w.upstream }
func (w *replaceableSocketWrapper) UpstreamWriter() any         { return w.upstream }
