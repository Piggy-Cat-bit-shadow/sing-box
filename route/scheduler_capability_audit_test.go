package route

import (
	"io"
	"net"
	"strings"
	"testing"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// gateWriter is the shape a route-level scheduler gate would take around a destination writer.
//
// It deliberately models BOTH configurations, because the whole scheduler design turns on which
// one is correct.
type gateWriter struct {
	upstream    io.Writer
	replaceable bool
}

func (g *gateWriter) Write(p []byte) (int, error) { return g.upstream.Write(p) }

func (g *gateWriter) WriterReplaceable() bool { return g.replaceable }

func (g *gateWriter) UpstreamWriter() any { return g.upstream }

// tcpPair returns a connected pair of real TCP sockets, because the capability being probed is
// whether the kernel-splice path is reachable and a net.Pipe is not a syscall conn.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptedCh := make(chan accepted, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		acceptedCh <- accepted{conn, acceptErr}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	server := <-acceptedCh
	require.NoError(t, server.err)
	t.Cleanup(func() { _ = server.conn.Close() })
	return client, server.conn
}

// TestSchedulerGateMustRefuseUpstreamReplacement is the capability audit that gates the whole
// scheduler phase.
//
// # Why this decides the design
//
// The copy engine reaches past a destination writer through WriterWithUpstream. Both
// N.SyscallConnForWrite (which copyDirect uses to decide whether kernel splice is possible) and
// N.UnwrapWriter (which WriteOwnedBuffer uses to find ExtendedWriter/MTU/headroom) unwrap only when
// the wrapper reports WriterReplaceable() == true.
//
// A scheduler gate has to see every write to be able to delay one, so:
//
//	WriterReplaceable() == true   -> the engine splices straight to the socket and the gate is
//	                                 bypassed entirely; the scheduler silently does nothing
//	WriterReplaceable() == false  -> the engine keeps the wrapper in the path, declines kernel
//	                                 splice, and runs the userspace copy loop the gate lives on
//
// This test pins that difference, because getting it backwards produces a scheduler that appears
// to work and never fires.
func TestSchedulerGateMustRefuseUpstreamReplacement(t *testing.T) {
	_, server := tcpPair(t)

	// Sanity: the bare socket IS splice-capable, so the comparison below is meaningful.
	_, rawConn := N.SyscallConnForWrite(server)
	require.NotNil(t, rawConn, "a real TCP socket must report a syscall conn")

	t.Run("replaceable gate is bypassed", func(t *testing.T) {
		gate := &gateWriter{upstream: server, replaceable: true}
		// The engine unwraps to the socket and would splice around the gate.
		_, conn := N.SyscallConnForWrite(gate)
		require.NotNil(t, conn,
			"a replaceable gate is transparent to SyscallConnForWrite, so copyDirect would splice "+
				"past it and the scheduler would never run")
		require.NotEqual(t, io.Writer(gate), N.UnwrapWriter(gate),
			"a replaceable gate is also transparent to UnwrapWriter")
	})

	t.Run("non-replaceable gate keeps the write path", func(t *testing.T) {
		gate := &gateWriter{upstream: server, replaceable: false}
		// The engine stops at the gate, so the userspace copy loop - and therefore the gate - is
		// what performs the transfer.
		_, conn := N.SyscallConnForWrite(gate)
		require.Nil(t, conn,
			"a non-replaceable gate must make copyDirect decline, or the scheduler has no place "+
				"to run")
		require.Equal(t, io.Writer(gate), N.UnwrapWriter(gate),
			"a non-replaceable gate must remain the writer the engine sees")
	})
}

// TestNonReplaceableGateMustForwardExtendedWriter pins the other half of the contract.
//
// Declining replacement keeps the gate in the path, but it also means WriteOwnedBuffer resolves its
// capability checks against the GATE rather than the socket. If the gate does not itself present
// ExtendedWriter, the engine falls back to a raw Write and the WriteBuffer/headroom path is lost -
// a different regression from the one above, and one that would otherwise only show up as an
// unexplained throughput change.
func TestNonReplaceableGateMustForwardExtendedWriter(t *testing.T) {
	_, server := tcpPair(t)

	_, isExtended := any(server).(N.ExtendedWriter)
	require.False(t, isExtended, "a bare socket is not an ExtendedWriter, which is the case to model")

	// A gate that forwards the capability.
	forwarding := &extendedGate{upstream: server}
	resolved := N.UnwrapWriter(forwarding)
	require.Equal(t, io.Writer(forwarding), resolved,
		"a non-replaceable gate stays in the path")
	_, stillExtended := resolved.(N.ExtendedWriter)
	require.True(t, stillExtended,
		"the gate must itself expose ExtendedWriter, or the engine degrades to raw writes and "+
			"the WriteBuffer fast path disappears")

	// And the ownership contract: WriteBuffer releases the buffer exactly once.
	buffer := buf.NewSize(8)
	buffer.WriteString("payload")
	require.NoError(t, forwarding.WriteBuffer(buffer))
	// Release() resets the Buffer to its zero value, so a zeroed length after WriteBuffer is the
	// observable form of "the writer took ownership". A writer that did not release would leave
	// the payload visible here.
	require.Zero(t, buffer.Len(),
		"WriteBuffer must take ownership of the buffer, matching ExtendedWriterWrapper")
}

// extendedGate is a non-replaceable gate that forwards the write capabilities.
type extendedGate struct {
	upstream io.Writer
}

func (g *extendedGate) Write(p []byte) (int, error) { return g.upstream.Write(p) }

func (g *extendedGate) WriterReplaceable() bool { return false }

func (g *extendedGate) UpstreamWriter() any { return g.upstream }

// WriteBuffer mirrors bufio.ExtendedWriterWrapper: it owns and releases the buffer.
func (g *extendedGate) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	_, err := g.upstream.Write(buffer.Bytes())
	return err
}

var (
	_ N.ExtendedWriter     = (*extendedGate)(nil)
	_ N.WriterWithUpstream = (*extendedGate)(nil)
	_ N.WithUpstreamWriter = (*extendedGate)(nil)
	_ io.Writer            = (*extendedGate)(nil)
)

// TestCopyEngineKeepsGateInTheLoop proves the consequence end to end: with a non-replaceable gate as
// the destination, the userspace copy loop performs the transfer, so every written byte passes
// through the gate.
func TestCopyEngineKeepsGateInTheLoop(t *testing.T) {
	_, server := tcpPair(t)

	counting := &countingGate{upstream: server}
	source := strings.NewReader("hello-gated-world")

	written, err := bufio.CopyWithIncreateBuffer(counting, source, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.EqualValues(t, len("hello-gated-world"), written)
	require.Positive(t, counting.writes,
		"a non-replaceable gate must actually observe the writes; if this is zero the engine "+
			"bypassed it and the scheduler would be dead code")
}

type countingGate struct {
	upstream io.Writer
	writes   int
	bytes    int
}

func (g *countingGate) Write(p []byte) (int, error) {
	g.writes++
	g.bytes += len(p)
	return g.upstream.Write(p)
}

func (g *countingGate) WriterReplaceable() bool { return false }

func (g *countingGate) UpstreamWriter() any { return g.upstream }

func (g *countingGate) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	g.writes++
	g.bytes += buffer.Len()
	_, err := g.upstream.Write(buffer.Bytes())
	return err
}

var (
	_ N.ExtendedWriter     = (*countingGate)(nil)
	_ N.WriterWithUpstream = (*countingGate)(nil)
	_ N.WithUpstreamWriter = (*countingGate)(nil)
)
