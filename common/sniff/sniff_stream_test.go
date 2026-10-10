package sniff_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	"github.com/stretchr/testify/require"
)

// sniffGoroutines counts the goroutines whose stack names this package, which is what a leak check on
// a sniff is about.
//
// # Why not runtime.NumGoroutine()
//
// Both lifecycle tests below compare a goroutine count taken before a 64-iteration loop against the
// same count afterwards, and they used the PROCESS-GLOBAL number. That number is moved by everything
// else in the test binary: this package runs 93 tests in one process, several of them complete real
// TLS handshakes, and a previous repetition's goroutines can still be running when the next one
// starts. MEASURED: the assertion at the cancelled-context test fails roughly once per ten
// `-count=10` iterations and once in a full `./common/sniff/` run, while the same test passes on its
// own - i.e. a leak reported in a test that did not leak, caused by the tests around it.
//
// Counting the stacks that name this package keeps the property the tests exist for - PeekStream must
// not leave a goroutine behind - and drops the dependence on what the rest of the process is doing. A
// goroutine that this package leaked still names it, wherever it is blocked.
func sniffGoroutines() int {
	stacks := make([]byte, 1<<20)
	read := runtime.Stack(stacks, true)
	count := 0
	for _, stack := range strings.Split(string(stacks[:read]), "\n\n") {
		if strings.Contains(stack, "sing-box/common/sniff") {
			count++
		}
	}
	return count
}

// peekStreamChunks drives PeekStream over an in-memory connection that hands back the given chunks
// one per read, using the production stream plan, and reports what the sniffers decided.
func peekStreamChunks(t *testing.T, chunks [][]byte, cached []*buf.Buffer, terminal error) (*adapter.InboundContext, error, int) {
	t.Helper()
	conn := &scriptedConn{chunks: chunks, terminal: terminal}
	metadata := adapter.InboundContext{}
	sniffBuffer := buf.NewPacket()
	defer sniffBuffer.Release()
	err := sniff.PeekStream(
		context.Background(),
		&metadata,
		conn,
		cached,
		sniffBuffer,
		0,
		sniff.DefaultStreamSniffers...,
	)
	return &metadata, err, conn.reads
}

// TestPeekStreamTLSClientHelloAcrossReads is the contract ErrNeedMoreData exists for: a ClientHello
// that does not arrive in one piece must be sniffed again over the whole cached payload after every
// further read, and must still be recognised with the same domain.
//
// The read counts matter as much as the verdict. A payload delivered in N chunks must not take more
// than N reads plus the one that observes the end of it, because anything larger means the loop is
// waiting for data that has already arrived.
func TestPeekStreamTLSClientHelloAcrossReads(t *testing.T) {
	t.Parallel()
	hello := captureClientHello(t, &tls.Config{ServerName: "www.example.com"})
	for _, reads := range []int{1, 2, 4, 8, 16} {
		t.Run("reads="+strconv.Itoa(reads), func(t *testing.T) {
			metadata, err, readCount := peekStreamChunks(t, splitChunks(hello, reads), nil, nil)
			require.NoError(t, err)
			require.Equal(t, C.ProtocolTLS, metadata.Protocol)
			require.Equal(t, "www.example.com", metadata.Domain)
			require.LessOrEqual(t, readCount, reads+1)
		})
	}
}

// TestPeekStreamTinySegments sends one byte per read. It is the worst case for the retry loop - the
// payload view is rebuilt once per byte - and the point is that it still terminates with the right
// answer rather than giving up after the first parse.
func TestPeekStreamTinySegments(t *testing.T) {
	t.Parallel()
	hello := captureClientHello(t, &tls.Config{ServerName: "www.example.com"})
	chunks := make([][]byte, len(hello))
	for i := range hello {
		chunks[i] = hello[i : i+1]
	}
	metadata, err, readCount := peekStreamChunks(t, chunks, nil, nil)
	require.NoError(t, err)
	require.Equal(t, C.ProtocolTLS, metadata.Protocol)
	require.Equal(t, "www.example.com", metadata.Domain)
	require.LessOrEqual(t, readCount, len(hello)+1)
}

// TestPeekStreamHTTPHeaderAcrossReads covers the other parser that needs more than one read: a
// request line and its headers do not have to arrive together.
//
// The split points here stop after the request line, which is as far as the HTTP parser can be
// carried on a partial read - see sniff_fragmentation_test.go for what happens at the others and
// why that is not a property of this loop.
func TestPeekStreamHTTPHeaderAcrossReads(t *testing.T) {
	t.Parallel()
	request := []byte("GET /index.html HTTP/1.1\r\nHost: fragmented.example.com\r\nUser-Agent: sniff\r\nAccept: */*\r\n\r\n")
	for _, reads := range []int{1, 2} {
		t.Run("reads="+strconv.Itoa(reads), func(t *testing.T) {
			metadata, err, _ := peekStreamChunks(t, splitChunks(request, reads), nil, nil)
			require.NoError(t, err)
			require.Equal(t, C.ProtocolHTTP, metadata.Protocol)
			require.Equal(t, "fragmented.example.com", metadata.Domain)
		})
	}
}

// TestPeekStreamSSHBannerInOneRead covers a banner that arrives with its newline. A banner cut
// before the newline is still recognised but reports a shortened client, which is the pre-existing
// behaviour pinned in sniff_fragmentation_test.go rather than a property of this loop.
func TestPeekStreamSSHBannerInOneRead(t *testing.T) {
	t.Parallel()
	banner := []byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
	metadata, err, readCount := peekStreamChunks(t, [][]byte{banner}, nil, nil)
	require.NoError(t, err)
	require.Equal(t, C.ProtocolSSH, metadata.Protocol)
	require.Equal(t, "OpenSSH_9.6p1 Ubuntu-3ubuntu13", metadata.Client)
	require.Equal(t, 1, readCount)
}

// TestPeekStreamDNSOverTCPAcrossReads covers the length-prefixed stream form, whose own two-byte
// length is the only thing that says how much more is needed.
func TestPeekStreamDNSOverTCPAcrossReads(t *testing.T) {
	t.Parallel()
	query := mustHex("001e740701000001000000000000012a06676f6f676c6503636f6d0000010001")
	for _, reads := range []int{1, 2, 4, 8} {
		t.Run("reads="+strconv.Itoa(reads), func(t *testing.T) {
			metadata, err, _ := peekStreamChunks(t, splitChunks(query, reads), nil, nil)
			require.NoError(t, err)
			require.Equal(t, C.ProtocolDNS, metadata.Protocol)
		})
	}
}

// TestPeekStreamCachedBuffersAreReparsedInFull pins the ownership side of the contract: the
// sniffers must see the bytes earlier rounds cached, in front of the newest read, or a ClientHello
// split across two sniff actions would never be recognised.
func TestPeekStreamCachedBuffersAreReparsedInFull(t *testing.T) {
	t.Parallel()
	hello := captureClientHello(t, &tls.Config{ServerName: "www.example.com"})
	parts := splitChunks(hello, 3)
	cached := []*buf.Buffer{buf.As(parts[0]), buf.As(parts[1])}
	metadata, err, readCount := peekStreamChunks(t, [][]byte{parts[2]}, cached, nil)
	require.NoError(t, err)
	require.Equal(t, C.ProtocolTLS, metadata.Protocol)
	require.Equal(t, "www.example.com", metadata.Domain)
	require.Equal(t, 1, readCount)
}

// TestPeekStreamCachedBuffersAreNotConsumed checks the borrowing direction: the cached buffers
// belong to the caller and are wrapped in a cached connection afterwards, so a sniff must leave
// every one of their bytes readable.
func TestPeekStreamCachedBuffersAreNotConsumed(t *testing.T) {
	t.Parallel()
	hello := captureClientHello(t, &tls.Config{ServerName: "www.example.com"})
	parts := splitChunks(hello, 2)
	cachedBuffer := buf.As(parts[0])
	cached := []*buf.Buffer{cachedBuffer}
	_, err, _ := peekStreamChunks(t, [][]byte{parts[1]}, cached, nil)
	require.NoError(t, err)
	require.Equal(t, parts[0], cachedBuffer.Bytes())
}

// TestPeekStreamReadErrorsDuringMultiRead covers what a dying connection and an expiring deadline
// look like to the loop. Both interrupt a sniff that was still waiting for ErrNeedMoreData, and
// both must leave the caller with that aggregate rather than with the transport error: route.go
// decides whether to keep reading from errors.Is(_, ErrNeedMoreData).
func TestPeekStreamReadErrorsDuringMultiRead(t *testing.T) {
	t.Parallel()
	hello := captureClientHello(t, &tls.Config{ServerName: "www.example.com"})
	partial := splitChunks(hello, 4)[:1]
	for _, testCase := range []struct {
		name     string
		terminal error
	}{
		{"connection-closed", io.ErrClosedPipe},
		{"read-timeout", timeoutError{}},
		{"unexpected-eof", io.ErrUnexpectedEOF},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			metadata, err, readCount := peekStreamChunks(t, partial, nil, testCase.terminal)
			require.Error(t, err)
			require.ErrorIs(t, err, sniff.ErrNeedMoreData)
			require.GreaterOrEqual(t, readCount, 2)
			require.Empty(t, metadata.Protocol)
		})
	}
}

// TestPeekStreamFirstReadErrorIsReported pins the other half: when the very first read fails there
// is no cached payload to re-parse, and the transport error is what the caller gets.
func TestPeekStreamFirstReadErrorIsReported(t *testing.T) {
	t.Parallel()
	metadata, err, readCount := peekStreamChunks(t, nil, nil, io.ErrClosedPipe)
	require.Error(t, err)
	require.NotErrorIs(t, err, sniff.ErrNeedMoreData)
	require.ErrorContains(t, err, "read payload")
	require.Empty(t, metadata.Protocol)
	require.Equal(t, 1, readCount)
}

// TestPeekStreamDeadlineIsCleared checks the deadline bookkeeping on both sides of every read. The
// value the loop sets has to be the configured timeout measured from the start of the sniff - not a
// shorter one, which is the change that would flatter a benchmark and break a slow sender - and it
// has to be cleared again so the connection is not left holding a stale deadline.
func TestPeekStreamDeadlineIsCleared(t *testing.T) {
	t.Parallel()
	hello := captureClientHello(t, &tls.Config{ServerName: "www.example.com"})
	conn := &scriptedConn{chunks: splitChunks(hello, 4)}
	metadata := adapter.InboundContext{}
	sniffBuffer := buf.NewPacket()
	defer sniffBuffer.Release()
	start := time.Now()
	require.NoError(t, sniff.PeekStream(context.Background(), &metadata, conn, nil, sniffBuffer, 0, sniff.DefaultStreamSniffers...))
	require.GreaterOrEqual(t, len(conn.deadlines), 8)
	for i, deadline := range conn.deadlines {
		if i%2 == 1 {
			require.True(t, deadline.IsZero(), "deadline %d was not cleared", i)
			continue
		}
		remaining := deadline.Sub(start)
		require.Greater(t, remaining, C.ReadPayloadTimeout-time.Minute)
		require.LessOrEqual(t, remaining, C.ReadPayloadTimeout+time.Minute)
	}
}

// TestPeekStreamDoesNotOutliveItsDeadline checks the lifecycle claim that matters on a mobile
// device: a sniff that cannot be satisfied still ends and leaves no goroutine behind.
func TestPeekStreamDoesNotOutliveItsDeadline(t *testing.T) {
	before := sniffGoroutines()
	metadata := adapter.InboundContext{}
	start := time.Now()
	for i := 0; i < 64; i++ {
		conn := &scriptedConn{chunks: [][]byte{{0x16, 0x03, 0x01, 0x00}}, terminal: timeoutError{}}
		// A fresh read buffer per call, exactly as actionSniff creates one per sniff action: the
		// buffer accumulates the payload across rounds and is not reset by the loop.
		sniffBuffer := buf.NewPacket()
		err := sniff.PeekStream(context.Background(), &metadata, conn, nil, sniffBuffer, 10*time.Millisecond, sniff.DefaultStreamSniffers...)
		sniffBuffer.Release()
		require.ErrorIs(t, err, sniff.ErrNeedMoreData)
	}
	require.Less(t, time.Since(start), 10*time.Second)
	require.Never(t, func() bool { return sniffGoroutines() > before+4 }, 200*time.Millisecond, 20*time.Millisecond)
}

// TestPeekStreamUnknownPayloadSweepsEverySniffer pins the full-sweep path: a payload nothing claims
// runs every parser and reports all of their verdicts, so the debug log stays as informative as it
// was before the aggregation was batched per round.
func TestPeekStreamUnknownPayloadSweepsEverySniffer(t *testing.T) {
	t.Parallel()
	metadata, err, readCount := peekStreamChunks(t, [][]byte{bytes.Repeat([]byte{0x00}, 64)}, nil, nil)
	require.Error(t, err)
	require.NotErrorIs(t, err, sniff.ErrNeedMoreData)
	require.Empty(t, metadata.Protocol)
	require.Equal(t, 1, readCount)
	require.ErrorContains(t, err, "first record does not look like a TLS handshake")
	require.ErrorContains(t, err, "malformed HTTP request")
}

// TestPeekStreamDefaultTimeoutIsNotShortened is the guard against the cheapest possible fake win.
// The timeout on the wire is C.ReadPayloadTimeout unless a rule names one; if a future change
// shortens it, weak networks start losing ClientHellos that used to be sniffed.
func TestPeekStreamDefaultTimeoutIsNotShortened(t *testing.T) {
	t.Parallel()
	require.Equal(t, 300*time.Millisecond, C.ReadPayloadTimeout)
	conn := &scriptedConn{chunks: [][]byte{{0x16}}, terminal: timeoutError{}}
	metadata := adapter.InboundContext{}
	sniffBuffer := buf.NewPacket()
	defer sniffBuffer.Release()
	start := time.Now()
	err := sniff.PeekStream(context.Background(), &metadata, conn, nil, sniffBuffer, 0, sniff.DefaultStreamSniffers...)
	require.ErrorIs(t, err, sniff.ErrNeedMoreData)
	require.GreaterOrEqual(t, conn.deadlines[0].Sub(start), C.ReadPayloadTimeout-time.Second)
	require.LessOrEqual(t, conn.deadlines[0].Sub(start), C.ReadPayloadTimeout+time.Second)
}

// TestPeekStreamCancelledContextStillTerminates covers the lifecycle case the router actually
// produces: the flow context is cancelled while a sniff is running.
//
// PeekStream does not poll the context itself, and that is deliberate - adding a check would change
// how many reads a sniff performs, which is a contract of its own. What is pinned here is the
// property that matters instead: a cancelled context cannot make the loop hang, leak, or corrupt a
// verdict whose bytes are already in hand. The payload below is a complete ClientHello, so every
// read is served without blocking and the answer is the same one an uncancelled context gets; the
// deadline set once at the start of the call is what bounds a sniffer that would otherwise wait.
func TestPeekStreamCancelledContextStillTerminates(t *testing.T) {
	before := sniffGoroutines()
	hello := captureClientHello(t, &tls.Config{ServerName: "www.example.com"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	for i := 0; i < 64; i++ {
		conn := &scriptedConn{chunks: splitChunks(hello, 4)}
		metadata := adapter.InboundContext{}
		sniffBuffer := buf.NewPacket()
		err := sniff.PeekStream(ctx, &metadata, conn, nil, sniffBuffer, 0, sniff.DefaultStreamSniffers...)
		sniffBuffer.Release()
		// Either outcome is legitimate. A cancelled context races crypto/tls's own cancellation,
		// and which of the two wins depends on whether the ClientHello was parsed before the
		// context was observed - so the verdict may be a completed sniff or a definite failure,
		// but it may never be "ask for more data", which is the state that would leave the caller
		// reading from a flow whose context is already gone.
		require.NotErrorIs(t, err, sniff.ErrNeedMoreData)
	}
	require.Less(t, time.Since(start), 10*time.Second)
	require.Never(t, func() bool { return sniffGoroutines() > before+4 }, 200*time.Millisecond, 20*time.Millisecond)
}
