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

// sniffGoroutinesFromCallback is sniffGoroutines for a census taken from the goroutine testify runs a
// condition on, and the subtraction is the difference between an allowance and a measurement.
//
// # Why `before` and the samples were not comparable
//
// `before` is read on the TEST goroutine. The condition of `require.Never`/`require.Eventually` runs on
// a goroutine testify starts, and a closure defined in this file has `sing-box/common/sniff_test` on
// its own stack - the same substring the predicate matches. MEASURED: a census taken from the test
// goroutine reads 1 and the same census taken from a callback goroutine reads 2, so every sample the
// predicate saw was one HIGHER than the baseline it was compared against.
//
// The consequence is the failure direction that matters for a leak check. With the `> before+4` this
// replaced, the real allowance was 3, not 4, and a FIXED leak was measured at every size below it: one
// leaked goroutine left the census at 3, two at 4 and three at 5, and the predicate fired at none of
// them; only four was caught. An allowance that hides three goroutines is not a tolerance, it is a
// blind spot - and it was invisible because the number was never calibrated.
//
// The test goroutine itself cancels out and is not part of this correction: it is blocked inside the
// assertion with `sniff_test` on its stack in both readings, so it contributes to `before` and to every
// sample alike. Only the callback's own frame is uncancelled, and it is exactly one.
//
// # Why this correction is necessary but NOT sufficient, measured by an adversary
//
// `assert.Never` starts its condition with a bare `go checkCond()` and re-arms the ticker only after a
// result arrives - so the PREVIOUS tick's condition goroutine can still be exiting while the next one
// runs, and a single sample can therefore see TWO callback frames rather than one. MEASURED with
// nothing leaked at all: `sniffGoroutines()` inside a condition read 2 on one run and 3 on the next,
// against a test-goroutine baseline of 1 - i.e. the corrected reading is `before` sometimes and
// `before+1` sometimes.
//
// That is why the two lifecycle checks do NOT assert `> before` over a window any more. A zero-margin
// "never exceeds" predicate would fire on testify's own scheduling with nothing wrong with the
// product. The leak assertion is instead "the census RETURNS to its baseline", which is immune to a
// transient extra frame and is exactly the property these tests exist for: a leaked goroutine never
// comes back.
func sniffGoroutinesFromCallback() int {
	return sniffGoroutines() - 1
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
	requireTheSniffCensusReturnsToBaseline(t, before,
		"PeekStream left a goroutine behind after an unsatisfiable sniff")
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
	requireTheSniffCensusReturnsToBaseline(t, before,
		"a cancelled context left a goroutine behind")
}

// requireTheSniffCensusReturnsToBaseline is the leak assertion both lifecycle checks use, and it is
// shaped the way it is because of a measurement rather than a preference.
//
// # Why "returns to baseline" and not "never exceeds baseline"
//
// "Never exceeds" is the more obvious phrasing and it cannot be asserted safely here. `assert.Never`
// starts its condition with a bare `go checkCond()` and re-arms the ticker only after a result
// arrives, so the previous tick's condition goroutine can still be exiting while the next one runs.
// MEASURED with nothing leaked: a sample inside a condition read two callback frames on one run and
// one on the next. With the frame correction applied that is `before` or `before+1`, so a zero-margin
// "never exceeds" predicate fires on testify's own scheduling with the product perfectly correct.
//
// The two halves below are therefore:
//
//  1. SECONDARY, and calibrated rather than guessed: the census never exceeds `before+1`. The one
//     allowed frame is the transient one above, MEASURED - not the uncalibrated 3 that the `+4`
//     allowance really was. This catches a burst leak of two or more immediately.
//  2. PRIMARY: the census RETURNS to `before`. A leaked goroutine never returns, so a single leaked
//     goroutine is caught by this half and by nothing else. It is immune to the transient frame
//     because a transient frame is gone by the next sample.
//
// The window is generous (2 s) because this half is about a permanent consequence, not about speed:
// there is no timing assumption to tune and none is stated.
func requireTheSniffCensusReturnsToBaseline(t *testing.T, before int, message string) {
	t.Helper()
	require.Never(t, func() bool { return sniffGoroutinesFromCallback() > before+1 },
		200*time.Millisecond, 20*time.Millisecond,
		"%s: the census exceeded its baseline by more than the one callback frame testify's own tick "+
			"can leave behind (baseline %d)", message, before)
	require.Eventually(t, func() bool { return sniffGoroutinesFromCallback() <= before },
		2*time.Second, 5*time.Millisecond,
		"%s: the census did not return to its baseline of %d. A leaked goroutine never comes back, "+
			"which is why THIS half is the leak assertion - the calibrated window above tolerates one "+
			"transient frame and therefore cannot see a single leak on its own", message, before)
}

// TestTheSniffCensusMovesForExactlyOneLeakedGoroutine is the calibration the two lifecycle checks were
// missing, and it is the half that makes the exact bound above safe to assert.
//
// A census another test in the binary can move, or one that cannot move at all, is not evidence. The
// allowance this replaced (`> before+4`) was never calibrated, and MEASURED it hid a fixed leak of one,
// two and three goroutines while catching four. So the instrument is shown here to move for EXACTLY
// one goroutine started by this package, read the same way the lifecycle predicates read it - from a
// callback goroutine, through the correction - and to come back when that goroutine is released.
func TestTheSniffCensusMovesForExactlyOneLeakedGoroutine(t *testing.T) {
	baseline := sniffGoroutines()

	release := make(chan struct{})
	started := make(chan struct{})
	go func() {
		// A function literal defined in this file carries `sing-box/common/sniff_test` on its stack,
		// which is exactly the shape the predicate matches - so this is a real leaked-goroutine
		// stand-in rather than a simulation of one.
		close(started)
		<-release
	}()
	<-started

	require.Equal(t, baseline+1, pollCensusFromCallback(t, baseline, 5*time.Second),
		"one goroutine started by this package must move the census by exactly one; a census that "+
			"cannot move proves nothing, and one that moves by more is counting something else "+
			"(baseline was %d)", baseline)

	close(release)

	returned := 0
	deadline := time.Now().Add(5 * time.Second)
	for {
		// Read the PLAIN census here, not the callback-corrected one: this reading is taken on the
		// test goroutine, which is where `baseline` was taken, so the two are already comparable and
		// subtracting the callback's frame would compare a corrected number against an uncorrected one.
		// That asymmetry was MEASURED while writing this test - it reported "expected 1, actual 0" - and
		// it is the same class of error as the one the correction exists to remove.
		returned = sniffGoroutines()
		if returned <= baseline || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.Equal(t, baseline, returned,
		"the census must come back to its baseline once the goroutine is released, or it reports an "+
			"accumulation that is not there (baseline was %d)", baseline)
}

// pollCensusFromCallback reads the census the way a lifecycle predicate reads it - from a goroutine
// other than the test's - until it exceeds baseline, and returns the last reading if the window
// passes, so the caller's assertion is what reports the failure rather than a timeout.
func pollCensusFromCallback(t *testing.T, baseline int, window time.Duration) int {
	t.Helper()
	observed := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		deadline := time.Now().Add(window)
		for {
			observed = sniffGoroutinesFromCallback()
			if observed > baseline || time.Now().After(deadline) {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	<-done
	return observed
}
