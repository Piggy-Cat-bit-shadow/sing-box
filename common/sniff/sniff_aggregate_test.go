package sniff_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/stretchr/testify/require"
)

// The failure sentinels used to check that an aggregate really is an aggregate. They are distinct
// values with distinct messages, so nothing in the aggregation is allowed to drop one.
var (
	errFailureOne   = errors.New("one")
	errFailureTwo   = errors.New("two")
	errFailureThree = errors.New("three")
	errFailureFour  = errors.New("four")
	errFailureFive  = errors.New("five")
	errFailureSix   = errors.New("six")
	errFailureSeven = errors.New("seven")
	errFailureEight = errors.New("eight")
	// errFailureAbsent is never returned by any sniffer in these tests.
	errFailureAbsent = errors.New("absent")
)

func failureSentinels() []error {
	return []error{
		errFailureOne, errFailureTwo, errFailureThree, errFailureFour,
		errFailureFive, errFailureSix, errFailureSeven, errFailureEight,
	}
}

func failingPacketSniffers(failures []error) []sniff.PacketSniffer {
	sniffers := make([]sniff.PacketSniffer, len(failures))
	for index, failure := range failures {
		sniffers[index] = func(_ context.Context, _ *adapter.InboundContext, _ []byte) error {
			return failure
		}
	}
	return sniffers
}

func failingStreamSniffers(failures []error) []sniff.StreamSniffer {
	sniffers := make([]sniff.StreamSniffer, len(failures))
	for index, failure := range failures {
		sniffers[index] = func(_ context.Context, _ *adapter.InboundContext, _ io.Reader) error {
			return failure
		}
	}
	return sniffers
}

// foldedFailureAggregate is the aggregation the loop used to perform, kept here as the reference
// the batched form has to match. E.Errors flattens multi-errors, drops nils and de-duplicates by
// message, and doing that per sniffer and doing it once over the whole round are only equivalent if
// those steps are associative - which is the claim this function exists to test.
func foldedFailureAggregate(failures []error) error {
	var aggregate error
	for _, failure := range failures {
		aggregate = E.Errors(aggregate, failure)
	}
	return aggregate
}

// TestPeekPacketReportsEveryFailure is the regression test for the packet aggregation.
//
// The failure path is the one place metadata.SniffError is worth anything, so it has to list every
// sniffer that said no. A version of this function that kept the first failure in a local and then
// failed to move it into the slice returned a clean, fast, and silently incomplete answer: four of
// these eight failures never reached the caller. Speed is not evidence here.
func TestPeekPacketReportsEveryFailure(t *testing.T) {
	t.Parallel()
	failures := failureSentinels()
	err := sniff.PeekPacket(context.Background(), &adapter.InboundContext{}, []byte{1, 2, 3}, failingPacketSniffers(failures)...)
	require.Error(t, err)
	for index, failure := range failures {
		require.ErrorIs(t, err, failure, "failure %d is missing from the aggregate", index)
	}
	require.NotErrorIs(t, err, errFailureAbsent)
	require.Equal(t, foldedFailureAggregate(failures).Error(), err.Error())
}

// TestPeekPacketSingleFailureIsReturnedUnchanged pins the short form. E.Errors returns its only
// argument untouched, so a sweep with one failure has to report that failure itself rather than a
// wrapper - route.go compares metadata.SniffError against sniff.ErrNeedMoreData on every rewrite a
// sniff action performs.
func TestPeekPacketSingleFailureIsReturnedUnchanged(t *testing.T) {
	t.Parallel()
	err := sniff.PeekPacket(context.Background(), &adapter.InboundContext{}, []byte{1}, failingPacketSniffers([]error{errFailureOne})...)
	require.Equal(t, errFailureOne, err)
}

// TestPeekPacketNoFailureIsNoError covers the empty sweep, which is what a rule with an empty
// sniffer list reduces to.
func TestPeekPacketNoFailureIsNoError(t *testing.T) {
	t.Parallel()
	require.NoError(t, sniff.PeekPacket(context.Background(), &adapter.InboundContext{}, []byte{1}))
}

// TestPeekPacketStopsAtTheFirstMatch checks that a claim ends the sweep and that the failures in
// front of it are diagnostics only: nothing about them reaches the caller.
func TestPeekPacketStopsAtTheFirstMatch(t *testing.T) {
	t.Parallel()
	claiming := func(_ context.Context, metadata *adapter.InboundContext, _ []byte) error {
		metadata.Protocol = "claimed"
		return nil
	}
	failures := []error{errFailureOne, errFailureTwo}
	sniffers := append(failingPacketSniffers(failures), claiming, func(_ context.Context, _ *adapter.InboundContext, _ []byte) error {
		return errFailureAbsent
	})
	metadata := adapter.InboundContext{}
	err := sniff.PeekPacket(context.Background(), &metadata, []byte{1}, sniffers...)
	require.NoError(t, err)
	require.Equal(t, "claimed", metadata.Protocol)
}

// TestPeekStreamReportsEveryFailure is the same regression for the stream path, where the round's
// failures used to be folded into the aggregate one sniffer at a time.
func TestPeekStreamReportsEveryFailure(t *testing.T) {
	t.Parallel()
	failures := failureSentinels()
	conn := &scriptedConn{chunks: [][]byte{{0x01, 0x02, 0x03, 0x04}}}
	metadata := adapter.InboundContext{}
	sniffBuffer := buf.NewPacket()
	defer sniffBuffer.Release()
	err := sniff.PeekStream(context.Background(), &metadata, conn, nil, sniffBuffer, 0, failingStreamSniffers(failures)...)
	require.Error(t, err)
	for index, failure := range failures {
		require.ErrorIs(t, err, failure, "failure %d is missing from the aggregate", index)
	}
	require.NotErrorIs(t, err, errFailureAbsent)
	require.Equal(t, foldedFailureAggregate(failures).Error(), err.Error())
	// None of these sniffers asked for more data, so one read is the whole conversation.
	require.Equal(t, 1, conn.reads)
}

// TestPeekStreamKeepsRetryingWhileAnySnifferNeedsMoreData is the other half of the aggregation
// contract. The loop decides whether to read again from the aggregate, so a round is only allowed
// to end the sniff when no sniffer is still waiting for bytes - and the sniffer that was waiting
// has to see the whole cached payload again on the next round, not the remainder.
func TestPeekStreamKeepsRetryingWhileAnySnifferNeedsMoreData(t *testing.T) {
	t.Parallel()
	calls := 0
	var observed []int
	waiting := func(_ context.Context, _ *adapter.InboundContext, reader io.Reader) error {
		calls++
		payload, _ := io.ReadAll(reader)
		observed = append(observed, len(payload))
		if calls < 3 {
			return E.Cause1(sniff.ErrNeedMoreData, io.ErrUnexpectedEOF)
		}
		return nil
	}
	conn := &scriptedConn{chunks: [][]byte{{0x01}, {0x02}, {0x03}}}
	metadata := adapter.InboundContext{}
	sniffBuffer := buf.NewPacket()
	defer sniffBuffer.Release()
	err := sniff.PeekStream(context.Background(), &metadata, conn, nil, sniffBuffer, 0, waiting, func(_ context.Context, _ *adapter.InboundContext, _ io.Reader) error {
		return errFailureAbsent
	})
	require.NoError(t, err)
	require.Equal(t, 3, calls)
	// Every round re-parses the whole cached payload, never just the newest bytes.
	require.Equal(t, []int{1, 2, 3}, observed)
	require.ErrorIs(t, E.Cause1(sniff.ErrNeedMoreData, io.ErrUnexpectedEOF), sniff.ErrNeedMoreData)
}

// errNeedMoreDataImpostor carries the sentinel's message without wrapping the sentinel. Nothing in
// this package returns one; it exists because E.Errors de-duplicates by message, which makes it the
// single input shape where "does any constituent need more data" and "does the aggregate need more
// data" can disagree.
var errNeedMoreDataImpostor = errors.New("need more data")

// needMoreDataCorpus is every error shape the stream sniffers in this package can hand back, plus
// the two aggregate forms E.Errors itself produces. TestErrorsNeedMoreDataAgreesWithTheOrOfIts-
// Constituents checks the substitution PeekStream makes against all of them at once.
func needMoreDataCorpus() []error {
	return []error{
		nil,
		os.ErrInvalid,
		io.EOF,
		io.ErrUnexpectedEOF,
		sniff.ErrNeedMoreData,
		// What TLSClientHello, HTTPHost, StreamDomainNameQuery, BitTorrent and RDP return when the
		// payload is merely incomplete.
		E.Cause1(sniff.ErrNeedMoreData, io.ErrUnexpectedEOF),
		// A wrapped sentinel whose wrapper implements Unwrap() error rather than Unwrap() []error.
		E.Cause(sniff.ErrNeedMoreData, "stream"),
		// The standard-library wrapper, which keeps the message and adds a distinct value.
		fmt.Errorf("while sniffing: %w", sniff.ErrNeedMoreData),
		// A definite verdict, and the shape crypto/tls answers with.
		tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
		// A cause chain that does NOT carry the sentinel, in the Unwrap() []error shape that
		// E.Errors flattens.
		E.Cause1(os.ErrInvalid, io.EOF),
		// A nested aggregate, which E.Errors flattens rather than nests.
		E.Errors(errFailureOne, errFailureTwo),
		errFailureThree,
	}
}

// TestErrorsNeedMoreDataAgreesWithTheOrOfItsConstituents is the precondition §3.2 requires before
// PeekStream may decide its retry from the constituents instead of from the aggregate: it checks
//
//	errors.Is(E.Errors(errs...), ErrNeedMoreData) == any(errors.Is(err, ErrNeedMoreData) for err in errs)
//
// over every one of the 4096 subsets of the corpus above, rather than over a hand-picked few. The
// corpus is why the check is worth anything: it holds the exact error TLSClientHello returns for a
// truncated ClientHello, which is the value the whole retry loop exists for.
//
// The equivalence is not an accident of this corpus, and it is not unconditional either. Both
// directions of the argument are in the comment on PeekStream; the one input shape that breaks the
// converse is covered separately by
// TestPeekStreamNeedMoreDataImpostorReadsMoreRatherThanStopping.
func TestErrorsNeedMoreDataAgreesWithTheOrOfItsConstituents(t *testing.T) {
	t.Parallel()
	corpus := needMoreDataCorpus()
	checked := 0
	for mask := 0; mask < 1<<len(corpus); mask++ {
		subset := make([]error, 0, len(corpus))
		anyConstituent := false
		for index, candidate := range corpus {
			if mask&(1<<index) == 0 {
				continue
			}
			subset = append(subset, candidate)
			if errors.Is(candidate, sniff.ErrNeedMoreData) {
				anyConstituent = true
			}
		}
		require.Equal(t, anyConstituent, errors.Is(E.Errors(subset...), sniff.ErrNeedMoreData),
			"subset %d disagrees: E.Errors(%v)", mask, subset)
		checked++
	}
	require.Equal(t, 1<<len(corpus), checked)
	// A corpus that never matched the sentinel would make the loop above vacuous in one direction.
	require.True(t, errors.Is(E.Errors(corpus...), sniff.ErrNeedMoreData))
}

// TestPeekStreamOnlyOneSnifferNeedsMoreDataDrivesTheRetry covers the case the retry decision is
// really about: one parser asking for bytes is enough, even when every other parser has already
// answered with a definite verdict. The end of the loop is the same question - the aggregate must
// not report a need for more data once the parser that wanted it has been satisfied.
func TestPeekStreamOnlyOneSnifferNeedsMoreDataDrivesTheRetry(t *testing.T) {
	t.Parallel()
	calls := 0
	var sawPayload []int
	waiting := func(_ context.Context, _ *adapter.InboundContext, reader io.Reader) error {
		calls++
		payload, _ := io.ReadAll(reader)
		sawPayload = append(sawPayload, len(payload))
		if calls < 3 {
			return E.Cause1(sniff.ErrNeedMoreData, io.ErrUnexpectedEOF)
		}
		return nil
	}
	conn := &scriptedConn{chunks: [][]byte{{0x01}, {0x02}, {0x03}}}
	metadata := adapter.InboundContext{}
	sniffBuffer := buf.NewPacket()
	defer sniffBuffer.Release()
	// Five definite failures around the one parser that is still waiting. The failures must not
	// end the sniff and must not be mistaken for it.
	err := sniff.PeekStream(context.Background(), &metadata, conn, nil, sniffBuffer, 0,
		failingStreamSniffers([]error{errFailureOne, errFailureTwo})[0],
		failingStreamSniffers([]error{errFailureOne, errFailureTwo})[1],
		waiting,
		failingStreamSniffers([]error{errFailureThree, errFailureFour})[0],
		failingStreamSniffers([]error{errFailureThree, errFailureFour})[1],
	)
	require.NoError(t, err)
	require.Equal(t, 3, calls)
	require.Equal(t, []int{1, 2, 3}, sawPayload, "each round reparses the whole cached payload")
}

// TestPeekStreamRecognisesWrappedNeedMoreData pins the error inspectability the loop depends on.
// Every parser here returns E.Cause1(ErrNeedMoreData, cause), so the sentinel sits one Unwrap()
// hop down inside a value that is itself an Unwrap() []error; a loop that compared errors by
// identity, or that only looked at the first unwrapped error, would stop reading and lose every
// fragmented ClientHello. E.Cause and fmt.Errorf cover the two other wrapper shapes.
func TestPeekStreamRecognisesWrappedNeedMoreData(t *testing.T) {
	t.Parallel()
	for name, wrapped := range map[string]error{
		"cause1": E.Cause1(sniff.ErrNeedMoreData, io.ErrUnexpectedEOF),
		"cause":  E.Cause(sniff.ErrNeedMoreData, "wrap"),
		"errorf": fmt.Errorf("wrap: %w", sniff.ErrNeedMoreData),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			waiting := func(_ context.Context, _ *adapter.InboundContext, _ io.Reader) error {
				calls++
				if calls < 4 {
					return wrapped
				}
				return nil
			}
			conn := &scriptedConn{chunks: [][]byte{{0x01}, {0x02}, {0x03}, {0x04}}}
			metadata := adapter.InboundContext{}
			sniffBuffer := buf.NewPacket()
			defer sniffBuffer.Release()
			require.NoError(t, sniff.PeekStream(context.Background(), &metadata, conn, nil, sniffBuffer, 0, waiting))
			require.Equal(t, 4, calls)
		})
	}
}

// TestPeekStreamFragmentedClientHelloIsStillDetected is the end-to-end statement of the invariant
// the retry loop protects, driven through the real plan and a real ClientHello: whatever a round
// decides, the parser sees the whole cached payload again on the next round, and a ClientHello that
// arrives in eight pieces is recognised exactly like one that arrives whole.
func TestPeekStreamFragmentedClientHelloIsStillDetected(t *testing.T) {
	t.Parallel()
	hello := captureClientHello(t, &tls.Config{ServerName: "fragmented.example.com"})
	whole := adapter.InboundContext{}
	wholeBuffer := buf.NewPacket()
	defer wholeBuffer.Release()
	require.NoError(t, sniff.PeekStream(
		context.Background(), &whole,
		&scriptedConn{chunks: [][]byte{hello}},
		nil, wholeBuffer, 0, baselineStreamSniffers...,
	))
	require.Equal(t, "tls", whole.Protocol)
	require.Equal(t, "fragmented.example.com", whole.Domain)
	// Eight reads, and the payload only becomes parseable on the last one.
	for _, reads := range []int{2, 3, 5, 8} {
		conn := &scriptedConn{chunks: splitChunks(hello, reads)}
		metadata := adapter.InboundContext{}
		sniffBuffer := buf.NewPacket()
		err := sniff.PeekStream(context.Background(), &metadata, conn, nil, sniffBuffer, 0, baselineStreamSniffers...)
		require.NoError(t, err, "%d reads", reads)
		require.Equal(t, "tls", metadata.Protocol, "%d reads", reads)
		require.Equal(t, "fragmented.example.com", metadata.Domain, "%d reads", reads)
		require.LessOrEqual(t, conn.reads, reads+1, "%d reads", reads)
		sniffBuffer.Release()
	}
}

// TestPeekStreamFinalEOFAggregatesTheLastRoundsFailures is the termination path that does not go
// through the retry decision: the connection runs dry while a parser is still waiting. The error
// reported there is the previous round's aggregate, and it has to be the same value the loop would
// have returned before the aggregate was deferred - including the detail that it still reports
// ErrNeedMoreData, because that is what the last round's parsers said.
func TestPeekStreamFinalEOFAggregatesTheLastRoundsFailures(t *testing.T) {
	t.Parallel()
	failures := failureSentinels()
	waiting := func(_ context.Context, _ *adapter.InboundContext, _ io.Reader) error {
		return E.Cause1(sniff.ErrNeedMoreData, io.ErrUnexpectedEOF)
	}
	conn := &scriptedConn{chunks: [][]byte{{0x01, 0x02}}, terminal: io.EOF}
	metadata := adapter.InboundContext{}
	sniffBuffer := buf.NewPacket()
	defer sniffBuffer.Release()
	err := sniff.PeekStream(context.Background(), &metadata, conn, nil, sniffBuffer, 0,
		append(failingStreamSniffers(failures), waiting)...,
	)
	require.Error(t, err)
	for index, failure := range failures {
		require.ErrorIs(t, err, failure, "failure %d is missing from the aggregate", index)
	}
	require.ErrorIs(t, err, sniff.ErrNeedMoreData)
	// The same failures the pre-deferral loop aggregated, in the same order and shape.
	require.Equal(t,
		foldedFailureAggregate(append(append([]error{}, failures...), E.Cause1(sniff.ErrNeedMoreData, io.ErrUnexpectedEOF))).Error(),
		err.Error(),
	)
	require.Equal(t, 2, conn.reads, "one chunk, then the terminal error")
}

// TestPeekStreamNeedMoreDataImpostorReadsMoreRatherThanStopping pins the one input shape where
// deciding the retry from the constituents differs from deciding it from the aggregate, so that the
// difference is a documented property of this loop rather than a hazard waiting to be discovered.
//
// E.Errors de-duplicates by message and keeps the first of each, so a parser that returns an error
// whose text is exactly "need more data" without wrapping the sentinel can displace the real
// sentinel from the aggregate: the old predicate then read `false` and the sweep stopped with a
// verdict. The new predicate sees the other parser's wrapped sentinel and reads again.
//
// The divergence is deliberately in this direction. Reading again can only give a parser more of the
// same payload it already reparses from offset zero; it can never turn a recognised flow into an
// unrecognised one, which is the failure mode a retry decision is allowed to have.
func TestPeekStreamNeedMoreDataImpostorReadsMoreRatherThanStopping(t *testing.T) {
	t.Parallel()
	impostor := func(_ context.Context, _ *adapter.InboundContext, _ io.Reader) error {
		return errNeedMoreDataImpostor
	}
	calls := 0
	waiting := func(_ context.Context, metadata *adapter.InboundContext, _ io.Reader) error {
		calls++
		if calls < 2 {
			return E.Cause1(sniff.ErrNeedMoreData, io.ErrUnexpectedEOF)
		}
		metadata.Protocol = "second-round"
		return nil
	}
	conn := &scriptedConn{chunks: [][]byte{{0x01}, {0x02}}}
	metadata := adapter.InboundContext{}
	sniffBuffer := buf.NewPacket()
	defer sniffBuffer.Release()
	require.NoError(t, sniff.PeekStream(context.Background(), &metadata, conn, nil, sniffBuffer, 0, impostor, waiting))
	require.Equal(t, "second-round", metadata.Protocol)
	require.Equal(t, 2, calls)
	// The old predicate, spelled out, is why this shape had to be pinned: the impostor's message
	// wins de-duplication and the wrapped sentinel never reaches the aggregate.
	require.False(t, errors.Is(E.Errors(errNeedMoreDataImpostor, E.Cause1(sniff.ErrNeedMoreData, io.ErrUnexpectedEOF)), sniff.ErrNeedMoreData))
	// The new predicate asks each constituent, so the wrapped sentinel is still visible.
	require.True(t, errors.Is(E.Cause1(sniff.ErrNeedMoreData, io.ErrUnexpectedEOF), sniff.ErrNeedMoreData))
}
