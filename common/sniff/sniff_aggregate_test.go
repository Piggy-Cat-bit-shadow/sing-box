package sniff_test

import (
	"context"
	"errors"
	"io"
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
