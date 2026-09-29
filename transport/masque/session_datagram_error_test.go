//go:build with_quic

package masque

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	transportHTTP "github.com/sagernet/sing-box/transport/http"

	"github.com/stretchr/testify/require"
)

// Tests for the datagram-error classification on the packet path.
//
// # Why this is worth a dedicated test
//
// The classifier exists for a performance reason that is invisible in its behaviour: errors.As
// takes the address of its target, which forces that target to the heap on EVERY call, including
// the calls where err is nil. Writing the obvious version therefore adds one heap allocation per
// successfully sent packet, and nothing about the code looks wrong.
//
// So there are two things to protect, and they pull in opposite directions:
//
//  1. the classification must stay correct, including for a WRAPPED too-large error -- the case a
//     fast type assertion alone would miss;
//  2. the success path must stay allocation-free, which is what the direct type assertion buys.
//
// A future change that simplified the classifier back to a bare errors.As would pass (1) and fail
// (2) silently. The allocation test below is what makes that visible.

// TestClassifyDatagramErrorMatchesErrorsAsSemantics pins the classification against the result the
// straightforward errors.As/errors.Is implementation would produce.
//
// It compares against a local reference implementation rather than against literal expected values,
// so the test states the CONTRACT ("agrees with the obvious classifier") instead of restating this
// implementation's own constants.
func TestClassifyDatagramErrorMatchesErrorsAsSemantics(t *testing.T) {
	t.Parallel()

	tooLarge := &transportHTTP.DatagramTooLargeError{MaxPayloadSize: 1300}

	reference := func(err error) (datagramErrorKind, int) {
		if err == nil {
			return datagramErrorOther, 0
		}
		var target *transportHTTP.DatagramTooLargeError
		switch {
		case errors.As(err, &target):
			return datagramErrorTooLarge, target.MaxPayloadSize
		case errors.Is(err, transportHTTP.ErrDatagramUnsupported):
			return datagramErrorUnsupported, 0
		}
		return datagramErrorOther, 0
	}

	for _, testCase := range []struct {
		name string
		err  error
	}{
		{name: "nil", err: nil},
		{name: "too large, unwrapped", err: tooLarge},
		{name: "too large, wrapped", err: fmt.Errorf("send datagram: %w", tooLarge)},
		{name: "too large, wrapped twice", err: fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", tooLarge))},
		{name: "unsupported, unwrapped", err: transportHTTP.ErrDatagramUnsupported},
		{name: "unsupported, wrapped", err: fmt.Errorf("send datagram: %w", transportHTTP.ErrDatagramUnsupported)},
		{name: "unrelated", err: errors.New("connection closed")},
		{name: "unrelated wrapped", err: fmt.Errorf("outer: %w", errors.New("connection closed"))},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			expectedKind, expectedSize := reference(testCase.err)
			kind, size := classifyDatagramError(testCase.err)
			require.Equal(t, expectedKind, kind,
				"classification of %v must agree with the straightforward errors.As implementation",
				testCase.err)
			require.Equal(t, expectedSize, size)
		})
	}
}

// TestClassifyDatagramErrorCarriesThePayloadCeiling proves the size travels with the
// classification.
//
// The caller derives the reported MTU from this value by subtracting the context ID, so losing it
// would degrade every Packet Too Big into a wrong or missing MTU rather than into an obvious
// failure.
func TestClassifyDatagramErrorCarriesThePayloadCeiling(t *testing.T) {
	t.Parallel()

	kind, size := classifyDatagramError(&transportHTTP.DatagramTooLargeError{MaxPayloadSize: 1234})
	require.Equal(t, datagramErrorTooLarge, kind)
	require.Equal(t, 1234, size)

	// And through a wrapper, which is the path the direct assertion cannot take.
	kind, size = classifyDatagramError(fmt.Errorf("wrapped: %w",
		&transportHTTP.DatagramTooLargeError{MaxPayloadSize: 999}))
	require.Equal(t, datagramErrorTooLarge, kind)
	require.Equal(t, 999, size)
}

// TestDatagramErrorClassificationDoesNotAllocateOnSuccess is the performance contract.
//
// It asserts what the code structure exists to guarantee: deciding that a nil error needs no
// special handling must not touch the heap. If someone reintroduces an unconditional errors.As,
// this fails while every correctness test above still passes -- which is precisely the failure mode
// this test exists to catch.
func TestDatagramErrorClassificationDoesNotAllocateOnSuccess(t *testing.T) {
	// Not parallel: it measures allocations, and a parallel test body would add noise from the
	// testing framework's own bookkeeping.
	kind, size := classifyDatagramError(nil)
	require.Equal(t, datagramErrorOther, kind)
	require.Equal(t, 0, size)

	allocations := testing.AllocsPerRun(1000, func() {
		_, _ = classifyDatagramError(nil)
	})
	require.Zero(t, allocations,
		"classifying a successful send must not allocate: an unconditional errors.As moves its "+
			"target to the heap on every call and costs one allocation per packet")
}

// TestWritePacketsAllocatesNothingBeyondTheBufferWrapper pins the per-packet allocation budget of
// the datagram fast path, and says exactly what that budget IS rather than pretending it is zero.
//
// # The one allocation that is real
//
// Sending a packet costs exactly ONE small allocation: the *buf.Buffer wrapper. The wrapper is 56
// bytes, it is returned by value from the pool, and it lands on the heap as soon as a caller holds
// a pointer to it -- which is what the API is for. No change in this package can remove it, so a
// test asserting zero would be asserting something false and would be deleted the first time
// somebody looked at it properly.
//
// What the pool DOES avoid, and what must stay avoided, is allocating the PAYLOAD. A missed pool
// recycle, a defensive copy, or a headroom reallocation would each add a second allocation
// proportional to packet size.
//
// # Why the assertion is on the COUNT and not on bytes
//
// An earlier version of this test compared B/op between a 64-byte and a 1280-byte packet and
// asserted the difference stayed small. That test could not fail: the batch is reused across
// iterations, so by the time the payload allocation happens the pool is already drained and the
// measured bytes stayed at the wrapper size. Injecting a real `copy` of the payload moved
// allocs/op from 1 to 2 while barely moving B/op -- so the count is the axis that actually
// detects the regression, and it is the one used here.
//
// The injected-copy experiment is the evidence for that choice, and it is recorded because the
// wrong version of this test looked perfectly reasonable.
func TestWritePacketsAllocatesNothingBeyondTheBufferWrapper(t *testing.T) {
	packet := buildBenchIPv4Packet(1280, 6,
		netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"))

	current := benchSession(&benchDatagramSink{}, &benchDiscardStream{}, &benchHandler{})
	prebuilt := newBenchPacketBuffers(1, packet)

	result := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := current.writePackets(prebuilt); err != nil {
				b.Fatal(err)
			}
		}
	})

	require.Equal(t, int64(1), result.AllocsPerOp(),
		"a single-packet write must cost exactly the buffer wrapper allocation; 2 means something on "+
			"the path is allocating per packet (a payload copy, a headroom reallocation, or an "+
			"errors.As target), and %.0f B/op", float64(result.AllocedBytesPerOp()))
}

// TestClassifyDatagramErrorAllocationIsNotPerPacketIsDocumentedByTheTestAbove ties the two
// contracts together explicitly.
//
// The classifier's own allocation behaviour is covered by
// TestDatagramErrorClassificationDoesNotAllocateOnSuccess, and the aggregate per-packet budget by
// the test above. This one exists so that a reader who finds only ONE of them understands they are
// two halves of the same guarantee: the classifier must not allocate on success (its own test), and
// nothing else on the path may either (the aggregate test).
func TestClassifyDatagramErrorAllocationIsNotPerPacketIsDocumentedByTheTestAbove(t *testing.T) {
	// A non-nil error IS allowed to allocate: it is the failure path, and errors.As is used there
	// deliberately so a wrapped too-large error is still classified.
	_, _ = classifyDatagramError(&transportHTTP.DatagramTooLargeError{MaxPayloadSize: 1300})

	// The success path must not, which is the property the packet path depends on.
	require.Zero(t, testing.AllocsPerRun(1000, func() {
		_, _ = classifyDatagramError(nil)
	}))
}
