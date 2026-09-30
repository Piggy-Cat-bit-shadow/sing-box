//go:build with_quic

package v2rayquic

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
)

// TestAcceptLoopFailureClassification pins the accept loop's log decision.
//
// streamAcceptLoop returns qtls.WrapError(err) from conn.AcceptStream, and the accept goroutine
// logs it unless the generic closed/canceled test recognises it. Every quic-go error type unwraps
// to net.ErrClosed whatever its code is, so relying on that test alone reports a protocol fault
// as an ordinary teardown.
//
// shouldLog performs the production decision: classify with asVisibleFault, then apply the
// generic closed/canceled test the accept loop uses.
func shouldLog(err error) bool {
	if err == nil {
		return false
	}
	classified := asVisibleFault(err)
	return !E.IsClosedOrCanceled(classified)
}

func TestAcceptLoopFailureClassification(t *testing.T) {
	t.Parallel()

	expected := []struct {
		name string
		err  error
	}{
		{"context canceled", context.Canceled},
		{"orderly transport close", &quic.TransportError{ErrorCode: quic.NoError}},
		{"orderly application close", &quic.ApplicationError{ErrorCode: 0}},
		{"idle timeout", &quic.IdleTimeoutError{}},
		{"handshake timeout", &quic.HandshakeTimeoutError{}},
		// NOTE: a StreamError is deliberately absent from this table. conn.AcceptStream reports
		// CONNECTION-level errors only; a stream reset never reaches the accept loop, so listing
		// one here would assert a path that cannot occur.
	}
	for _, testCase := range expected {
		t.Run("quiet/"+testCase.name, func(t *testing.T) {
			if shouldLog(testCase.err) {
				t.Fatalf("an expected closure must not be logged as a fault: %v", testCase.err)
			}
		})
	}

	// Every entry here is a shape conn.AcceptStream can actually return on this path. A
	// *quic.StreamError is deliberately absent -- see TestAcceptStreamFaultSurface below for why,
	// and for the helper-level coverage that input would give.
	faults := []struct {
		name string
		err  error
	}{
		{"transport protocol violation", &quic.TransportError{ErrorCode: 0xa}},
		{"transport frame encoding error", &quic.TransportError{ErrorCode: 0x7}},
		{"application error with a fault code", &quic.ApplicationError{ErrorCode: 0x102}},
		{"stateless reset", &quic.StatelessResetError{}},
		{"version negotiation failure", &quic.VersionNegotiationError{}},
		{"plain unknown error", errors.New("boom")},
	}
	for _, testCase := range faults {
		t.Run("visible/"+testCase.name, func(t *testing.T) {
			if !shouldLog(testCase.err) {
				t.Fatalf("a real accept-loop fault must be logged: %v", testCase.err)
			}
			// The production path carries the qtls-wrapped spelling, because streamAcceptLoop
			// returns qtls.WrapError(err). Classifying only the raw error would leave the real
			// path untested.
			wrapped := qtls.WrapError(testCase.err)
			if !shouldLog(wrapped) {
				t.Fatalf("the wrapped spelling must also be logged: %v", wrapped)
			}
			// Report which cases the generic test alone would have silenced; those are the ones
			// that actually needed the wrapper.
			if E.IsClosedOrCanceled(testCase.err) {
				t.Logf("%s: the generic closed/canceled test alone would have silenced this "+
					"fault; the wrapper is what keeps it visible", testCase.name)
			}
		})
	}
}

// TestAcceptStreamFaultSurface records the contract this test file relies on, and keeps the
// helper-level coverage for a shape the accept loop cannot receive.
//
// # Why *quic.StreamError is NOT in the accept-loop table
//
// conn.AcceptStream, via incomingStreamsMap.AcceptStream, can return exactly three things:
//
//  1. m.closeErr -- the CONNECTION-level error set by CloseWithError, which is what
//     destroyImpl fans out on teardown. That is a TransportError, ApplicationError,
//     StatelessResetError, VersionNegotiationError, IdleTimeoutError or HandshakeTimeoutError.
//  2. ctx.Err() when the accept context is done.
//  3. an error from deleteStream, which is a plain fmt.Errorf.
//
// A *quic.StreamError is never among them: it describes ONE reset stream, and the accept loop is
// reading the stream MAP, not an individual stream. Asserting it in the accept-loop table would
// mean proving the production path is fixed using an input that path cannot receive.
//
// The helper is still exercised for a stream reset below, so a change in asVisibleFault's
// treatment of that type is still caught -- it is simply labelled as what it is.
func TestAcceptStreamFaultSurface(t *testing.T) {
	t.Parallel()

	// Helper-level only: NOT REACHABLE FROM THE AcceptStream PATH.
	t.Run("helper/stream error is handled even though AcceptStream cannot return one", func(t *testing.T) {
		streamFault := &quic.StreamError{
			ErrorCode: quic.StreamErrorCode(http3.ErrCodeInternalError),
			Remote:    true,
		}
		if !shouldLog(streamFault) {
			t.Fatalf("the helper must still treat a stream fault as visible: %v", streamFault)
		}
		// A zero-code reset is classified as an orderly end by isExpectedQuicClosure, but the
		// accept loop would still log it: a *quic.StreamError does not unwrap to net.ErrClosed,
		// so the generic test applied afterwards answers false. That is pre-existing upstream
		// behaviour and it is UNREACHABLE here, because AcceptStream never returns a StreamError.
		// Recorded rather than "fixed", because changing it would be an unrequested behaviour
		// change on a path no shipped binary can enter.
		orderly := &quic.StreamError{ErrorCode: 0, Remote: false}
		if !isExpectedQuicClosure(orderly) {
			t.Fatalf("a zero-code reset must be classified as an orderly end: %v", orderly)
		}
		if !E.IsClosedOrCanceled(orderly) {
			t.Logf("note: %v is classified as orderly but does not satisfy the generic "+
				"closed/canceled test; the accept loop would log it. Unreachable from "+
				"AcceptStream, so left as upstream behaviour.", orderly)
		}
	})
}

// TestVisibleFaultHidesTheSentinel proves the wrapper does not leak net.ErrClosed.
func TestVisibleFaultHidesTheSentinel(t *testing.T) {
	t.Parallel()

	fault := &quic.TransportError{ErrorCode: 0xa}
	if !errors.Is(fault, net.ErrClosed) {
		t.Fatal("premise: a transport fault is expected to unwrap to net.ErrClosed")
	}
	wrapped := asVisibleFault(fault)
	if errors.Is(wrapped, net.ErrClosed) {
		t.Fatal("a visible fault must not satisfy net.ErrClosed, or the accept loop silences it")
	}
	// errors.As must not reach the quic-go type either, because that traversal is the second
	// path by which the sentinel leaked in.
	var back *quic.TransportError
	if errors.As(wrapped, &back) {
		t.Fatal("a visible fault must not expose the quic-go type through errors.As")
	}
	var visible *visibleFault
	if !errors.As(wrapped, &visible) || visible.Cause() == nil {
		t.Fatal("the original error must stay reachable through Cause()")
	}
	if visible.Error() != fault.Error() {
		t.Fatalf("the message must be preserved: got %q, want %q", visible.Error(), fault.Error())
	}
}

// TestVisibleFaultErrorsAsContract pins the deliberate compatibility change.
//
// errors.As cannot reach the quic-go type through a visibleFault, because the only traversal that
// would get there is Unwrap, and that is also the second path by which net.ErrClosed leaks back in
// and re-silences the fault. The two cannot both be satisfied, so diagnostic access is offered
// through Cause() instead.
//
// This is asserted rather than left implicit so a future edit that adds Unwrap -- the obvious way
// to "fix" errors.As -- is caught immediately.
func TestVisibleFaultErrorsAsContract(t *testing.T) {
	t.Parallel()

	fault := &quic.TransportError{ErrorCode: 0xa, ErrorMessage: "PROTOCOL_VIOLATION"}
	wrapped := asVisibleFault(fault)

	var visible *visibleFault
	if !errors.As(wrapped, &visible) {
		t.Fatal("the wrapper itself must be reachable so a caller can read Cause()")
	}
	if visible.Cause() == nil {
		t.Fatal("Cause() must expose the original error")
	}
	if visible.Cause().Error() != fault.Error() {
		t.Fatalf("Cause() must preserve the message: got %q, want %q",
			visible.Cause().Error(), fault.Error())
	}

	// The blocked traversal, stated explicitly.
	var transportErr *quic.TransportError
	if errors.As(wrapped, &transportErr) {
		t.Fatal("errors.As must NOT reach the quic-go type: that traversal is the same one that " +
			"lets net.ErrClosed back in, and adding Unwrap to satisfy it would re-break the fault " +
			"visibility this wrapper exists to provide")
	}
	var statelessErr *quic.StatelessResetError
	var versionErr *quic.VersionNegotiationError
	if errors.As(wrapped, &statelessErr) || errors.As(wrapped, &versionErr) {
		t.Fatal("no quic-go type may be reachable through a visibleFault")
	}

	// And the sentinel stays blocked, which is the property the above protects.
	if errors.Is(wrapped, net.ErrClosed) {
		t.Fatal("a visible fault must not satisfy net.ErrClosed")
	}
}
