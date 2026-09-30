//go:build with_quic

package v2rayquic

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
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

	faults := []struct {
		name string
		err  error
	}{
		{"transport protocol violation", &quic.TransportError{ErrorCode: 0xa}},
		{"transport frame encoding error", &quic.TransportError{ErrorCode: 0x7}},
		{"application error with a fault code", &quic.ApplicationError{ErrorCode: 0x102}},
		{"stream internal error", &quic.StreamError{ErrorCode: quic.StreamErrorCode(http3.ErrCodeInternalError)}},
		{"plain unknown error", errors.New("boom")},
	}
	for _, testCase := range faults {
		t.Run("visible/"+testCase.name, func(t *testing.T) {
			if !shouldLog(testCase.err) {
				t.Fatalf("a real accept-loop fault must be logged: %v", testCase.err)
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
