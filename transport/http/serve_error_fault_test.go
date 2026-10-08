//go:build with_quic

package http

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/sagernet/quic-go"

	"github.com/stretchr/testify/require"
)

// A QUIC fault must not be silenced by the generic closed/canceled test.
//
// # The failure this pins
//
// quic-go's TransportError.Unwrap() returns net.ErrClosed next to the real cause. That makes
// "errors.Is(err, net.ErrClosed)" true for EVERY transport error, so a condition that tests
// closed-ness before the typed classifier reports an orderly shutdown for a protocol violation
// as well. The HTTP/3 server's shutdown path had exactly that order, which meant
// PROTOCOL_VIOLATION and FRAME_ENCODING_ERROR - the two errors an operator most needs to see -
// were never logged. The rule this restores is the one stated on IsExpectedH3Closure: the typed
// classification decides first, and the generic sentinels are only a fallback.
func TestServeErrorIsAFaultKeepsQuicFaultsVisible(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		err         error
		wantIsFault bool
	}{
		{
			name:        "nil",
			err:         nil,
			wantIsFault: false,
		},
		{
			name:        "orderly close",
			err:         net.ErrClosed,
			wantIsFault: false,
		},
		{
			name:        "eof",
			err:         io.EOF,
			wantIsFault: false,
		},
		{
			name:        "quic application close without error",
			err:         &quic.ApplicationError{ErrorCode: 0},
			wantIsFault: false,
		},
		{
			name:        "quic protocol violation",
			err:         &quic.TransportError{ErrorCode: quic.ProtocolViolation},
			wantIsFault: true,
		},
		{
			name:        "quic frame encoding error",
			err:         &quic.TransportError{ErrorCode: quic.FrameEncodingError},
			wantIsFault: true,
		},
		{
			name:        "quic stateless reset",
			err:         &quic.StatelessResetError{},
			wantIsFault: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			// The precondition that made the old condition wrong: a plain closed test calls a
			// transport fault "closed" too.
			if transportErr, isTransportError := testCase.err.(*quic.TransportError); isTransportError {
				require.ErrorIs(t, transportErr, net.ErrClosed,
					"precondition: quic transport errors unwrap to net.ErrClosed")
			}
			require.Equal(t, testCase.wantIsFault, serveErrorIsAFault(testCase.err))
		})
	}
}

// The typed classifier and the fault decision must agree, so a change to one without the other
// fails here rather than in a log review.
func TestServeErrorIsAFaultMatchesTypedClassification(t *testing.T) {
	t.Parallel()

	for _, err := range []error{
		&quic.TransportError{ErrorCode: quic.ProtocolViolation},
		&quic.TransportError{ErrorCode: quic.NoError},
		&quic.ApplicationError{ErrorCode: 0x10c},
		errors.New("plain error"),
		net.ErrClosed,
	} {
		if CarriesQuicSemantics(err) {
			require.Equal(t, !IsExpectedH3Closure(err), serveErrorIsAFault(err),
				"an error with quic semantics must be decided by the typed classifier alone: %v", err)
		}
	}
}
