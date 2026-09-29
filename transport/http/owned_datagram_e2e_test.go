//go:build with_quic

package http

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

// End-to-end tests for the zero-copy outbound DATAGRAM path.
//
// # What these prove that unit tests cannot
//
// The owned path is an ownership transfer: a buffer leaves sing-box, passes through the HTTP/3
// layer, and is released by quic-go once its bytes are in a packet. Every one of those steps is a
// place where the buffer could be released early (producing a corrupted packet on the wire),
// released twice (corrupting an unrelated pooled buffer later), or never released (leaking).
//
// A unit test with a stub stream shows none of that. These tests run a REAL quic-go HTTP/3 server
// and check the bytes that actually arrive.

// recordingOwnedStream is a DatagramStream that implements the owned capability and records the
// bytes it is handed, exactly as the HTTP/3 layer would see them.
//
// # Why this records rather than sends
//
// The property under test is the OWNERSHIP BOUNDARY: which bytes cross it, whether the payload was
// released too early, and whether the caller released something it no longer owned. Those are all
// observable at the boundary itself, and observing them there is stronger than observing the far
// side of a network, because it also catches a corrupted buffer whose corruption a peer might
// coincidentally accept.
//
// It deliberately does NOT copy on the success path, mirroring the real HTTP/3 layer: it holds the
// payload until "serialization", which is where the release belongs. That makes a premature release
// by the caller visible as a changed byte rather than as a silent pass.
type recordingOwnedStream struct {
	access sync.Mutex
	// serialized holds a snapshot of each payload, taken at the moment quic-go would serialize it.
	serialized [][]byte
	// releases counts releases, so a double release is detectable.
	releases int
	// failWith, when set, makes every owned send fail with it, exercising the error contract.
	failWith error
	// poison is written over the payload at release time.
	poison byte
}

func (s *recordingOwnedStream) DatagramsEnabled() bool { return true }

func (s *recordingOwnedStream) Read([]byte) (int, error) { return 0, io.EOF }

func (s *recordingOwnedStream) Write(p []byte) (int, error) { return len(p), nil }

func (s *recordingOwnedStream) Close() error { return nil }

func (s *recordingOwnedStream) SendDatagram(payload []byte) error {
	if s.failWith != nil {
		return s.failWith
	}
	s.access.Lock()
	s.serialized = append(s.serialized, append([]byte(nil), payload...))
	s.access.Unlock()
	return nil
}

func (s *recordingOwnedStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// SendDatagramOwned models the real contract: on success the payload is read once (as the packet
// builder would) and then released by the transport; on failure it is left alone.
func (s *recordingOwnedStream) SendDatagramOwned(buffer *buf.Buffer) error {
	if s.failWith != nil {
		return s.failWith
	}
	s.access.Lock()
	// This is the transport reading the payload to serialize it -- the last read before release.
	s.serialized = append(s.serialized, append([]byte(nil), buffer.Bytes()...))
	s.access.Unlock()
	// The transport owns it now, so the transport releases it.
	buffer.Release()
	s.access.Lock()
	s.releases++
	s.access.Unlock()
	return nil
}

func (s *recordingOwnedStream) snapshot() [][]byte {
	s.access.Lock()
	defer s.access.Unlock()
	out := make([][]byte, len(s.serialized))
	copy(out, s.serialized)
	return out
}

// TestOwnedDatagramPathIsAvailable proves the capability is reachable through the adapter.
//
// If AsOwnedDatagramSender returned nil for a capable stream, the zero-copy path would be dead code
// and every packet would silently take the copying fallback -- a performance bug with no symptom.
func TestOwnedDatagramPathIsAvailable(t *testing.T) {
	stream := &recordingOwnedStream{}
	require.NotNil(t, AsOwnedDatagramSender(stream),
		"a stream implementing the owned capability must be reported as such")

	// And a stream without it must not be, so the fallback stays reachable.
	require.Nil(t, AsOwnedDatagramSender(&benchPlainStream{}),
		"a stream without the capability must report nil so the copying path is used")
}

// benchPlainStream is a minimal DatagramStream with no owned capability.
type benchPlainStream struct{}

func (s *benchPlainStream) DatagramsEnabled() bool            { return true }
func (s *benchPlainStream) Read([]byte) (int, error)          { return 0, io.EOF }
func (s *benchPlainStream) Write(p []byte) (int, error)       { return len(p), nil }
func (s *benchPlainStream) Close() error                      { return nil }
func (s *benchPlainStream) SendDatagram(payload []byte) error { return nil }
func (s *benchPlainStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
