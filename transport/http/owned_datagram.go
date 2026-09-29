//go:build with_quic

package http

import (
	"github.com/sagernet/sing/common/buf"

	"github.com/sagernet/quic-go/http3"
)

// The zero-copy outbound DATAGRAM path.
//
// # The two copies this removes
//
// Sending one CONNECT-IP packet over HTTP Datagrams used to cost two full-payload copies inside
// quic-go, on top of nothing this repository did:
//
//	http3:  data := make([]byte, 0, len(b)+8); append(id); append(b...)   // a packet-sized alloc + copy
//	quic:   f.Data = make([]byte, len(p)); copy(f.Data, p)                // another packet-sized copy
//
// Both are addressed in the quic-go fork by an additive owned-datagram API. What remains here is
// the ADAPTER that lets a sing-box *buf.Buffer satisfy the http3 ownership interface without either
// side learning about the other: http3 must not import sing/common/buf, and this package must not
// reimplement HTTP/3 framing.
//
// # Why the adapter is not merely a convenience
//
// *buf.Buffer already has the exact shape the owned path needs -- Bytes, ExtendHeader, Advance,
// Release -- so the adapter is a rename and nothing else. It deliberately does NOT copy, does not
// allocate a packet-sized object, and holds no state beyond the pointer.

// ownedBuffer adapts *buf.Buffer to the ownership interface the HTTP/3 owned datagram path expects.
//
// It is a value type holding one pointer, so it stays on the stack: the whole point of this path is
// to avoid per-packet allocation, and an adapter that itself escaped would give much of that back.
type ownedBuffer struct {
	buffer *buf.Buffer
}

// Prepend reserves n bytes in front of the payload and returns them for writing.
//
// It returns nil when the buffer has no room, which is the signal the HTTP/3 layer uses to fall back
// to its copying path. Reporting that honestly matters more than avoiding the fallback: a buffer
// that cannot hold the prefix must not have it written anyway.
func (o ownedBuffer) Prepend(n int) []byte {
	if o.buffer.Start() < n {
		return nil
	}
	return o.buffer.ExtendHeader(n)
}

// Advance shrinks the payload from the front, undoing a Prepend.
//
// The HTTP/3 layer calls this when a send fails, so the caller gets its buffer back exactly as it
// handed it over -- which is what the PTB and capsule-fallback paths depend on.
func (o ownedBuffer) Advance(n int) { o.buffer.Advance(n) }

// Bytes returns the current payload.
func (o ownedBuffer) Bytes() []byte { return o.buffer.Bytes() }

// Release returns the buffer to its pool.
//
// It runs exactly once, from quic-go, after the payload has been copied into an outgoing QUIC
// packet. It is the ONLY release on this path: the caller must not also release, which is the
// contract SendDatagramOwned documents.
func (o ownedBuffer) Release() {
	if o.buffer != nil {
		o.buffer.Release()
	}
}

// OwnedDatagramSender is the OPTIONAL capability of a DatagramStream that can take ownership of a
// datagram payload instead of copying it.
//
// # Why it is optional rather than part of DatagramStream
//
// DatagramStream has implementers outside this package -- test doubles, other transports, and the
// HTTP/2 fallback -- and widening it would force every one of them to grow a method most cannot
// implement meaningfully. Callers therefore type-assert for this capability and keep the copying
// path otherwise, which also means a stream that cannot do it degrades silently and safely rather
// than failing.
type OwnedDatagramSender interface {
	// SendDatagramOwned sends the datagram while transferring ownership of buffer.
	//
	// On a nil return the callee owns buffer and will release it exactly once; the caller MUST NOT
	// touch it again. On error the caller still owns buffer, with its bytes exactly as passed in.
	SendDatagramOwned(buffer *buf.Buffer) error
}

// h3OwnedDatagramStream is implemented by the HTTP/3 datagram stream.
type h3OwnedDatagramStream interface {
	SendDatagramOwned(payload http3.OwnedDatagramPayload) error
}

// AsOwnedDatagramSender reports the owned-send capability of a datagram stream, or nil when the
// stream cannot take ownership.
//
// Callers are expected to resolve this ONCE when a session is established and keep the result,
// because the capability cannot change while the connection lives and the packet path may not pay
// for a type assertion on every packet.
func AsOwnedDatagramSender(stream DatagramStream) OwnedDatagramSender {
	// A stream may already speak the sing-box owned interface directly. That is what test doubles
	// and any future non-HTTP/3 implementation use, and checking it first keeps those from having to
	// imitate the http3 interface.
	if sender, ok := stream.(OwnedDatagramSender); ok {
		return sender
	}
	if sender, ok := stream.(h3OwnedDatagramStream); ok {
		return ownedH3Sender{sender: sender}
	}
	return nil
}

// ownedH3Sender forwards a *buf.Buffer to the HTTP/3 owned path through the adapter.
type ownedH3Sender struct {
	sender h3OwnedDatagramStream
}

func (s ownedH3Sender) SendDatagramOwned(buffer *buf.Buffer) error {
	return s.sender.SendDatagramOwned(ownedBuffer{buffer: buffer})
}
