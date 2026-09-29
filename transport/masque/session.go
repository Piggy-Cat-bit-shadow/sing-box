package masque

import (
	std_bufio "bufio"
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	upgradeToken       = "connect-ip"
	DefaultMTU         = 1280
	PacketHeadroom     = transportHTTP.CapsuleHeadroom
	QUICPacketOverhead = 51
	minimumLinkMTU     = 1280
	// maxPacketSize bounds one MASQUE inner IP packet.
	//
	// IPv4 Total Length counts the whole packet, so the largest ordinary IPv4 packet is
	// 65535. IPv6 Payload Length excludes the 40-byte base header (RFC 8200 section 3),
	// so the largest ordinary IPv6 packet is 40 + 65535. Jumbograms are not supported.
	maxPacketSize = 40 + 65535
)

type sessionHandler interface {
	handleAddressAssign(addresses []AssignedAddress) error
	handleAddressRequest(addresses []AssignedAddress) error
	handleRouteAdvertisement(routes []AddressRange) error
	// handleDNSAssign receives a validated DNS configuration. Each capsule SUPERSEDES
	// the previous one rather than appending, per draft-ietf-masque-connect-ip-dns-06
	// §3.4; the handler is responsible for replacing its state accordingly.
	handleDNSAssign(configurations []DNSConfiguration) error
	// handlePREF64 receives NAT64 prefixes, or none when the capsule is empty. An
	// empty capsule INVALIDATES previously received prefixes (§4.2), so an empty slice
	// is a meaningful instruction and not a no-op.
	handlePREF64(prefixes []netip.Prefix) error
	handlePacket(buffer *buf.Buffer)
	handlePacketTooBig(buffer *buf.Buffer, mtu int)
}

type session struct {
	ctx            context.Context
	cancel         context.CancelCauseFunc
	stream         io.ReadWriteCloser
	datagrams      transportHTTP.DatagramStream
	reader         *std_bufio.Reader
	handler        sessionHandler
	packetHeadroom func() int
	writeAccess    sync.Mutex
}

func newSession(ctx context.Context, stream io.ReadWriteCloser, handler sessionHandler, packetHeadroom func() int) *session {
	sessionCtx, cancel := context.WithCancelCause(ctx)
	// The datagram view is taken only when the peer actually negotiated HTTP Datagrams,
	// so the session records the capability instead of re-deriving it from a type
	// assertion that cannot express it. A stream that does not report it is treated as
	// incapable, which is the safe default: the capsule path always works.
	var datagrams transportHTTP.DatagramStream
	if capable, isDatagramStream := stream.(transportHTTP.DatagramStream); isDatagramStream && capable.DatagramsEnabled() {
		datagrams = capable
	}
	current := &session{
		ctx:            sessionCtx,
		cancel:         cancel,
		stream:         stream,
		datagrams:      datagrams,
		reader:         std_bufio.NewReader(stream),
		handler:        handler,
		packetHeadroom: packetHeadroom,
	}
	return current
}

func (s *session) run() error {
	stop := context.AfterFunc(s.ctx, func() {
		s.stream.Close()
	})
	defer stop()
	var loops sync.WaitGroup
	if s.datagrams != nil {
		loops.Go(s.loopDatagram)
	}
	err := s.loopCapsule()
	s.cancel(err)
	s.stream.Close()
	loops.Wait()
	return context.Cause(s.ctx)
}

func (s *session) loopDatagram() {
	for {
		datagram, err := s.datagrams.ReceiveDatagram(s.ctx)
		if err != nil {
			s.cancel(err)
			return
		}
		contextID, contextLength, valid := transportHTTP.DecodeVarint(datagram)
		if !valid || contextID != 0 || len(datagram) == contextLength {
			continue
		}
		s.handleIngressDatagram(datagram[contextLength:])
	}
}

// handleIngressDatagram delivers one received HTTP/3 datagram payload to the
// handler.
//
// # Ownership, stated explicitly
//
// The buffer WRAPS the slice quic-go returned; it does not copy it. That is only
// valid because of a property of the pinned quic-go (v0.61.0-sing-box-mod.7) that
// was verified in the source rather than assumed:
//
//	datagram_queue.go HandleDatagramFrame:
//	    data := make([]byte, len(f.Data))
//	    copy(data, f.Data)
//	    h.rcvQueue = append(h.rcvQueue, data)
//	datagram_queue.go Receive:
//	    data := h.rcvQueue[0]
//	    h.rcvQueue = h.rcvQueue[1:]
//	    return data
//
// So the returned slice is an INDEPENDENT per-datagram allocation, the receive
// queue drops its own reference before handing it back, and the backing array is
// never reused by the transport. Nothing else holds a reference to it once
// ReceiveDatagram returns.
//
// # Who owns what
//
//	creator    quic-go allocates the slice (make+copy in HandleDatagramFrame)
//	holder     this session, from the return of ReceiveDatagram onward
//	released   whoever consumes the buffer calls Release()
//	invalid    never by quic-go; the array is not recycled while it is alive
//	async use  permitted, because the allocation outlives the transport's
//	           reference to it - which is exactly what the TUN hand-off does
//
// # Why buf.As and not buf.NewSize
//
// buf.As is UNMANAGED: Release() does not return the slice to sing's pool. The
// backing array belongs to quic-go and is reclaimed by the GC. Wrapping it in a
// MANAGED buffer would hand quic-go's memory to the pool, where a later buf.Get
// in an unrelated code path could hand the same bytes out again - a
// memory-corruption class of bug.
//
// The cost is that this packet does not enter the pooled-buffer fast path, so a
// managed buffer still has to be acquired on the TUN side when the packet is
// written out. That is the deliberate trade: one pooled acquisition there
// instead of a pooled acquisition PLUS a full-packet memcpy here.
//
// # What this replaced, and why
//
//	buffer := buf.NewSize(headroom + len(datagram) - contextLength)
//	buffer.Resize(headroom, 0)
//	common.Must1(buffer.Write(datagram[contextLength:]))
//
// which acquired a pooled buffer and memcpy'd the entire packet into it, on top
// of the copy quic-go had already performed. The headroom the pooled path
// reserved is not needed here: this buffer carries only the payload, and the
// consumer that prepends a header (the packet writer) is the one that needs
// headroom, which it obtains on its own path.
//
// # Empty payloads
//
// A zero-length payload is preserved rather than skipped. An empty datagram and
// no datagram are different outcomes, and buf.As of an empty slice is a legal
// zero-length buffer. The length check in loopDatagram already rejects the case
// where the varint consumed the whole datagram, which is a malformed frame
// rather than an empty packet.
func (s *session) handleIngressDatagram(payload []byte) {
	s.handler.handlePacket(buf.As(payload))
}

func (s *session) loopCapsule() error {
	for {
		capsuleType, _, err := transportHTTP.ReadVarint(s.reader)
		if err != nil {
			return err
		}
		length, _, err := transportHTTP.ReadVarint(s.reader)
		if err != nil {
			return err
		}
		if length > transportHTTP.MaxCapsuleLength {
			return E.New("capsule too large: ", length)
		}
		switch capsuleType {
		case transportHTTP.CapsuleTypeDatagram:
			err = s.readDatagramCapsule(int(length))
		case capsuleTypeAddressAssign, capsuleTypeAddressRequest, capsuleTypeRouteAdvertisement,
			capsuleTypeDNSAssign, capsuleTypePREF64:
			err = s.readControlCapsule(capsuleType, int(length))
		default:
			// Unknown capsules are ignored, as RFC 9297 requires, so a peer
			// implementing a later extension cannot break this session. The two new
			// types are matched explicitly above precisely so that recognising them is
			// a deliberate act rather than a side effect.
			_, err = s.reader.Discard(int(length))
		}
		if err != nil {
			return err
		}
	}
}

func (s *session) readDatagramCapsule(length int) error {
	contextID, contextLength, err := transportHTTP.ReadVarint(s.reader)
	if err != nil {
		return err
	}
	if contextLength > length {
		return E.New("malformed datagram capsule")
	}
	payloadLength := length - contextLength
	if contextID != 0 || payloadLength == 0 || payloadLength > maxPacketSize {
		_, err = s.reader.Discard(payloadLength)
		return err
	}
	headroom := s.packetHeadroom()
	buffer := buf.NewSize(headroom + payloadLength)
	buffer.Resize(headroom, 0)
	_, err = buffer.ReadFullFrom(s.reader, payloadLength)
	if err != nil {
		buffer.Release()
		return err
	}
	s.handler.handlePacket(buffer)
	return nil
}

func (s *session) readControlCapsule(capsuleType uint64, length int) error {
	payload := make([]byte, length)
	_, err := io.ReadFull(s.reader, payload)
	if err != nil {
		return err
	}
	switch capsuleType {
	case capsuleTypeAddressAssign:
		addresses, parseErr := parseAddresses(payload)
		if parseErr != nil {
			return E.Cause(parseErr, "parse ADDRESS_ASSIGN capsule")
		}
		return s.handler.handleAddressAssign(addresses)
	case capsuleTypeDNSAssign:
		configurations, parseErr := parseDNSAssign(payload)
		if parseErr != nil {
			return E.Cause(parseErr, "parse DNS_ASSIGN capsule")
		}
		return s.handler.handleDNSAssign(configurations)
	case capsuleTypePREF64:
		prefixes, parseErr := parsePREF64(payload)
		if parseErr != nil {
			return E.Cause(parseErr, "parse PREF64 capsule")
		}
		return s.handler.handlePREF64(prefixes)
	case capsuleTypeAddressRequest:
		addresses, parseErr := parseAddresses(payload)
		if parseErr != nil {
			return E.Cause(parseErr, "parse ADDRESS_REQUEST capsule")
		}
		if len(addresses) == 0 {
			return E.New("empty ADDRESS_REQUEST capsule")
		}
		for _, address := range addresses {
			if address.RequestID == 0 {
				return E.New("ADDRESS_REQUEST capsule with zero request ID")
			}
		}
		return s.handler.handleAddressRequest(addresses)
	default:
		routes, parseErr := parseRoutes(payload)
		if parseErr != nil {
			return E.Cause(parseErr, "parse ROUTE_ADVERTISEMENT capsule")
		}
		return s.handler.handleRouteAdvertisement(routes)
	}
}

func (s *session) writeCapsule(capsule *buf.Buffer) error {
	defer capsule.Release()
	s.writeAccess.Lock()
	defer s.writeAccess.Unlock()
	_, err := s.stream.Write(capsule.Bytes())
	return err
}

func (s *session) writePackets(buffers []*buf.Buffer) error {
	capsules := buffers[:0]
	for i, buffer := range buffers {
		datagram := transportHTTP.PrependContextID(buffer)
		if s.datagrams != nil {
			err := s.datagrams.SendDatagram(datagram.Bytes())
			var tooLarge *transportHTTP.DatagramTooLargeError
			switch {
			case err == nil:
				datagram.Release()
				continue
			case errors.As(err, &tooLarge):
				mtu := tooLarge.MaxPayloadSize - 1
				if mtu >= minimumLinkMTU {
					datagram.Advance(1)
					s.handler.handlePacketTooBig(datagram, mtu)
					continue
				}
				err = E.New("QUIC connection is unable to carry ", minimumLinkMTU, " bytes packets")
			case errors.Is(err, transportHTTP.ErrDatagramUnsupported):
				capsules = append(capsules, datagram)
				continue
			}
			datagram.Release()
			buf.ReleaseMulti(capsules)
			buf.ReleaseMulti(buffers[i+1:])
			return err
		}
		capsules = append(capsules, datagram)
	}
	if len(capsules) == 0 {
		return nil
	}
	s.writeAccess.Lock()
	defer s.writeAccess.Unlock()
	return transportHTTP.WriteDatagramCapsules(s.stream, capsules)
}
