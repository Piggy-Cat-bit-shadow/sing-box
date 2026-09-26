package masque

import (
	std_bufio "bufio"
	"context"
	"errors"
	"io"
	"sync"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	upgradeToken       = "connect-ip"
	DefaultMTU         = 1280
	PacketHeadroom     = 64
	QUICPacketOverhead = 51
	minimumLinkMTU     = 1280
	// maxPacketSize bounds one MASQUE inner IP packet, in bytes.
	//
	// It is the largest ORDINARY IPv6 packet, and the arithmetic differs between the
	// two families:
	//
	//	IPv4  Total Length is 16 bits and counts the WHOLE packet, header included,
	//	      so a maximal IPv4 packet is 65535 bytes;
	//	IPv6  Payload Length is 16 bits and counts everything AFTER the 40-byte base
	//	      header (RFC 8200 section 3), so a maximal ordinary IPv6 packet is
	//	      40 + 65535 = 65575 bytes.
	//
	// The value used to be 65535, taken from the IPv4 figure. That silently DISCARDED
	// any IPv6 packet in the 65536..65575 window: a legal packet, dropped by a bound
	// that was never about IPv6. Measured before the change, with a real capsule on the
	// wire path: 65535 was delivered, 65536 and 65575 produced nothing.
	//
	// JUMBOGRAMS ARE NOT SUPPORTED and this bound does not enable them. RFC 8200 section
	// 4.5 allows a Payload Length of 0 with a Hop-by-Hop Jumbo Payload option to carry up
	// to 2^32-1 bytes; that would need a different parser and is out of scope. The bound
	// is raised to the largest ordinary packet and no further, and the packet parser
	// still decides validity from the actual IP header, so a buffer in this range whose
	// Payload Length does not agree with its size is rejected by the parser rather than
	// by this limit.
	//
	// sing-tun agrees with the arithmetic: gtcpip/header/ipv6.go defines
	// IPv6MaximumPayloadSize = 65535 for the amount after the base header, and its
	// IPv6.IsValid admits a total of IPv6MinimumSize + that.
	maxPacketSize = 40 + 65535
	sendQueueSize = 256
)

type sessionHandler interface {
	handleAddressAssign(addresses []AssignedAddress) error
	handleAddressRequest(addresses []AssignedAddress) error
	handleRouteAdvertisement(routes []AddressRange) error
	handlePacket(buffer *buf.Buffer)
	handlePacketTooBig(buffer *buf.Buffer, mtu int)
}

type session struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	stream io.ReadWriteCloser
	// datagrams is the datagram-capable view of the stream, or nil when the peer
	// did not negotiate HTTP Datagrams.
	//
	// The write path uses nil to mean "write a capsule instead", which is why the
	// distinction is kept here rather than recovered from SendDatagram's error.
	//
	// This is NOT a fix for a demonstrated bug. Clearing it does not make the
	// capsule fallback fail and does not leak a goroutine (measured: the fallback
	// test passes either way, and an active tunnel shows 9 goroutines both ways).
	// The reason is that the server-side ReceiveDatagram reads a dedicated datagram
	// queue rather than the DATA stream, so a datagram loop with no datagrams just
	// blocks harmlessly. See the note on DatagramStream for the full measurement.
	datagrams   transportHTTP.DatagramStream
	reader      *std_bufio.Reader
	handler     sessionHandler
	sendQueue   chan *buf.Buffer
	writeAccess sync.Mutex
}

// newSession builds a session over a MASQUE request stream.
//
// The datagram view is taken only when the peer actually negotiated HTTP
// Datagrams, so the session records the capability rather than re-deriving it from
// a type assertion that cannot express it.
//
// A stream that does not report the capability at all is treated as incapable,
// which is the safe default: the capsule path always works for both protocols.
//
// This is intent-clarifying rather than defect-fixing; see DatagramStream for the
// measurement that distinguishes the two.
func newSession(ctx context.Context, stream io.ReadWriteCloser, handler sessionHandler, queued bool) *session {
	sessionCtx, cancel := context.WithCancelCause(ctx)
	var datagrams transportHTTP.DatagramStream
	if capable, isDatagramStream := stream.(transportHTTP.DatagramStream); isDatagramStream && capable.DatagramsEnabled() {
		datagrams = capable
	}
	current := &session{
		ctx:       sessionCtx,
		cancel:    cancel,
		stream:    stream,
		datagrams: datagrams,
		reader:    std_bufio.NewReader(stream),
		handler:   handler,
	}
	if queued {
		current.sendQueue = make(chan *buf.Buffer, sendQueueSize)
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
	if s.sendQueue != nil {
		loops.Go(s.loopSend)
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
		buffer := buf.NewSize(PacketHeadroom + len(datagram) - contextLength)
		buffer.Resize(PacketHeadroom, 0)
		buffer.Write(datagram[contextLength:])
		s.handler.handlePacket(buffer)
	}
}

func (s *session) loopSend() {
	for {
		select {
		case buffer := <-s.sendQueue:
			err := s.writePacket(buffer)
			if err != nil {
				s.cancel(err)
			}
		case <-s.ctx.Done():
			for {
				select {
				case buffer := <-s.sendQueue:
					buffer.Release()
				default:
					return
				}
			}
		}
	}
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
		case capsuleTypeAddressAssign, capsuleTypeAddressRequest, capsuleTypeRouteAdvertisement:
			err = s.readControlCapsule(capsuleType, int(length))
		default:
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
	buffer := buf.NewSize(PacketHeadroom + payloadLength)
	buffer.Resize(PacketHeadroom, 0)
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

func (s *session) queuePacket(buffer *buf.Buffer) {
	select {
	case s.sendQueue <- buffer:
	default:
		buffer.Release()
	}
}

func (s *session) writePacket(buffer *buf.Buffer) error {
	datagram := transportHTTP.PrependContextID(buffer)
	if s.datagrams != nil {
		err := s.datagrams.SendDatagram(datagram.Bytes())
		var tooLarge *transportHTTP.DatagramTooLargeError
		switch {
		case err == nil:
			datagram.Release()
			return nil
		case errors.As(err, &tooLarge):
			mtu := tooLarge.MaxPayloadSize - 1
			if mtu < minimumLinkMTU {
				datagram.Release()
				return E.New("QUIC connection is unable to carry ", minimumLinkMTU, " bytes packets")
			}
			datagram.Advance(1)
			s.handler.handlePacketTooBig(datagram, mtu)
			return nil
		case errors.Is(err, transportHTTP.ErrDatagramUnsupported):
		default:
			datagram.Release()
			return err
		}
	}
	s.writeAccess.Lock()
	defer s.writeAccess.Unlock()
	return transportHTTP.WriteDatagramCapsule(s.stream, datagram)
}
