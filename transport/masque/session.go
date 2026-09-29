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
	QUICPacketOverhead = 51
	minimumLinkMTU     = 1280

	// masqueContextIDMaxLength is the largest MASQUE Context ID this client can frame.
	//
	// The client uses Context ID 0, which is a 1-byte varint. The constant is stated separately
	// from the value in use so the headroom budget below reads as a protocol sum rather than as an
	// assumption, and so a future second context ID has an obvious place to be accounted for.
	masqueContextIDMaxLength = 1
	// http3QuarterStreamIDMaxLength is the largest HTTP/3 quarter stream ID varint.
	//
	// RFC 9000 varints reach 8 bytes, and HTTP/3 divides the stream ID by four, so a long-lived
	// connection WILL eventually use a multi-byte value. Sizing the headroom for the common case
	// would make the zero-copy path silently stop working -- falling back to a full copy per
	// packet -- once a connection had served enough requests, which is the worst kind of
	// regression: invisible, and only on long-lived connections.
	http3QuarterStreamIDMaxLength = 8

	// ownedDatagramHeadroom is what the zero-copy HTTP/3 DATAGRAM path must be able to prepend
	// without reallocating: the MASQUE Context ID, then the HTTP/3 quarter stream ID.
	//
	// It is the requirement the pooled buffers must satisfy for the fast path to be taken. A buffer
	// with less headroom is not an error -- the HTTP/3 layer falls back to copying -- but it costs
	// a packet-sized allocation and copy, so it is a performance cliff rather than a failure.
	ownedDatagramHeadroom = masqueContextIDMaxLength + http3QuarterStreamIDMaxLength

	// capsuleHeadroom is what the CAPSULE fallback must be able to prepend: the capsule type, the
	// payload-length varint, and the MASQUE Context ID.
	capsuleHeadroom = transportHTTP.CapsuleHeadroom

	// PacketHeadroom is the front headroom the tunnel requires of every packet buffer.
	//
	// It is the MAXIMUM of the paths a packet can take, so that a buffer satisfying it never
	// reallocates on either. The two paths are not alternatives chosen per packet -- a session can
	// fall back from datagrams to capsules at any time -- so both requirements have to hold
	// simultaneously.
	PacketHeadroom = max(capsuleHeadroom, ownedDatagramHeadroom)
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
	ctx       context.Context
	cancel    context.CancelCauseFunc
	stream    io.ReadWriteCloser
	datagrams transportHTTP.DatagramStream
	// ownedDatagrams is the ownership-transferring send capability, or nil when this stream cannot
	// take ownership. Decided ONCE here rather than per packet: a stream's capability cannot change
	// while the connection lives, and the packet path may not pay for a type assertion.
	ownedDatagrams transportHTTP.OwnedDatagramSender
	// batchOwnedDatagrams is the BATCHED ownership-transferring send capability, or nil when this
	// stream cannot take ownership in batches. Also resolved once, for the same reason.
	//
	// It is kept alongside ownedDatagrams rather than replacing it: batch is an additional
	// capability, and a stream may well offer one without the other. When only batch is available
	// the single-packet path keeps using ownedDatagrams, and when only ownedDatagrams is available
	// the loop below is exactly what it was before batching existed.
	batchOwnedDatagrams transportHTTP.BatchOwnedDatagramSender
	// batchScratch is a reusable slice for the batched send path.
	//
	// # Why this exists, and what it cost not to have it
	//
	// The first version of the batch path allocated a fresh slice per batch, and the measurement
	// was unambiguous: batch=2 was 46% SLOWER and batch=4 30% slower than the per-packet loop
	// (p<0.001, isolated benchmark). One allocation of 32 B/op cost ~40 ns, which is far more than
	// the ~13 ns/packet the batch reclaims from the send queue. Batching only pays if the batch
	// itself is free to assemble.
	//
	// The slice is only ever used inside writeBatchOwned, which is single-threaded with respect to
	// itself: writePackets is called from the device loop, and the transport takes ownership of the
	// buffers (not of this slice) before returning. It is reused rather than pooled because it
	// belongs to exactly one session.
	batchScratch   []*buf.Buffer
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
	var ownedDatagrams transportHTTP.OwnedDatagramSender
	var batchOwnedDatagrams transportHTTP.BatchOwnedDatagramSender
	if capable, isDatagramStream := stream.(transportHTTP.DatagramStream); isDatagramStream && capable.DatagramsEnabled() {
		datagrams = capable
		// Resolved once, alongside the capability that makes it meaningful. A stream that cannot
		// take ownership simply leaves this nil and the copying path is used unchanged.
		ownedDatagrams = transportHTTP.AsOwnedDatagramSender(capable)
		batchOwnedDatagrams = transportHTTP.AsBatchOwnedDatagramSender(capable)
	}
	current := &session{
		ctx:                 sessionCtx,
		cancel:              cancel,
		stream:              stream,
		datagrams:           datagrams,
		ownedDatagrams:      ownedDatagrams,
		batchOwnedDatagrams: batchOwnedDatagrams,
		reader:              std_bufio.NewReader(stream),
		handler:             handler,
		packetHeadroom:      packetHeadroom,
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

// loopDatagram delivers received HTTP Datagrams to the handler.
//
// # It does not run alone
//
// run() starts this loop in its own goroutine and then occupies the calling goroutine with
// loopCapsule, so a peer sending datagrams AND capsule-carried packets drives handlePacket from two
// goroutines at once.
//
// That is worth stating because it forbids an optimisation that otherwise looks free: reusing one
// []*buf.Buffer per session for the ClientHandler hand-off would save an allocation per received
// packet, and this loop taken alone is single-goroutine and would tolerate it. The capsule loop is
// the second caller, so a shared slice would be a data race. (A race of that shape is caught by
// `go test -race`, so the guard is the existing CI rather than a bespoke test.)
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

// datagram error classification, and why it is not a switch over errors.As.
//
// A packet path may not allocate per packet. The obvious classifier --
//
//	var tooLarge *transportHTTP.DatagramTooLargeError
//	switch {
//	case err == nil:
//	case errors.As(err, &tooLarge):
//	case errors.Is(err, transportHTTP.ErrDatagramUnsupported):
//	}
//
// breaks that rule in a way that is invisible in review: errors.As takes the ADDRESS of its target,
// so the compiler must assume the pointer outlives the call and moves `tooLarge` to the heap on
// every iteration -- including the iterations where err is nil and the call never runs. Escape
// analysis confirms it ("moved to heap: tooLarge"), and a memory profile of the packet path showed
// it as the single remaining per-packet allocation.
//
// The classification below keeps errors.As, but only reached AFTER a nil check and a direct type
// assertion have both failed. Those two answer the cases that actually occur, and neither takes an
// address, so the success path allocates nothing. errors.As stays in the chain for the case the
// direct assertion cannot see -- a WRAPPED *DatagramTooLargeError -- so a future wrapper cannot
// silently change how an error is handled.
type datagramErrorKind uint8

const (
	datagramErrorOther datagramErrorKind = iota
	datagramErrorTooLarge
	datagramErrorUnsupported
)

// classifyDatagramError reports how a failed SendDatagram should be handled, and the transport's
// maximum payload size when the failure was a size failure.
//
// The returned kind is only meaningful for a non-nil error; callers check err == nil first, which
// is what keeps this off the success path entirely.
//
// # Why the nil check delegates instead of falling through
//
// The direct assertion and the errors.As fallback are deliberately NOT in this function's body.
// Go hoists the heap allocation for an errors.As target to FUNCTION ENTRY, so a function that
// merely CONTAINS an errors.As allocates once per call even when the call is never reached. The
// nil return therefore has to leave this function entirely, which is why the two remaining cases
// live in classifyWrappedDatagramError.
func classifyDatagramError(err error) (datagramErrorKind, int) {
	if err == nil {
		return datagramErrorOther, 0
	}
	if tooLarge, isTooLarge := err.(*transportHTTP.DatagramTooLargeError); isTooLarge {
		return datagramErrorTooLarge, tooLarge.MaxPayloadSize
	}
	// Reached only for an error that is not directly a *DatagramTooLargeError, i.e. never on the
	// success path this classifier exists to keep clean.
	return classifyWrappedDatagramError(err)
}

// classifyWrappedDatagramError handles the errors that need unwrapping.
//
// It is a separate function so that the allocation its errors.As forces is paid only by callers
// that actually have an error to classify.
func classifyWrappedDatagramError(err error) (datagramErrorKind, int) {
	var tooLarge *transportHTTP.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return datagramErrorTooLarge, tooLarge.MaxPayloadSize
	}
	if errors.Is(err, transportHTTP.ErrDatagramUnsupported) {
		return datagramErrorUnsupported, 0
	}
	return datagramErrorOther, 0
}

// writePackets sends a batch of inner IP packets over the established session.
//
// # Two send paths, one ownership rule
//
// When the datagram stream can take ownership of a buffer, packets are handed over WITHOUT the two
// payload copies quic-go's copying API performs. When it cannot, the copying path is used and this
// side releases the buffer itself.
//
// The rule that keeps both correct is that a buffer is released EXACTLY ONCE, by whoever owns it:
//
//	owned, nil error       -> the transport owns it. This function must NOT release it.
//	owned, non-nil error   -> still ours. The HTTP/3 layer rolled back its prefix, so the buffer
//	                          reads as ContextID + packet again and can be retried or turned into
//	                          a PTB.
//	not owned, nil error   -> we still own it (the copy was sent), so release it here.
//	not owned, non-nil err -> we own it, and it was never sent.
//
// Getting the first case wrong would be a double release of a pooled buffer, which corrupts
// unrelated traffic later rather than failing here.
//
// # The batch fast path
//
// A CONNECT-IP sender does not produce packets one at a time. sing-tun's dispatch stage collects a
// whole read burst and hands it over in a single call, so this function routinely receives several
// buffers at once -- measured at a mean of ~4 and reaching the tens on a loaded link.
//
// Sending those individually repeats, once per packet, the transport's send-queue lock and its send
// scheduling signal. One signal already makes the connection drain the whole queue, so the
// repetitions bought nothing. The batch path below charges both once for the group.
//
// # Why the batch is attempted FIRST and falls back to the loop
//
// The batch is all-or-nothing, so any refusal -- an oversized packet, a peer that does not accept
// datagrams, a stream that has failed -- rejects the WHOLE group and leaves every buffer with this
// function, exactly as if the batch had never been attempted. That makes the fallback safe by
// construction: the loop below runs on the complete, unmodified input and performs the same
// per-packet classification it always did, so the too-large and unsupported handling is not
// duplicated or re-derived here.
//
// A batch of one is NOT sent through this path: the transport charges the same fixed cost for a
// single-element batch as for a plain send, and the measurement showed a small regression at
// batch=1. Single packets therefore take the original loop, unchanged.
func (s *session) writePackets(buffers []*buf.Buffer) error {
	// len>1 only: see the batch=1 note above.
	if s.batchOwnedDatagrams != nil && len(buffers) > 1 {
		if s.writeBatchOwned(buffers) {
			return nil
		}
		// The batch was refused and every buffer is still ours and unmodified. Fall through to the
		// per-packet loop, which is what classifies the failure.
	}
	capsules := buffers[:0]
	for i, buffer := range buffers {
		datagram := transportHTTP.PrependContextID(buffer)
		if s.datagrams != nil {
			var err error
			if s.ownedDatagrams != nil {
				// Ownership transfers on success, so the release below is skipped entirely.
				err = s.ownedDatagrams.SendDatagramOwned(datagram)
				if err == nil {
					continue
				}
			} else {
				err = s.datagrams.SendDatagram(datagram.Bytes())
				if err == nil {
					// The overwhelmingly common case, and it is kept first and free of any
					// error-classification machinery.
					datagram.Release()
					continue
				}
			}
			// Only now, on the failure path, is the error classified. This ordering is not
			// stylistic: passing the address of a typed pointer to errors.As makes that variable
			// escape to the heap UNCONDITIONALLY, whether or not the call matches, so classifying
			// first cost one heap allocation per successfully sent packet. See
			// classifyDatagramError.
			kind, maxPayloadSize := classifyDatagramError(err)
			switch kind {
			case datagramErrorTooLarge:
				mtu := maxPayloadSize - 1
				if mtu >= minimumLinkMTU {
					datagram.Advance(1)
					s.handler.handlePacketTooBig(datagram, mtu)
					continue
				}
				err = E.New("QUIC connection is unable to carry ", minimumLinkMTU, " bytes packets")
			case datagramErrorUnsupported:
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

// writeBatchOwned attempts to send the whole group with one ownership-transferring call.
//
// It reports whether the batch was accepted. A false return means every buffer the caller holds is
// still owned by this function and byte-identical to what the caller passed in, so the caller can
// safely run the per-packet loop over the same slice.
//
// # The context ID must be undone here, and this was a real bug
//
// The transport's rollback only removes the quarter stream ID that HTTP/3 added. It knows nothing
// about the 1-byte context ID this function prepends, so a refused batch comes back with the
// context ID still attached. The fallback loop then prepends a SECOND one, shifting the inner IP
// header by a byte -- and packetAddresses reads the version nibble from the wrong offset, rejects
// the packet as invalid, and the packet is dropped with no error.
//
// That is exactly what happened before this was fixed: a refused batch of two packets produced no
// PTB, no capsule fallback and no error. Every packet was silently discarded. The Advance below is
// what restores the caller's view.
//
// # PrependContextID can CONSUME a buffer, which is why substitution refuses the batch
//
// When a buffer has no headroom for the context-ID byte, PrependContextID allocates a replacement
// and RELEASES the original. If the batch were then refused, the caller's slice would hold
// released -- possibly recycled -- buffers, and the fallback loop would double-release them: silent
// heap corruption rather than a failure at the call site.
//
// So a substitution is detected and the batch is refused BEFORE it is attempted, and the caller's
// slice is updated to the replacement at the index where it happened.
//
// # Why substitution is not on the hot path
//
// The device feeding this path reserves PacketHeadroom (>= 9) bytes precisely so the single-byte
// context ID fits, so substitution does not happen in production. It is a correctness guard for a
// caller with a differently-shaped pool.
func (s *session) writeBatchOwned(buffers []*buf.Buffer) bool {
	// Reused, not allocated: see the batchScratch field.
	if cap(s.batchScratch) < len(buffers) {
		s.batchScratch = make([]*buf.Buffer, len(buffers))
	}
	prepared := s.batchScratch[:len(buffers)]
	for i, buffer := range buffers {
		prepared[i] = transportHTTP.PrependContextID(buffer)
		if prepared[i] != buffer {
			// A replacement was allocated and the original released. Any prefix already applied to
			// the earlier buffers must be undone before returning, and the caller's slice takes the
			// replacement at this index so it does not keep a pointer to freed memory.
			for j := range i {
				buffers[j].Advance(1)
			}
			buffers[i] = prepared[i]
			buffers[i].Advance(1)
			return false
		}
	}
	if s.batchOwnedDatagrams.SendDatagramsOwned(prepared) == nil {
		return true
	}
	// The batch was refused. Ownership of every buffer is still ours, but each still carries the
	// context ID, so remove it to restore exactly what the caller passed in.
	//
	// This is also what makes the fallback correct: without it the loop would prepend a second
	// context ID and every packet in the batch would be silently dropped.
	for _, buffer := range buffers {
		buffer.Advance(1)
	}
	return false
}
