package sniff

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

type (
	StreamSniffer = func(ctx context.Context, metadata *adapter.InboundContext, reader io.Reader) error
	PacketSniffer = func(ctx context.Context, metadata *adapter.InboundContext, packet []byte) error
)

var ErrNeedMoreData = E.New("need more data")

func Skip(metadata *adapter.InboundContext) bool {
	// skip server first protocols
	switch metadata.Destination.Port {
	case 25, 465, 587:
		// SMTP
		return true
	case 143, 993:
		// IMAP
		return true
	case 110, 995:
		// POP3
		return true
	}
	return false
}

// DefaultStreamSniffers is the plan a sniff action runs when it names no stream sniffer.
//
// The order is the order the parsers are tried in, and it is kept here rather than at the call
// site so that the stream benchmarks and the router cannot drift apart. It is not a priority list:
// a parser that claims a payload ends the attempt, so moving a weak parser in front of a stronger
// one changes what gets reported.
var DefaultStreamSniffers = []StreamSniffer{
	TLSClientHello,
	HTTPHost,
	StreamDomainNameQuery,
	BitTorrent,
	SSH,
	RDP,
}

// DefaultPacketSniffers is the order in which datagram payloads are attributed to a protocol.
//
// Order is load-bearing, not cosmetic: PeekPacket returns on the first sniffer that claims the
// packet, so a weak sniffer placed early steals traffic from a stronger one placed later.
//
// WireGuard sits immediately before UTP because UTP is the weakest check in this list - it reads
// two nibbles out of the first byte and an extension chain that is usually empty - and it was
// claiming WireGuard handshake initiations, which start 01 00 00 00 and are 148 bytes. WireGuard
// is not promoted above QUIC or STUN: those match fixed multi-byte constants (QUIC's version and
// connection-id layout, STUN's 0x2112A442 magic cookie) and cannot match a WireGuard header, so
// moving WireGuard past them would only add ways for the two to fight. Everything after UTP is
// untouched, and the first bytes the later sniffers require (0x00 for the UDP tracker, 0x14-0x19
// for DTLS, and an NTP version field WireGuard's low type byte cannot produce) are disjoint from
// WireGuard's type values, so the insertion changes nothing for them.
var DefaultPacketSniffers = []PacketSniffer{
	DomainNameQuery,
	QUICClientHello,
	STUNMessage,
	WireGuard,
	UTP,
	UDPTracker,
	DTLSRecord,
	NTP,
}

// payloadReader is the logical payload PeekStream sniffs: the buffers cached from earlier rounds
// followed by the bytes read so far, presented as one io.Reader.
//
// It is a rewindable cursor rather than a fresh io.MultiReader per sniffer because of how the
// retry loop is shaped. Every round of reads re-runs the whole sniffer list over the whole cached
// payload, so a fragmented ClientHello that takes eight reads runs six sniffers eight times, and
// building a reader graph inside that inner loop costs two allocations for every one of those
// forty-eight attempts while presenting the same bytes each time.
//
// The segments are borrowed, never copied. A cursor therefore must not outlive the PeekStream
// call that created it: the sniffers below are synchronous and drop the reader when they return,
// and the single cursor is rewound between sniffers so that no sniffer ever observes where the
// previous one stopped.
type payloadReader struct {
	segments [][]byte
	segment  int
	offset   int
}

func (r *payloadReader) Reset(segments [][]byte) {
	r.segments = segments
	r.segment = 0
	r.offset = 0
}

func (r *payloadReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// One segment per call, matching what io.MultiReader over bytes.Reader produced before: a
	// short read at a segment boundary is not just allowed, it is the established behaviour every
	// parser here already tolerates through io.ReadFull and bufio.
	for r.segment < len(r.segments) {
		segment := r.segments[r.segment]
		if r.offset == len(segment) {
			r.segment++
			r.offset = 0
			continue
		}
		n := copy(p, segment[r.offset:])
		r.offset += n
		return n, nil
	}
	return 0, io.EOF
}

func PeekStream(ctx context.Context, metadata *adapter.InboundContext, conn net.Conn, buffers []*buf.Buffer, buffer *buf.Buffer, timeout time.Duration, sniffers ...StreamSniffer) error {
	if timeout == 0 {
		timeout = C.ReadPayloadTimeout
	}
	deadline := time.Now().Add(timeout)
	// The cached buffers cannot change during this call, so their payload is captured once. The
	// newest buffer is re-read after every ReadOnceFrom because reading is what fills it.
	segments := make([][]byte, 0, len(buffers)+1)
	for _, cachedBuffer := range buffers {
		segments = append(segments, cachedBuffer.Bytes())
	}
	newestSegment := len(segments)
	segments = append(segments, nil)
	var payload payloadReader
	// Held across rounds and resliced, so the failures of the round that ends the sniff cost one
	// allocation per call instead of one slice per failure per round. E.Errors may keep a
	// reference to the slice it is handed, which is why the slice is private to this call and is
	// not read again once returned.
	roundErrors := make([]error, 0, len(sniffers))
	var sniffError error
	for i := 0; ; i++ {
		err := conn.SetReadDeadline(deadline)
		if err != nil {
			return E.Cause(err, "set read deadline")
		}
		_, err = buffer.ReadOnceFrom(conn)
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			if i > 0 {
				// roundErrors still holds the last completed round's failures - this iteration
				// has not reset it - so the aggregate the loop used to keep in sniffError is
				// rebuilt here, once, instead of on every round.
				sniffError = E.Errors(roundErrors...)
				break
			}
			return E.Cause(err, "read payload")
		}
		segments[newestSegment] = buffer.Bytes()
		roundErrors = roundErrors[:0]
		// The retry decision is read off the round's failures directly, and E.Errors is called
		// only on the round that ends the sniff. Intermediate rounds used to build an aggregate
		// they immediately threw away; a fragmented ClientHello that takes eight reads paid for
		// seven of them.
		//
		// The substitution is sound in the direction that matters. E.Errors drops nil arguments,
		// flattens anything with an Unwrap() []error, de-duplicates by message and wraps what is
		// left in a multiError, so every element it keeps is either one of these errors or a
		// child of one: an aggregate that matches ErrNeedMoreData always has a constituent that
		// matches too, and answering "need more data" therefore never outlives the round that
		// produced it. The converse - a constituent that matches means the aggregate would have
		// - holds for every error these sniffers can return, because "need more data" is a
		// message only ErrNeedMoreData itself writes, and it is checked exhaustively in
		// TestErrorsNeedMoreDataAgreesWithTheOrOfItsConstituents. The single shape that
		// disagrees is an error that mimics the sentinel's message without wrapping the
		// sentinel, which de-duplication can prefer over the real one; that case is pinned by
		// TestPeekStreamNeedMoreDataImpostorReadsMoreRatherThanStopping, and it diverges by
		// reading again rather than by stopping early.
		needMore := false
		for _, sniffer := range sniffers {
			// Rewind rather than rebuild: every sniffer starts at offset zero of the same
			// payload, and a sniffer that fails leaves the next one a clean cursor.
			payload.Reset(segments)
			err = sniffer(ctx, metadata, &payload)
			if err == nil {
				return nil
			}
			roundErrors = append(roundErrors, err)
			if errors.Is(err, ErrNeedMoreData) {
				needMore = true
			}
		}
		if !needMore {
			sniffError = E.Errors(roundErrors...)
			break
		}
	}
	return sniffError
}

func PeekPacket(ctx context.Context, metadata *adapter.InboundContext, packet []byte, sniffers ...PacketSniffer) error {
	// A packet is claimed by the first sniffer that recognises it, and every sniffer that ran
	// before that one failed. Those earlier failures are diagnostics - they end up in
	// metadata.SniffError for logging and nothing routes on them - so the common path is not
	// allowed to allocate an aggregate it is about to discard.
	//
	// The first two failures live in locals, which covers the sniffers that actually claim most
	// datagrams (DNS, QUIC, STUN and WireGuard sit in the first four slots of the default plan),
	// and the slice appears only when a third failure proves a real aggregate is required. Using
	// a stack array instead would be simpler but costs more: passing a slice of it to E.Errors
	// makes the whole array escape, which is a heap allocation on every call including the ones
	// that succeed on the first try.
	var (
		firstError  error
		secondError error
		sniffErrors []error
	)
	for _, sniffer := range sniffers {
		err := sniffer(ctx, metadata, packet)
		if err == nil {
			return nil
		}
		switch {
		case firstError == nil:
			firstError = err
		case secondError == nil:
			secondError = err
		case sniffErrors == nil:
			sniffErrors = make([]error, 0, len(sniffers))
			sniffErrors = append(sniffErrors, firstError, secondError, err)
		default:
			sniffErrors = append(sniffErrors, err)
		}
	}
	switch {
	case firstError == nil:
		return E.Errors()
	case secondError == nil:
		// E.Errors returns a single argument unchanged, so this is E.Errors(firstError).
		return firstError
	case sniffErrors == nil:
		return E.Errors(firstError, secondError)
	default:
		return E.Errors(sniffErrors...)
	}
}
