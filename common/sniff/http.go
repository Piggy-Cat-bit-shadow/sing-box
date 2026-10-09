package sniff

import (
	std_bufio "bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badhttp"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// httpHeadSize is how much of a stream the cheap gate looks at before net/http's parser is built.
//
// The gate exists so that a payload which cannot be an HTTP request never pays for the 4KiB
// bufio.Reader the parser needs. One read is enough for that: the payloads that reach this sniffer
// and have nothing to do with HTTP - a DNS-over-TCP length prefix, a BitTorrent handshake, an RDP
// TPKT header, an all-zero segment - give themselves away in their first byte or two. 64 is one
// cache line, it covers the shortest complete request line with room to spare ("GET / HTTP/1.1" is
// 14 bytes before its terminator), and it keeps the replay copy below small enough to sit inside
// the reader that holds it.
const httpHeadSize = 64

// The failure modes net/http's readRequest reaches from the request line alone, worded the way it
// words them. badStringError formats them as "%s %q", and the gate reproduces that formatting
// wherever it holds the same evidence the parser would have held - the whole line, the whole method
// or the whole version. The wording is worth keeping identical because metadata.SniffError is what
// an operator reads when a flow is classified wrongly, and this is the phrase they already grep for.
const (
	httpMalformedRequest = "malformed HTTP request"
	httpInvalidMethod    = "invalid method"
	httpMalformedVersion = "malformed HTTP version"
)

// httpTokenOctets is the method alphabet.
//
// net/http's validMethod calls isToken, which is httpguts.ValidHeaderFieldName, whose table is
// exactly tchar = "!#$%&'*+-.^_`|~" / DIGIT / ALPHA. Nothing else is a token octet: no control byte,
// no separator, and nothing at or above 0x80. The alphabet is written out here rather than derived
// so that the gate's alphabet is visible at the site that depends on it, and
// TestHTTPGateAlphabetMatchesTheParsers is what keeps the two in step.
const httpTokenOctets = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func httpTokenOctet(b byte) bool {
	return strings.IndexByte(httpTokenOctets, b) >= 0
}

// httpReplayReader hands the bytes the gate inspected to the parser before continuing with the
// stream, and replays the error that inspection read produced.
//
// The gate has to see the payload without spending it, and a reader cannot be rewound, so the head
// is remembered instead. The parser then observes the same bytes in the same order it would have
// observed without the gate, and the stream underneath is read exactly as often as the parser would
// have read it: once for the head, and the error that read produced is replayed rather than asked
// for a second time.
type httpReplayReader struct {
	head   [httpHeadSize]byte
	filled int
	served int
	err    error
	reader io.Reader
}

func (r *httpReplayReader) Read(p []byte) (int, error) {
	if r.served < r.filled {
		n := copy(p, r.head[r.served:r.filled])
		r.served += n
		return n, nil
	}
	if r.err != nil {
		err := r.err
		r.err = nil
		return 0, err
	}
	return r.reader.Read(p)
}

func HTTPHost(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	// The gate runs before the bufio.Reader the parser needs, because that reader - a 4KiB buffer
	// plus the request-line parse behind it, for every stream that is not TLS - is the cost being
	// avoided. httpRequestLineRejected only turns away payloads the parser would have turned away
	// itself, so the verdicts this sniffer produces are unchanged; see its comment for the three
	// rules that keep it from deciding anything a prefix cannot answer.
	head := &httpReplayReader{reader: reader}
	head.filled, head.err = reader.Read(head.head[:])
	if rejected, rejectErr := httpRequestLineRejected(head.head[:head.filled]); rejected {
		return rejectErr
	}
	request, err := badhttp.ReadRequest(std_bufio.NewReader(head))
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return E.Cause1(ErrNeedMoreData, err)
		} else {
			return err
		}
	}
	metadata.Protocol = C.ProtocolHTTP
	metadata.Domain = M.ParseSocksaddr(request.Host).Fqdn
	return nil
}

// httpRequestLineRejected reports whether head proves that net/http's readRequest will turn this
// payload away, and returns the error it would be turned away with.
//
// It applies the parser's own request-line conditions and nothing else:
//
//	parseRequestLine: the line must hold two spaces, so that a method, a request URI and a version
//	                  all exist;
//	validMethod:      the method must be a non-empty run of token octets;
//	ParseHTTPVersion: the version must be HTTP/, a digit, a period and a digit.
//
// The gate sees a prefix, so it also has to be careful about which questions a prefix can answer.
// Three rules keep it from ever deciding where the parser would have asked for more bytes:
//
//   - A first line that has ended inside the head is judged in full, with the parser's own
//     conditions in the parser's own order, so its verdict and its error are reproduced exactly.
//   - A first line that has not ended yet is judged only on its method. The method is the run of
//     token octets ending at the first space, so a byte that is neither a token octet nor a space
//     before that space cannot be part of it, and the line has nowhere else to put the byte. The
//     request URI is deliberately not inspected at all: url.ParseRequestURI is what accepts or
//     rejects it, and restating that here would be a second, weaker parser.
//   - A CR as the last byte in hand is never a decision. It may end the line or it may sit inside
//     it, and only the byte after it tells the two apart, so the gate waits for that byte.
//
// Nothing outside the request line is decided, which is what keeps ErrNeedMoreData intact: a
// request whose headers have not arrived yet passes the gate and still reaches the parser, which is
// the only thing that can answer io.ErrUnexpectedEOF for it.
func httpRequestLineRejected(head []byte) (bool, error) {
	if lineEnd, ended := httpFirstLineEnd(head); ended {
		return httpCompleteLineRejected(head[:lineEnd])
	}
	for index, b := range head {
		if httpTokenOctet(b) {
			continue
		}
		if b == ' ' {
			if index == 0 {
				// An empty first field. parseRequestLine is happy with it whenever the line
				// holds a second space; validMethod never is.
				return true, fmt.Errorf("%s: empty method", httpMalformedRequest)
			}
			// A valid method and the space that ends it. Everything after this point is bytes
			// the gate has decided not to judge.
			return false, nil
		}
		if b == '\r' && index+1 == len(head) {
			// Ambiguous until the next byte arrives.
			return false, nil
		}
		// A stray CR or any other non-token byte inside the method. Whether the parser then
		// calls the line malformed or the method invalid depends on bytes this gate has not
		// seen; either way it is a definite rejection and never a request for more data.
		return true, fmt.Errorf("%s: %q at offset %d is not a token octet", httpMalformedRequest, b, index)
	}
	return false, nil
}

// httpCompleteLineRejected applies the parser's request-line conditions to a complete first line -
// terminator excluded, exactly the bytes bufio.ReadLine hands textproto - and reports the error the
// parser would have reported. The order of the three checks is readRequest's order, so that a line
// that fails more than one of them is described the way the parser describes it.
func httpCompleteLineRejected(line []byte) (bool, error) {
	method, rest, ok := bytes.Cut(line, httpSpace)
	if !ok {
		return true, httpBadString(httpMalformedRequest, line)
	}
	_, version, ok := bytes.Cut(rest, httpSpace)
	if !ok {
		return true, httpBadString(httpMalformedRequest, line)
	}
	if !httpValidMethod(method) {
		return true, httpBadString(httpInvalidMethod, method)
	}
	if !httpValidVersion(version) {
		return true, httpBadString(httpMalformedVersion, version)
	}
	return false, nil
}

var httpSpace = []byte{' '}

// httpBadString reproduces net/http's badStringError, which is fmt.Errorf("%s %q", what, val). The
// quoted value is the parser's own evidence, which is why this can only be used where the gate holds
// all of it.
func httpBadString(what string, value []byte) error {
	return fmt.Errorf("%s %q", what, value)
}

// httpValidMethod restates validMethod: a non-empty run of token octets.
func httpValidMethod(method []byte) bool {
	if len(method) == 0 {
		return false
	}
	for _, b := range method {
		if !httpTokenOctet(b) {
			return false
		}
	}
	return true
}

// httpValidVersion restates ParseHTTPVersion. The two literal versions it names come first there,
// but both are already HTTP/d.d, and everything after that requires the prefix, a length of exactly
// len("HTTP/X.Y"), a period in the middle and a digit on either side - so the accept set is exactly
// HTTP/ followed by a digit, a period and a digit.
func httpValidVersion(version []byte) bool {
	return len(version) == len("HTTP/X.Y") &&
		string(version[:5]) == "HTTP/" &&
		version[5] >= '0' && version[5] <= '9' &&
		version[6] == '.' &&
		version[7] >= '0' && version[7] <= '9'
}

// httpFirstLineEnd returns the length of the first line in head, terminator excluded, and whether
// the line has ended at all.
//
// It restates what bufio.ReadLine strips before textproto ever sees a line: a LF always ends a line,
// a CR ends one only when the LF that follows it is also in hand, and a CR with nothing behind it
// answers nothing.
func httpFirstLineEnd(head []byte) (int, bool) {
	for index := 0; index < len(head); index++ {
		switch head[index] {
		case '\n':
			return index, true
		case '\r':
			if index+1 == len(head) {
				return 0, false
			}
			if head[index+1] == '\n' {
				return index, true
			}
		}
	}
	return 0, false
}
