package sniff

import (
	std_bufio "bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badhttp"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// httpChunkedReader is an io.Reader over one payload that hands back at most chunk bytes per Read,
// with the chunks counted so a test can tell how much of the stream a parser actually asked for.
type httpChunkedReader struct {
	payload []byte
	chunk   int
	reads   int
}

func (r *httpChunkedReader) Read(p []byte) (int, error) {
	r.reads++
	if len(r.payload) == 0 {
		return 0, io.EOF
	}
	size := r.chunk
	if size <= 0 || size > len(p) {
		size = len(p)
	}
	if size > len(r.payload) {
		size = len(r.payload)
	}
	n := copy(p, r.payload[:size])
	r.payload = r.payload[n:]
	return n, nil
}

// httpParseReference is the parser as this sniffer ran it before the gate existed: the payload goes
// straight into a bufio.Reader. httpNeedMore reports whether the parser asked for more bytes, which
// is the answer HTTPHost turns into ErrNeedMoreData.
func httpParseReference(t *testing.T, payload []byte, chunk int) (string, bool) {
	t.Helper()
	request, err := badhttp.ReadRequest(std_bufio.NewReader(&httpChunkedReader{payload: payload, chunk: chunk}))
	if err == nil {
		// The derivation HTTPHost applies to the parser's answer. It is not part of the gate and
		// is unchanged by it, but it is what the two sides have to be compared through.
		return "ok:" + M.ParseSocksaddr(request.Host).Fqdn, false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "", true
	}
	return "err:" + err.Error(), false
}

// httpSniffOutcome is what HTTPHost did with the same payload, in the same shape, so the two can be
// compared directly.
func httpSniffOutcome(t *testing.T, payload []byte, chunk int) (string, bool) {
	t.Helper()
	var metadata adapter.InboundContext
	err := HTTPHost(context.Background(), &metadata, &httpChunkedReader{payload: payload, chunk: chunk})
	if err == nil {
		return "ok:" + metadata.Domain, false
	}
	if errors.Is(err, ErrNeedMoreData) {
		return "", true
	}
	return "err:" + err.Error(), false
}

// httpAcceptedRequests is the accept corpus: requests the parser recognises, in the shapes a
// stream sniffer actually meets. Every prefix of every one of them is a payload the gate has to let
// through, because PeekStream calls this sniffer once per read and a prefix is all it has on the
// first one.
var httpAcceptedRequests = []string{
	"GET / HTTP/1.1\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n",
	"GET /index.html HTTP/1.0\r\nHost: example.com:8080\r\n\r\n",
	"POST /submit HTTP/1.1\r\nHost: post.example.com\r\nContent-Length: 0\r\n\r\n",
	"PUT /resource HTTP/1.1\r\nHost: put.example.com\r\n\r\n",
	"DELETE /resource HTTP/1.1\r\nHost: delete.example.com\r\n\r\n",
	"OPTIONS * HTTP/1.1\r\nHost: options.example.com\r\n\r\n",
	"HEAD / HTTP/1.1\r\nHost: head.example.com\r\n\r\n",
	"TRACE / HTTP/1.1\r\nHost: trace.example.com\r\n\r\n",
	"CONNECT www.example.com:443 HTTP/1.1\r\nHost: connect.example.com\r\n\r\n",
	// The extension-method case the gate is forbidden from treating as a whitelist.
	"FROBNICATE /thing HTTP/1.1\r\nHost: custom.example.com\r\n\r\n",
	"MKCOL /a HTTP/1.1\r\nHost: m.example.com\r\n\r\n",
	"get /lower HTTP/1.1\r\nHost: lower.example.com\r\n\r\n",
	"X / HTTP/9.9\r\nHost: future.example.com\r\n\r\n",
	"GET http://absolute.example.com/x HTTP/1.1\r\nHost: absolute.example.com\r\n\r\n",
	"GET /with,punctuation~and%20escapes HTTP/1.1\r\nHost: p.example.com\r\n\r\n",
	"GET / HTTP/1.1\r\n\r\n",
	"GET / HTTP/1.1\nHost: bare-lf.example.com\n\n",
}

// httpRejectedPayloads is the reject corpus, together with the evidence the gate is allowed to use
// for each: a payload whose first line is complete inside the head is described with the parser's
// own error text, and one whose line is still open is described with the gate's own.
var httpRejectedPayloads = []struct {
	name         string
	payload      string
	completeLine bool
}{
	{"one-space", "GET/HTTP/1.1\r\nHost: h\r\n\r\n", true},
	{"no-space", "GET\r\nHost: h\r\n\r\n", true},
	{"bad-version", "GET / HTTP/1.1x\r\nHost: h\r\n\r\n", true},
	{"short-version", "GET / HTTP/1\r\nHost: h\r\n\r\n", true},
	{"version-not-http", "GET / FTP/1.1\r\nHost: h\r\n\r\n", true},
	{"nul-in-method", "G\x00T / HTTP/1.1\r\nHost: h\r\n\r\n", true},
	{"high-byte-method", "G\xffT / HTTP/1.1\r\nHost: h\r\n\r\n", true},
	{"colon-method", "G:T / HTTP/1.1\r\nHost: h\r\n\r\n", true},
	{"empty-method", " / HTTP/1.1\r\nHost: h\r\n\r\n", true},
	// Lines that never end. The parser reaches its verdict on the bytes it has, and so does the
	// gate - these are the DNS-over-TCP, all-zero and BitTorrent shapes.
	{"all-zero", string(bytes.Repeat([]byte{0x00}, 64)), false},
	{"dns-length-prefix", "\x00\x1e\x74\x07\x01\x00\x00\x01", false},
	{"bittorrent-handshake", "\x13BitTorrent protocol", false},
	{"rdp-tpkt", "\x03\x00\x00\x13\x0e\xe0", false},
	{"high-bytes", "\xff\xfe\xfd\xfc\xfb", false},
	{"ssh-banner", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", true},
	{"tls-record", "\x16\x03\x01\x00\x2e\x01\x00\x00\x2a", false},
}

// TestHTTPGateAlphabetMatchesTheParser is the one thing the gate restates by hand rather than
// deriving: the method alphabet. The parser's own answer is taken for all 256 bytes, by asking it
// to parse a request whose method is "A" + byte + "B" and recording whether the method survived.
//
// A byte the gate calls a token octet must leave the parser with a method it accepts; a byte the
// gate calls anything else must make the parser reject the request. Both directions are required:
// the first is what keeps extension methods working, the second is what makes the rejection sound.
func TestHTTPGateAlphabetMatchesTheParser(t *testing.T) {
	t.Parallel()
	for value := 0; value < 256; value++ {
		b := byte(value)
		line := "A" + string(rune(b)) + "B / HTTP/1.1\r\nHost: h\r\n\r\n"
		var metadata adapter.InboundContext
		err := HTTPHost(context.Background(), &metadata, strings.NewReader(line))
		accepted := err == nil
		if httpTokenOctet(b) {
			require.True(t, accepted, "the gate calls %#02x a token octet but the parser rejected %q with %v", b, line, err)
		} else {
			require.Error(t, err, "the gate calls %#02x a non-token byte but the parser accepted %q", b, line)
			require.NotErrorIs(t, err, ErrNeedMoreData, "byte %#02x", b)
		}
	}
}

// TestHTTPGateAllowsEveryPrefixOfAnAcceptedRequest is the fragmentation invariant, stated as
// GateAllows(prefix) for every prefix of every request the parser accepts.
//
// It is the direction that matters, and the direction a microbenchmark cannot see. PeekStream hands
// this sniffer whatever one read produced, so a request that arrives in pieces is parsed from a
// prefix first; a gate that rejected a prefix of a valid request would turn the parser's
// "need more data" into a verdict, end the sweep and lose the flow.
func TestHTTPGateAllowsEveryPrefixOfAnAcceptedRequest(t *testing.T) {
	t.Parallel()
	checked := 0
	for _, request := range httpAcceptedRequests {
		// The corpus is only worth anything if the parser really accepts it.
		require.True(t, httpParsesWhole(t, request), "corpus entry is not accepted by the parser: %q", request)
		for length := 0; length <= len(request); length++ {
			prefix := request[:length]
			rejected, err := httpRequestLineRejected([]byte(prefix))
			require.False(t, rejected,
				"the gate rejected a %d byte prefix of %q with %v", length, request, err)
			checked++
		}
	}
	require.Greater(t, checked, 500)
}

func httpParsesWhole(t *testing.T, request string) bool {
	t.Helper()
	_, err := badhttp.ReadRequest(std_bufio.NewReader(strings.NewReader(request)))
	return err == nil
}

// TestHTTPGateRejectsOnlyWhatTheParserRejects is the soundness direction, over an exhaustive sweep
// of short heads rather than over a hand-picked list: for every one- and two-byte head, and for
// every continuation that could plausibly repair it, a head the gate rejects has to leave the
// parser with a definite rejection and never with a request for more bytes.
//
// The continuations are the point. A rejection is only allowed to be a rejection because no
// continuation can save the payload, so the sweep pairs every rejected head with the completions
// that would save it if the gate were wrong.
func TestHTTPGateRejectsOnlyWhatTheParserRejects(t *testing.T) {
	t.Parallel()
	repairs := []string{
		"T / HTTP/1.1\r\nHost: h\r\n\r\n",
		" / HTTP/1.1\r\nHost: h\r\n\r\n",
		" / HTTP/1.0\r\n\r\n",
		"T /a HTTP/1.1\r\nHost: h\r\n\r\n",
		"T http://h/ HTTP/1.1\r\nHost: h\r\n\r\n",
		"OD / HTTP/1.1\r\nHost: h\r\n\r\n",
		" / HTTP/1.1\r\n",
		"\r\n",
		"\n",
		"",
	}
	alphabet := []byte{
		'A', 'a', 'G', 'T', ' ', '/', ':', '.', '\r', '\n', 0x00, 0x01, 0x1f, 0x7f, 0x80, 0xff,
		'!', '@', '[', ']', '?', '=', '{', '}', '(', ')', '<', '>', ',', ';', '\\', '"', '\t',
	}
	heads := make([][]byte, 0, 256+len(alphabet)*len(alphabet))
	for value := 0; value < 256; value++ {
		heads = append(heads, []byte{byte(value)})
	}
	for _, first := range alphabet {
		for _, second := range alphabet {
			heads = append(heads, []byte{first, second})
		}
	}
	rejectedHeads := 0
	for _, head := range heads {
		rejected, gateErr := httpRequestLineRejected(head)
		if !rejected {
			continue
		}
		rejectedHeads++
		for _, repair := range repairs {
			payload := append(append([]byte{}, head...), repair...)
			_, more := httpParseReference(t, payload, 0)
			require.False(t, more,
				"the gate rejected head %q (with %v) but %q only asked for more data", head, gateErr, payload)
			var metadata adapter.InboundContext
			parseErr := HTTPHost(context.Background(), &metadata, bytes.NewReader(payload))
			require.Error(t, parseErr,
				"the gate rejected head %q (with %v) but the payload %q parsed", head, gateErr, payload)
		}
	}
	// A gate that rejected nothing would pass the loop above vacuously.
	require.Greater(t, rejectedHeads, 1000)
}

// TestHTTPGateKeepsTheParsersOwnErrorWhereItHasTheEvidence pins the diagnostic half of the gate. A
// payload whose first line is complete inside the head is one the parser would have described
// exactly, so the gate has to describe it the same way, down to the quoted value; a payload whose
// line is still open is one the gate decided on partial evidence, and it says so instead of quoting
// a prefix as though it were the line.
func TestHTTPGateKeepsTheParsersOwnErrorWhereItHasTheEvidence(t *testing.T) {
	t.Parallel()
	for _, testCase := range httpRejectedPayloads {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			payload := []byte(testCase.payload)
			var metadata adapter.InboundContext
			gateErr := HTTPHost(context.Background(), &metadata, bytes.NewReader(payload))
			require.Error(t, gateErr, "the gate let %q through to the parser", testCase.payload)

			reference, more := httpParseReference(t, payload, 0)
			require.False(t, more, "%q asked the parser for more data", testCase.payload)
			require.True(t, strings.HasPrefix(reference, "err:"), "the parser accepted %q", testCase.payload)

			if testCase.completeLine {
				require.Equal(t, strings.TrimPrefix(reference, "err:"), gateErr.Error(),
					"the gate described %q differently from the parser", testCase.payload)
			} else {
				require.ErrorContains(t, gateErr, httpMalformedRequest)
			}
		})
	}
}

// TestHTTPGateDescribesTheUnknownPayloadTheWayItUsedTo is the regression that keeps
// metadata.SniffError readable: the all-zero segment everything-not-recognised ends with must still
// report the parser's phrase for it. The characters it quotes are the gate's own, because the gate
// decided before the line ended - the phrase is what an operator greps for.
func TestHTTPGateDescribesTheUnknownPayloadTheWayItUsedTo(t *testing.T) {
	t.Parallel()
	var metadata adapter.InboundContext
	err := HTTPHost(context.Background(), &metadata, bytes.NewReader(bytes.Repeat([]byte{0x00}, 64)))
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNeedMoreData)
	require.ErrorContains(t, err, "malformed HTTP request")
}

// TestHTTPHostIsUnchangedByTheGate is the equivalence check for the replay reader: for every
// payload and every read chunking, this sniffer must reach the same verdict the parser reaches when
// the payload is handed to it directly. The one-byte chunking rows are the interesting ones - they
// are where a gate that consumed more of the stream than it replayed, or that replayed it in the
// wrong order, would show up as a different verdict rather than as an error.
//
// The comparison is on the verdict, not on the wording of a rejection. When a read ends before the
// request line does, the gate can already prove the line cannot be valid - that is what makes it
// cheap - and it says so in its own words, where the parser would have waited for the rest of the
// line and quoted it. The two agree that the payload is not a request, which is the part that
// decides anything; TestHTTPGateKeepsTheParsersOwnErrorWhereItHasTheEvidence pins the exact wording
// for the case where the gate does hold the whole line.
func TestHTTPHostIsUnchangedByTheGate(t *testing.T) {
	t.Parallel()
	payloads := make([]string, 0, len(httpAcceptedRequests)+len(httpRejectedPayloads)+4)
	payloads = append(payloads, httpAcceptedRequests...)
	for _, testCase := range httpRejectedPayloads {
		payloads = append(payloads, testCase.payload)
	}
	payloads = append(payloads,
		"",
		"G",
		"GET / HTTP/1.1\r\nHost: split.example.com", // a request that has not finished arriving
		"GET / HTTP/1.1\r\nHost: split.example.com\r\n",
	)
	for _, payload := range payloads {
		for _, chunk := range []int{1, 2, 3, 7, 64, 4096} {
			reference, referenceMore := httpParseReference(t, []byte(payload), chunk)
			outcome, outcomeMore := httpSniffOutcome(t, []byte(payload), chunk)
			require.Equal(t, referenceMore, outcomeMore, "payload %q chunk %d: need-more-data differs", payload, chunk)
			if referenceMore {
				continue
			}
			require.Equal(t, strings.HasPrefix(reference, "ok:"), strings.HasPrefix(outcome, "ok:"),
				"payload %q chunk %d: accepted differs (%q vs %q)", payload, chunk, reference, outcome)
			if strings.HasPrefix(reference, "ok:") {
				require.Equal(t, reference, outcome, "payload %q chunk %d", payload, chunk)
				continue
			}
			require.True(t, strings.HasPrefix(outcome, "err:"),
				"payload %q chunk %d: the parser rejected it but this sniffer did not (%q)", payload, chunk, outcome)
		}
	}
}

// TestHTTPHostReadsNoMoreThanTheParserWouldHave checks the cost claim in the direction that is
// observable: the gate reads one chunk and the parser reads the rest, so the stream is read exactly
// as often as the parser alone would have read it - never twice for the same bytes. A gate that
// read the payload and then let the parser read it again from the stream would show up here.
func TestHTTPHostReadsNoMoreThanTheParserWouldHave(t *testing.T) {
	t.Parallel()
	payload := []byte(httpAcceptedRequests[0])
	for _, chunk := range []int{1, 2, 5, 16, 4096} {
		referenceReader := &httpChunkedReader{payload: append([]byte{}, payload...), chunk: chunk}
		_, referenceErr := badhttp.ReadRequest(std_bufio.NewReader(referenceReader))
		require.NoError(t, referenceErr)

		sniffReader := &httpChunkedReader{payload: append([]byte{}, payload...), chunk: chunk}
		var metadata adapter.InboundContext
		require.NoError(t, HTTPHost(context.Background(), &metadata, sniffReader))
		require.Equal(t, "www.example.com", metadata.Domain)
		require.LessOrEqual(t, sniffReader.reads, referenceReader.reads+1,
			"chunk %d: the gate read the stream %d times where the parser alone read it %d",
			chunk, sniffReader.reads, referenceReader.reads)
	}
}
