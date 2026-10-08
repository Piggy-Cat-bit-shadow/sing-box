package sniff_test

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing/common/buf"
	"github.com/stretchr/testify/require"
)

// baselineStreamSniffers is the stream plan spelled out here rather than taken from the package.
//
// That is deliberate: this file has to compile against both the optimized and the pre-optimization
// implementation, so that the table below can be produced from either and compared. It is the same
// six parsers in the same order as sniff.DefaultStreamSniffers, and
// TestStreamSniffingAcrossReadsMatchesPreOptimizationBaseline is the reason to keep it that way.
var baselineStreamSniffers = []sniff.StreamSniffer{
	sniff.TLSClientHello,
	sniff.HTTPHost,
	sniff.StreamDomainNameQuery,
	sniff.BitTorrent,
	sniff.SSH,
	sniff.RDP,
}

// TestStreamSniffingAcrossReadsMatchesPreOptimizationBaseline pins exactly what the stream plan does
// when a read boundary cuts a request, and it pins it against a measurement rather than against an
// opinion: every row below was produced by running this test unchanged against the implementation
// this optimization replaced (common/sniff/sniff.go and common/sniff/tls.go at 6927861bf), and the
// two runs agree row for row, including the aggregation text.
//
// Two of those rows record limitations that are NOT introduced here and are not fixed here, because
// fixing either would change what gets detected:
//
//   - HTTP stops being recognised when a read ends inside the request. Go's net/http parser - which
//     HTTPHost borrows through common/badhttp - answers a truncated request with a definite
//     "malformed ..." verdict rather than with io.ErrUnexpectedEOF, so PeekStream has nothing that
//     says "ask for more" and ends the attempt. A request that arrives whole, or cut after the
//     request line, is still recognised.
//   - SSH is recognised from a banner that has not ended yet, because SSH ignores bufio.ReadLine's
//     isPrefix result and reports the partial line as the client. The protocol is right and the
//     client string is short.
func TestStreamSniffingAcrossReadsMatchesPreOptimizationBaseline(t *testing.T) {
	t.Parallel()
	request := []byte("GET /index.html HTTP/1.1\r\nHost: fragmented.example.com\r\nUser-Agent: sniff\r\nAccept: */*\r\n\r\n")
	banner := []byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
	for _, testCase := range []struct {
		name     string
		payload  []byte
		reads    int
		protocol string
		client   string
	}{
		{"http-whole", request, 1, "http", ""},
		{"http-cut-after-request-line", request, 2, "http", ""},
		{"http-cut-inside-header", request, 3, "", ""},
		{"http-cut-inside-version", request, 5, "", ""},
		{"http-cut-inside-path", request, 9, "", ""},
		{"ssh-whole", banner, 1, "ssh", "OpenSSH_9.6p1 Ubuntu-3ubuntu13"},
		{"ssh-cut-after-version", banner, 2, "ssh", "OpenSSH_9.6p"},
		{"ssh-cut-inside-version", banner, 3, "ssh", "OpenSS"},
		{"ssh-cut-inside-prefix", banner, 9, "ssh", "Op"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conn := &scriptedConn{chunks: splitChunks(testCase.payload, testCase.reads)}
			metadata := adapter.InboundContext{}
			sniffBuffer := buf.NewPacket()
			defer sniffBuffer.Release()
			err := sniff.PeekStream(context.Background(), &metadata, conn, nil, sniffBuffer, 0, baselineStreamSniffers...)
			require.Equal(t, testCase.protocol, metadata.Protocol)
			require.Equal(t, testCase.client, metadata.Client)
			if testCase.protocol == "" {
				require.Error(t, err)
				require.NotErrorIs(t, err, sniff.ErrNeedMoreData,
					"the sweep has to end with a verdict, not with a request for more data")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestTruncatedHTTPAndSSHAreDefiniteVerdicts is the root cause of the two HTTP rows above and the
// SSH client strings, checked at the parser instead of through the loop. Both parsers answer a
// truncated input with something other than ErrNeedMoreData, which is precisely why the loop stops:
// it only keeps reading while some parser is still asking for bytes.
func TestTruncatedHTTPAndSSHAreDefiniteVerdicts(t *testing.T) {
	t.Parallel()
	// Closed shapes: the parser can tell the request is wrong without seeing the rest of it, so it
	// answers with a verdict and the loop stops.
	for _, truncated := range []string{
		"GET /index",
		"GET /index.html HT",
		"GET /index.html HTTP/1.1\r\nHost",
	} {
		var metadata adapter.InboundContext
		err := sniff.HTTPHost(context.Background(), &metadata, strings.NewReader(truncated))
		require.Error(t, err, "HTTPHost(%q)", truncated)
		require.NotErrorIs(t, err, sniff.ErrNeedMoreData, "HTTPHost(%q)", truncated)
	}
	// An open shape: headers that simply have not been terminated yet. This one does ask for more
	// data, which is what makes the three above the only reason a cut request can be lost.
	var openMetadata adapter.InboundContext
	require.ErrorIs(t,
		sniff.HTTPHost(context.Background(), &openMetadata, strings.NewReader("GET /index.html HTTP/1.1\r\nHost: fragmented.example.com\r\nUser-Agent: sniff\r\n")),
		sniff.ErrNeedMoreData)
	for _, truncated := range []string{
		"SSH-2.0-",
		"SSH-2.0-OpenSSH_9.6p",
	} {
		var metadata adapter.InboundContext
		require.NoError(t, sniff.SSH(context.Background(), &metadata, strings.NewReader(truncated)), "SSH(%q)", truncated)
		require.Equal(t, "ssh", metadata.Protocol, "SSH(%q)", truncated)
	}
}
