package sniff

import (
	std_bufio "bufio"
	"context"
	"io"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badhttp"
	M "github.com/sagernet/sing/common/metadata"
)

// The benchmarks §5 asks for, run against this sniffer alone rather than through the whole stream
// plan, so that a change to the gate shows up as a change here instead of being averaged away.
//
// Every shape is measured twice: once through HTTPHost, and once through the exact parser call the
// sniffer made before the gate existed. Both sides read from a reader that has already been built
// and is reused between iterations, which is what a caller hands this sniffer, so the difference
// between the two rows is the gate and nothing else.

// httpBenchReader is an io.Reader over one payload that hands back at most chunk bytes per Read,
// resettable so a benchmark can replay it without allocating a reader per iteration.
type httpBenchReader struct {
	payload []byte
	offset  int
	chunk   int
}

func (r *httpBenchReader) reset() { r.offset = 0 }

func (r *httpBenchReader) Read(p []byte) (int, error) {
	if r.offset == len(r.payload) {
		return 0, io.EOF
	}
	size := r.chunk
	if size <= 0 || size > len(p) {
		size = len(p)
	}
	if size > len(r.payload)-r.offset {
		size = len(r.payload) - r.offset
	}
	n := copy(p, r.payload[r.offset:r.offset+size])
	r.offset += n
	return n, nil
}

// httpGateBenchmarkWithoutGate is the reference: the body HTTPHost had before the gate existed,
// badhttp.ReadRequest(std_bufio.NewReader(reader)) followed by the same domain derivation, reading
// the same reader. The derivation is not part of the gate and is unchanged by it, but leaving it
// out of this side would charge its two allocations to the gate.
func httpGateBenchmarkWithoutGate(b *testing.B, payload []byte, chunk int) {
	b.Helper()
	reader := &httpBenchReader{payload: payload, chunk: chunk}
	metadata := adapter.InboundContext{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.reset()
		metadata.Domain = ""
		request, err := badhttp.ReadRequest(std_bufio.NewReader(reader))
		if err == nil {
			metadata.Domain = M.ParseSocksaddr(request.Host).Fqdn
		}
	}
}

func httpGateBenchmark(b *testing.B, payload []byte, chunk int) {
	b.Helper()
	reader := &httpBenchReader{payload: payload, chunk: chunk}
	metadata := adapter.InboundContext{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.reset()
		metadata.Protocol = ""
		metadata.Domain = ""
		_ = HTTPHost(context.Background(), &metadata, reader)
	}
}

func httpGatePair(b *testing.B, name string, payload []byte, chunk int) {
	b.Run(name+"/gate", func(b *testing.B) { httpGateBenchmark(b, payload, chunk) })
	b.Run(name+"/without-gate", func(b *testing.B) { httpGateBenchmarkWithoutGate(b, payload, chunk) })
}

var (
	httpHostGateRequest = []byte(httpAcceptedRequests[0])
	// A request cut inside its first line, which is the shape PeekStream sees on an early read.
	httpHostGateFragmentedLine = []byte("GET /index.html HTT")
	httpHostGateDNS            = []byte("\x00\x1e\x74\x07\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x2a\x06google\x03com\x00\x00\x01\x00\x01")
	httpHostGateSSH            = []byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
	httpHostGateBitTorrent     = []byte("\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00")
	httpHostGateRDP            = []byte("\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")
	httpHostGateTLS            = []byte("\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03")
	httpHostGateCustomMethod   = []byte("FROBNICATE /thing HTTP/1.1\r\nHost: custom.example.com\r\n\r\n")
)

func BenchmarkHTTPHostSuccess(b *testing.B) {
	httpGatePair(b, "success", httpHostGateRequest, 0)
}

// BenchmarkHTTPHostCustomMethod is the case §5 forbids a method whitelist for: a method the parser
// accepts because it is a token, not because it is on a list.
func BenchmarkHTTPHostCustomMethod(b *testing.B) {
	httpGatePair(b, "custom-method", httpHostGateCustomMethod, 0)
}

// BenchmarkHTTPHostFragmentedFirstLine is the case the gate is most likely to get wrong: the first
// read ends in the middle of the request line, so the parser would have asked for more data and the
// gate is not allowed to decide yet.
func BenchmarkHTTPHostFragmentedFirstLine(b *testing.B) {
	httpGatePair(b, "fragmented-first-line", httpHostGateFragmentedLine, 4)
}

func BenchmarkHTTPHostDNSOverStream(b *testing.B) {
	httpGatePair(b, "dns-over-stream", httpHostGateDNS, 0)
}
func BenchmarkHTTPHostSSH(b *testing.B) { httpGatePair(b, "ssh", httpHostGateSSH, 0) }
func BenchmarkHTTPHostBitTorrent(b *testing.B) {
	httpGatePair(b, "bittorrent", httpHostGateBitTorrent, 0)
}
func BenchmarkHTTPHostRDP(b *testing.B)       { httpGatePair(b, "rdp", httpHostGateRDP, 0) }
func BenchmarkHTTPHostTLSRecord(b *testing.B) { httpGatePair(b, "tls-record", httpHostGateTLS, 0) }
func BenchmarkHTTPHostUnknown(b *testing.B)   { httpGatePair(b, "unknown", make([]byte, 64), 0) }
