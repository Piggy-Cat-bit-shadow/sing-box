package naive

import (
	"bytes"
	"io"
	"testing"
)

// Benchmarks for the Naive padding codec and the connection wrappers.
//
// Scope note: these are PURE CPU measurements of this package's own hot path --
// framing, de-framing and the headroom/MTU decisions the router consults. They
// deliberately do NOT claim end-to-end proxy throughput, which depends on the
// kernel, the transport and the outbound and is measured separately by the
// integration suite.
//
// They are deterministic and allocation-reporting, so a regression in the frame
// path shows up as a number rather than as a feeling.
//
// Run with:
//   go test -run XXX -bench BenchmarkPadding -benchmem ./protocol/naive/

// benchmarkPayload is a realistic tunnel payload: large enough to be streamed,
// small enough to fit one frame.
var benchmarkPayload = bytes.Repeat([]byte("x"), 1400)

// BenchmarkPaddingWriteFramed measures the first 8 frames, which carry the
// 3-byte header and the padding bytes.
func BenchmarkPaddingWriteFramed(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(int64(len(benchmarkPayload)))
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		writer := io.Discard
		connection := &paddingConn{enabled: true}
		b.StartTimer()
		if _, err := connection.writeWithPadding(writer, benchmarkPayload); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPaddingWriteRaw measures the post-window path, which is plain I/O and
// should therefore be markedly cheaper than the framed case.
func BenchmarkPaddingWriteRaw(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(int64(len(benchmarkPayload)))
	connection := &paddingConn{enabled: true, writePadding: paddingCount}
	b.ResetTimer()
	for range b.N {
		if _, err := connection.writeWithPadding(io.Discard, benchmarkPayload); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPaddingWriteUnpadded measures a connection that never negotiated
// padding: no frame header, no padding bytes, no extra allocation.
func BenchmarkPaddingWriteUnpadded(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(int64(len(benchmarkPayload)))
	connection := &paddingConn{enabled: false}
	b.ResetTimer()
	for range b.N {
		if _, err := connection.writeWithPadding(io.Discard, benchmarkPayload); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPaddingReadFramed measures de-framing a stream of frames.
func BenchmarkPaddingReadFramed(b *testing.B) {
	// Build a stream of framed payloads once, then read it repeatedly.
	var stream bytes.Buffer
	payload := benchmarkPayload
	for range 4096 {
		stream.Write([]byte{byte(len(payload) >> 8), byte(len(payload)), 0})
		stream.Write(payload)
	}
	encoded := stream.Bytes()

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		connection := &paddingConn{enabled: true}
		source := bytes.NewReader(encoded)
		b.StartTimer()
		buffer := make([]byte, len(payload))
		for range 4096 {
			if _, err := connection.readWithPadding(source, buffer); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkPaddingReadRaw measures the post-window read path.
func BenchmarkPaddingReadRaw(b *testing.B) {
	data := make([]byte, 4096*len(benchmarkPayload))
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	connection := &paddingConn{enabled: true, readPadding: paddingCount}
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		source := bytes.NewReader(data)
		b.StartTimer()
		buffer := make([]byte, len(benchmarkPayload))
		for {
			n, err := connection.readWithPadding(source, buffer)
			if n == 0 || err != nil {
				break
			}
		}
	}
}

// BenchmarkPaddingWriteChunked measures data larger than one frame, which forces
// the 16-bit chunking path.
func BenchmarkPaddingWriteChunked(b *testing.B) {
	large := bytes.Repeat([]byte("y"), 200000)
	b.ReportAllocs()
	b.SetBytes(int64(len(large)))
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		connection := &paddingConn{enabled: true}
		b.StartTimer()
		if _, err := connection.writeChunked(io.Discard, large); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHeadroomDecisions measures the helpers the router calls per buffer.
// They are trivial, and this pins that they stay trivial.
func BenchmarkHeadroomDecisions(b *testing.B) {
	framed := &paddingConn{enabled: true}
	raw := &paddingConn{enabled: true, writePadding: paddingCount}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = framed.frontHeadroom()
		_ = framed.rearHeadroom()
		_ = framed.writerMTU()
		_ = framed.readerReplaceable()
		_ = framed.writerReplaceable()
		_ = raw.frontHeadroom()
		_ = raw.writerReplaceable()
	}
}
