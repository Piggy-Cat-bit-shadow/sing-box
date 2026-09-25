package naive

import (
	"bytes"
	"io"
	"testing"

	"github.com/sagernet/sing/common/buf"
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
		if _, err := connection.writeFrameForTest(writer, benchmarkPayload); err != nil {
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
		if _, err := connection.writeFrameForTest(io.Discard, benchmarkPayload); err != nil {
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
		if _, err := connection.writeFrameForTest(io.Discard, benchmarkPayload); err != nil {
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
	// Each iteration de-frames the WHOLE stream, i.e. 4096 payloads. Reporting
	// only one payload's worth of bytes made this benchmark incomparable with
	// BenchmarkPaddingReadRaw: the two had similar ns/op while their MB/s
	// differed by ~4096x, and the apparent "framing is nearly free" result was
	// an artefact of the byte basis rather than a measurement.
	b.SetBytes(int64(len(payload) * 4096))
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
//
// It consumes the same number of payload bytes as BenchmarkPaddingReadFramed
// (4096 payloads), so the two are directly comparable. Read the MB/s column
// rather than ns/op when comparing them: framed additionally carries 3 header
// bytes per payload, so equal wall time would not mean equal throughput.
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

// BenchmarkPaddingWriteBuffer measures the buffer path, which is the one the
// router actually uses for bulk transfer (naiveConn.WriteBuffer).
//
// The buffer is built with the correct headroom the production copy path
// guarantees, so the numbers reflect real work rather than a degenerate
// allocation:
//
//	buf.NewSize(3 + 255 + len(payload)); b.Resize(3, len(payload))
//
// sing/common/buf.Resize(start, end) sets b.end = b.start + end, so the second
// argument is a LENGTH. Passing an end offset here (as an earlier test did) both
// corrupts Len() and eats 3 bytes of the rear headroom that the 0..255 padding
// range depends on. Both headroom values are asserted before timing so this
// benchmark cannot silently measure the wrong buffer.
func BenchmarkPaddingWriteBuffer(b *testing.B) {
	for _, testCase := range []struct {
		name    string
		payload []byte
	}{
		{"small-64B", bytes.Repeat([]byte("s"), 64)},
		{"medium-1400B", bytes.Repeat([]byte("m"), 1400)},
		{"large-16KiB", bytes.Repeat([]byte("l"), 16*1024)},
	} {
		b.Run(testCase.name, func(b *testing.B) {
			payload := testCase.payload
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				buffer := buf.NewSize(3 + 255 + len(payload))
				// Resize(start, LENGTH), matching the production copy path.
				buffer.Resize(3, len(payload))
				copy(buffer.Bytes(), payload)
				if buffer.Start() < 3 || buffer.FreeLen() < 255 || buffer.Len() != len(payload) {
					b.Fatalf("buffer headroom is wrong: start=%d free=%d len=%d",
						buffer.Start(), buffer.FreeLen(), buffer.Len())
				}
				connection := &paddingConn{enabled: true, writePadding: paddingCount}
				b.StartTimer()
				if err := connection.writeBufferWithPadding(io.Discard, buffer); err != nil {
					b.Fatal(err)
				}
				buffer.Release()
			}
		})
	}
}

// BenchmarkPaddingWriteBufferFramed is the same path with the padding window
// still OPEN, so the frame header and the random padding are actually written.
//
// writePadding is set to paddingCount-1 so the counter is inside the window for
// every iteration, which is where the codec cost lives.
func BenchmarkPaddingWriteBufferFramed(b *testing.B) {
	for _, testCase := range []struct {
		name    string
		payload []byte
	}{
		{"small-64B", bytes.Repeat([]byte("s"), 64)},
		{"medium-1400B", bytes.Repeat([]byte("m"), 1400)},
		{"large-16KiB", bytes.Repeat([]byte("l"), 16*1024)},
	} {
		b.Run(testCase.name, func(b *testing.B) {
			payload := testCase.payload
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				buffer := buf.NewSize(3 + 255 + len(payload))
				buffer.Resize(3, len(payload))
				copy(buffer.Bytes(), payload)
				// paddingCount-1 keeps the frame window open, but the counter is
				// advanced by the call, so reset it every iteration.
				connection := &paddingConn{enabled: true, writePadding: paddingCount - 1}
				b.StartTimer()
				if err := connection.writeBufferWithPadding(io.Discard, buffer); err != nil {
					b.Fatal(err)
				}
				buffer.Release()
			}
		})
	}
}
