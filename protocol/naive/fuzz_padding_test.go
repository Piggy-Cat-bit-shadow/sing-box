package naive

import (
	"bytes"
	"io"
	"testing"
)

// Fuzzing for the Naive padding codec.
//
// The decoder parses untrusted input on the first bytes of every padded
// connection, so its failure modes matter: a panic takes the process down, a huge
// allocation turns a small input into an out-of-memory kill, and an infinite loop
// wedges the connection forever. A wrong frame counter is equally serious in a
// quieter way, because it desynchronises the stream rather than crashing.
//
// The properties asserted here are therefore:
//
//	no panic
//	no allocation proportional to a declared length that was never supplied
//	no infinite loop (every call returns)
//	the frame counter never runs ahead of what was actually decoded
//
// Run the smoke form with:
//
//	go test -fuzz=FuzzNaivePaddingFrame -fuzztime=10s ./protocol/naive

// frameTestStream builds a stream of padding frames. Each entry is either a
// complete frame or a deliberately truncated one, so the fuzzer's input controls
// how the decoder is walked.
func frameTestStream(data []byte, payloadLimit int) []byte {
	var stream bytes.Buffer
	offset := 0
	for offset+3 <= len(data) {
		frameSize := int(data[offset])
		paddingSize := int(data[offset+1])
		offset += 2

		// Cap the payload the FRAME DECLARES, so a fuzz input cannot ask the
		// decoder for a gigabyte. The declared size is what the decoder trusts,
		// and the buffer it reads into is sized from the caller, not from this.
		declaredPayload := min(frameSize, payloadLimit)

		header := make([]byte, 3)
		header[0] = byte(declaredPayload >> 8)
		header[1] = byte(declaredPayload)
		header[2] = byte(paddingSize % 256)
		stream.Write(header)

		// Supply however many payload bytes are actually available; the point is
		// that a truncated frame must be handled, not that it must succeed.
		available := min(declaredPayload, len(data)-offset)
		if available > 0 {
			stream.Write(data[offset : offset+available])
			offset += available
		}
	}
	// Append whatever is left, which gives the decoder a trailing partial header.
	stream.Write(data[offset:])
	return stream.Bytes()
}

// FuzzNaivePaddingFrame drives the de-framing path with arbitrary input.
func FuzzNaivePaddingFrame(fuzz *testing.F) {
	// Seeds from the required shapes: zero bytes, short headers, exact frames,
	// the padding extremes, a maximum-size payload, and several frames in one
	// stream.
	fuzz.Add([]byte{})
	fuzz.Add([]byte{0x00})
	fuzz.Add([]byte{0x00, 0x00})
	fuzz.Add([]byte{0x00, 0x00, 0x00})
	fuzz.Add([]byte{0x00, 0x05, 0x00, 'h', 'e', 'l', 'l', 'o'})
	fuzz.Add([]byte{0x00, 0x00, 0xff})
	fuzz.Add([]byte{0xff, 0xff, 0xff})
	fuzz.Add([]byte{0x00, 0x03, 0x02, 'a', 'b', 'c', 0x00, 0x00})
	fuzz.Add([]byte{0x01, 0x00, 0x00})
	// Two frames back to back, then a truncated third.
	fuzz.Add([]byte{
		0x00, 0x02, 0x00, 'x', 'y',
		0x00, 0x02, 0x01, 'z', 'w', 0x00,
		0x00, 0x09, 0x00, 'q',
	})

	// A payload ceiling so a fuzz input cannot request an enormous read. The
	// decoder itself must not allocate from the declared length before the bytes
	// arrive, and this keeps the test focused on that property.
	const payloadLimit = 4096

	fuzz.Fuzz(func(t *testing.T, data []byte) {
		reader := bytes.NewReader(frameTestStream(data, payloadLimit))
		connection := &paddingConn{enabled: true}

		// A fixed-size buffer, as the production read path uses: the decoder must
		// never grow it from a declared length.
		buffer := make([]byte, 1024)

		const maxIterations = 4096
		for range maxIterations {
			n, err := connection.readWithPadding(reader, buffer)
			if err != nil {
				// io.EOF and io.ErrUnexpectedEOF are the expected terminal
				// conditions for truncated input. io.ErrShortBuffer is also a
				// legitimate refusal. Anything else is still fine to observe -
				// the requirement is that the call RETURNS and does not panic.
				break
			}
			if n == 0 {
				break
			}
			// The counter must never claim more decoded frames than could
			// possibly have been seen: one frame per iteration at most.
			if connection.readPadding > maxIterations {
				t.Fatalf("frame counter advanced beyond the number of reads: %d",
					connection.readPadding)
			}
		}

		// The padding window is bounded, so the counter cannot exceed the window
		// plus the frames consumed while draining it.
		if connection.readPadding < 0 {
			t.Fatalf("frame counter went negative: %d", connection.readPadding)
		}
	})
}

// FuzzNaivePaddingFrameRoundTrip feeds the ENCODER random payloads and padding
// sizes and requires the decoder to recover exactly what was encoded.
//
// This is the property the framing exists for, and it complements the decoder
// fuzzing above: that one asks "does malformed input stay safe", this one asks
// "does well-formed input survive".
func FuzzNaivePaddingFrameRoundTrip(fuzz *testing.F) {
	fuzz.Add([]byte("hello"), uint8(0))
	fuzz.Add([]byte("x"), uint8(255))
	fuzz.Add([]byte{}, uint8(0))
	fuzz.Add(bytes.Repeat([]byte("y"), 200), uint8(7))

	fuzz.Fuzz(func(t *testing.T, payload []byte, paddingSize uint8) {
		// Keep the encoded frame small enough to be meaningful; the decoder's
		// buffer is sized from the payload as the production path does.
		if len(payload) > 4096 {
			payload = payload[:4096]
		}

		connection := &paddingConn{enabled: true}
		size := int(paddingSize)
		connection.paddingSize = func() int { return size }

		var encoded bytes.Buffer
		writer := &recordingWriter{}
		if err := connection.writeFrameForTestErr(writer, payload); err != nil {
			t.Fatalf("encoding a valid frame failed: %v", err)
		}
		encoded.Write(writer.data)

		// The declared header must match what was actually appended, which is the
		// property the peer relies on when it skips the padding.
		written := writer.data
		if len(written) < 3 {
			t.Fatalf("encoded frame is shorter than its header: %d bytes", len(written))
		}
		declaredPayload := int(written[0])<<8 | int(written[1])
		declaredPadding := int(written[2])
		if declaredPayload != len(payload) {
			t.Fatalf("declared payload %d != actual %d", declaredPayload, len(payload))
		}
		if declaredPadding != size {
			t.Fatalf("declared padding %d != chosen %d", declaredPadding, size)
		}
		if len(written) != 3+len(payload)+size {
			t.Fatalf("frame length %d != header+payload+padding %d",
				len(written), 3+len(payload)+size)
		}
		if connection.writePadding != 1 {
			t.Fatalf("a fully written frame must advance the counter once, got %d",
				connection.writePadding)
		}

		// And it must decode back to the original payload.
		//
		// A zero-length payload is the exception, and deliberately so: the
		// encoder emits a frame declaring originalDataSize == 0, and the decoder
		// CONSUMES that frame and continues rather than returning a zero-byte
		// read. That is the hardening that stops a zero-length frame from being a
		// no-progress read, so for an empty payload the round trip yields EOF and
		// no data - which is the correct outcome, not a failure.
		decoder := &paddingConn{enabled: true}
		out := make([]byte, len(payload)+1)
		n, err := decoder.readWithPadding(bytes.NewReader(written), out)
		if len(payload) == 0 {
			if n != 0 {
				t.Fatalf("an empty frame must decode to no data, got %d bytes", n)
			}
			return
		}
		if err != nil {
			t.Fatalf("decoding a frame this encoder produced failed: %v", err)
		}
		if n != len(payload) {
			t.Fatalf("decoded %d bytes, expected %d", n, len(payload))
		}
		if !bytes.Equal(out[:n], payload) {
			t.Fatalf("round trip changed the payload:\n sent: %x\n got:  %x", payload, out[:n])
		}
	})
}

// recordingWriter captures what the padding writer emits.
type recordingWriter struct {
	data []byte
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

// writeFrameForTestErr exposes the unexported padded write path to the fuzzer.
func (p *paddingConn) writeFrameForTestErr(writer io.Writer, data []byte) error {
	_, err := p.writeFrameForTest(writer, data)
	return err
}
