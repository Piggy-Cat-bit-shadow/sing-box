package naive

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Server-side padded-frame segmentation, against the reference's arithmetic.
//
// REFERENCE PARITY. klzgrad/forwardproxy's flushingIoCopy sizes each frame as:
//
//	paddingSize := rand.Intn(256)
//	maxRead     := 65536 - 3 - paddingSize
//	nr, er      := src.Read(buf[3:maxRead])
//
// The padding size is drawn FIRST and the payload budget is then reduced by it,
// so header + payload + padding never exceeds 65536 whatever is drawn.
//
// The previous implementation chunked the payload at 65535 and added padding
// afterwards, which produced frames up to 3 + 65535 + 255 = 65793 bytes and put
// every frame boundary in a different place. Measured with the padding draws
// {0,1,2,7,31,...}:
//
//	before: data=65535 pad=0 wire=65538 | data=65535 pad=1 wire=65539 | ...
//	after:  data=65533 pad=0 wire=65536 | data=65532 pad=1 wire=65536 | ...
//
// These tests pin the AFTER, so the arithmetic cannot drift back.

// fixedPaddingSource returns a deterministic sequence of padding draws.
func fixedPaddingSource(draws []int) paddingSizeSource {
	index := 0
	return func() int {
		value := draws[index%len(draws)]
		index++
		return value
	}
}

// decodeFrames walks a frame stream and returns the decoded headers.
type decodedFrame struct {
	dataLength    int
	paddingLength int
	wireLength    int
}

func decodePaddingFrames(t *testing.T, data []byte) []decodedFrame {
	t.Helper()
	var frames []decodedFrame
	offset := 0
	for offset+3 <= len(data) {
		dataLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		paddingLength := int(data[offset+2])
		wireLength := 3 + dataLength + paddingLength
		if offset+wireLength > len(data) {
			break
		}
		frames = append(frames, decodedFrame{dataLength, paddingLength, wireLength})
		offset += wireLength
	}
	return frames
}

// TestPaddedSegmentationNeverExceedsTheReferenceCeiling is the core invariant.
func TestPaddedSegmentationNeverExceedsTheReferenceCeiling(t *testing.T) {
	// The draws cover the full 0..255 range at its extremes and in between,
	// because the ceiling depends on the draw.
	draws := []int{0, 1, 2, 7, 31, 127, 254, 255}
	connection := &paddingConn{enabled: true, paddingSize: fixedPaddingSource(draws)}

	payload := bytes.Repeat([]byte("a"), 256*1024)
	var out bytes.Buffer
	if _, err := connection.writeChunked(&out, payload); err != nil {
		t.Fatalf("writeChunked: %v", err)
	}

	frames := decodePaddingFrames(t, out.Bytes())
	if len(frames) == 0 {
		t.Fatal("no frames were emitted")
	}
	for index, frame := range frames {
		if frame.wireLength > 65536 {
			t.Fatalf("frame %d is %d bytes on the wire, exceeding the "+
				"reference ceiling of 65536 (data=%d padding=%d)",
				index, frame.wireLength, frame.dataLength, frame.paddingLength)
		}
		// Within the padding window a FULL frame must fill the ceiling, which is
		// what makes the segmentation identical to the reference rather than
		// merely legal. The FINAL frame is the payload remainder and is
		// legitimately short, so it is excluded.
		isFinal := index == len(frames)-1
		if !isFinal && frame.wireLength != 65536 {
			t.Fatalf("frame %d is %d bytes; the reference fills the ceiling "+
				"exactly (data=%d padding=%d, expected data=%d)",
				index, frame.wireLength, frame.dataLength, frame.paddingLength,
				65536-3-frame.paddingLength)
		}
	}

	// The payload must reassemble exactly, so tighter framing lost nothing.
	total := 0
	for _, frame := range frames {
		total += frame.dataLength
	}
	if total != len(payload) {
		t.Fatalf("frames carry %d payload bytes, want %d", total, len(payload))
	}
	t.Logf("%d frames for %d bytes; first 8 wire lengths: %v", len(frames),
		len(payload), wireLengths(frames, 8))
}

func wireLengths(frames []decodedFrame, limit int) []int {
	var out []int
	for index, frame := range frames {
		if index >= limit {
			break
		}
		out = append(out, frame.wireLength)
	}
	return out
}

// TestPaddedSegmentationPayloadBudgetTracksTheDraw pins the per-draw arithmetic.
//
// Each frame's payload must be exactly 65536 - 3 - paddingSize, because that is
// what the reference's read budget produces. A fixed 65535 payload would fail
// this for every draw except zero.
func TestPaddedSegmentationPayloadBudgetTracksTheDraw(t *testing.T) {
	for _, paddingSize := range []int{0, 1, 2, 7, 31, 127, 254, 255} {
		t.Run(itoa(paddingSize), func(t *testing.T) {
			connection := &paddingConn{enabled: true, paddingSize: fixedPaddingSource([]int{paddingSize})}
			payload := bytes.Repeat([]byte("b"), 128*1024)
			var out bytes.Buffer
			if _, err := connection.writeChunked(&out, payload); err != nil {
				t.Fatalf("writeChunked: %v", err)
			}
			frames := decodePaddingFrames(t, out.Bytes())
			if len(frames) == 0 {
				t.Fatal("no frames")
			}
			first := frames[0]
			wantPayload := 65536 - 3 - paddingSize
			if first.dataLength != wantPayload {
				t.Fatalf("first frame carries %d payload bytes, want %d "+
					"(65536 - 3 header - %d padding)",
					first.dataLength, wantPayload, paddingSize)
			}
			if first.paddingLength != paddingSize {
				t.Fatalf("first frame padding is %d, want %d",
					first.paddingLength, paddingSize)
			}
		})
	}
}

// TestPaddedSegmentationStopsAfterTheWindow pins the frame count rule.
//
// Only the first NumFirstPaddings frames are padded; the rest are raw, so the
// frame count for a large payload must be 8 padded frames plus the remainder.
func TestPaddedSegmentationStopsAfterTheWindow(t *testing.T) {
	draws := make([]int, paddingCount)
	connection := &paddingConn{enabled: true, paddingSize: fixedPaddingSource(draws)}

	// Large enough to need MORE than paddingCount frames: with zero draws each
	// framed frame carries 65533 payload bytes, so the window alone consumes
	// about 8 * 65533 bytes. A payload at or below that would close the window
	// only because it ran out, which is not what this test is about.
	payload := bytes.Repeat([]byte("c"), 1*1024*1024)
	var out bytes.Buffer
	if _, err := connection.writeChunked(&out, payload); err != nil {
		t.Fatalf("writeChunked: %v", err)
	}

	frames := decodePaddingFrames(t, out.Bytes())
	if connection.writePadding != paddingCount {
		t.Fatalf("writePadding counter is %d, want %d",
			connection.writePadding, paddingCount)
	}
	// The counter says how many frames were FRAMED. Verify that agrees with the
	// wire: the first paddingCount frames carry a frame header, and anything
	// after them must be RAW, which decodePaddingFrames cannot see directly
	// because raw bytes have no header. The observable proof is that the payload
	// after the window is not framed: decoding stops producing frames whose
	// padding follows the draw sequence.
	//
	// With zero draws every framed frame is exactly 65536 bytes, and the bytes
	// after the window are raw. So the frame count must be paddingCount plus at
	// most one remainder frame that was NOT framed.
	framedBytes := 0
	for index, frame := range frames {
		if index >= paddingCount {
			break
		}
		if frame.wireLength != 65536 {
			t.Fatalf("framed frame %d is %d bytes, want a full 65536-byte frame",
				index, frame.wireLength)
		}
		framedBytes += frame.wireLength
	}
	if framedBytes >= len(out.Bytes()) {
		t.Fatal("the whole payload was framed; the window must close after " +
			"paddingCount frames and the rest must be raw")
	}
	t.Logf("%d bytes framed over %d frames, %d bytes raw afterwards",
		framedBytes, connection.writePadding, len(out.Bytes())-framedBytes)
}

// TestAdvertisedMTUIsSafeForEveryDraw asserts the advertised MTU cannot cause an
// oversized frame.
//
// The copy path may hand over up to writerMTU() bytes in one WriteBuffer call. If
// that payload plus the header plus the largest possible padding exceeded the
// ceiling, the writer would emit an illegal frame through no fault of its caller.
func TestAdvertisedMTUIsSafeForEveryDraw(t *testing.T) {
	connection := &paddingConn{enabled: true}
	advertised := connection.writerMTU()

	if advertised+3+255 > 65536 {
		t.Fatalf("advertised MTU %d plus header and maximum padding is %d, "+
			"which exceeds the reference ceiling of 65536",
			advertised, advertised+3+255)
	}

	// And the worst case must actually be accepted through writeChunked.
	for _, paddingSize := range []int{0, 255} {
		worst := &paddingConn{enabled: true, paddingSize: fixedPaddingSource([]int{paddingSize})}
		payload := bytes.Repeat([]byte("d"), advertised)
		var out bytes.Buffer
		if _, err := worst.writeChunked(&out, payload); err != nil {
			t.Fatalf("writeChunked at MTU with padding %d: %v", paddingSize, err)
		}
		for index, frame := range decodePaddingFrames(t, out.Bytes()) {
			if frame.wireLength > 65536 {
				t.Fatalf("padding %d frame %d is %d bytes", paddingSize, index, frame.wireLength)
			}
		}
	}
}
