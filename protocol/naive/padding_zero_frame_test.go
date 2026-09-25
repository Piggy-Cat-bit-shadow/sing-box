package naive

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// Zero-length padded frames must not produce a no-progress read.
//
// A Naive frame may declare originalDataSize == 0 while still carrying padding.
// Returning (0, nil) for such a frame violates the io.Reader contract: a copy
// loop may spin forever, and bufio-style readers treat a zero-byte nil-error read
// as "try again".
//
// HARDENING, not parity. The reference behaves the same way and worse: with
// nr == 0 it skips its padding read entirely, leaving those bytes in the stream
// and misaligning every later frame. The frame is consumed here instead, and the
// read continues to the next frame or to EOF.

// frame builds a Naive frame with explicit data and padding sizes.
func frame(dataSize, paddingSize int, payload byte) []byte {
	out := []byte{byte(dataSize >> 8), byte(dataSize), byte(paddingSize)}
	for range dataSize {
		out = append(out, payload)
	}
	return append(out, make([]byte, paddingSize)...)
}

// TestZeroDataFrameWithPaddingMakesProgress is the core regression.
func TestZeroDataFrameWithPaddingMakesProgress(t *testing.T) {
	// An empty frame carrying padding, then a real one.
	wire := append(frame(0, 5, 0), frame(4, 0, 'X')...)

	connection := &paddingConn{enabled: true}
	buffer := make([]byte, 64)
	n, err := connection.readWithPadding(bytes.NewReader(wire), buffer)
	if err != nil {
		t.Fatalf("the empty frame must be skipped and the real one returned, got %v", err)
	}
	if n != 4 {
		t.Fatalf("got %d bytes, want the 4-byte payload of the second frame", n)
	}
	if string(buffer[:n]) != "XXXX" {
		t.Fatalf("got %q, want %q", buffer[:n], "XXXX")
	}
	// The padding of the empty frame must have been consumed, so the second
	// frame was read from the right offset. Getting this wrong would have
	// returned the padding byte instead.
	if connection.readPadding != 2 {
		t.Fatalf("readPadding is %d, want 2 (both frames consumed)",
			connection.readPadding)
	}
}

// TestZeroDataFrameWithZeroPaddingMakesProgress covers the degenerate pair.
func TestZeroDataFrameWithZeroPaddingMakesProgress(t *testing.T) {
	wire := append(frame(0, 0, 0), frame(3, 0, 'Y')...)
	connection := &paddingConn{enabled: true}
	buffer := make([]byte, 64)

	n, err := connection.readWithPadding(bytes.NewReader(wire), buffer)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 3 || string(buffer[:n]) != "YYY" {
		t.Fatalf("got n=%d %q, want 3 YYY", n, buffer[:n])
	}
}

// TestConsecutiveZeroFramesMakeProgress covers a run of empty frames.
//
// The run stays inside the padding window: only the first NumFirstPaddings frames
// are framed at all, and everything after them is raw. A longer run would cross
// that boundary and the trailing bytes would be read as plain payload, which is
// correct protocol behaviour and not what this test is about.
func TestConsecutiveZeroFramesMakeProgress(t *testing.T) {
	var wire []byte
	for range paddingCount - 1 {
		wire = append(wire, frame(0, 1, 0)...)
	}
	wire = append(wire, frame(2, 0, 'Z')...)

	connection := &paddingConn{enabled: true}
	buffer := make([]byte, 64)
	n, err := connection.readWithPadding(bytes.NewReader(wire), buffer)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 2 || string(buffer[:n]) != "ZZ" {
		t.Fatalf("got n=%d %q, want 2 ZZ", n, buffer[:n])
	}
}

// TestOnlyZeroFramesReportsEOF asserts the loop terminates rather than spinning.
//
// The stream holds fewer frames than the padding window, so every frame is parsed
// as a frame and the reader must run out of input rather than loop.
func TestOnlyZeroFramesReportsEOF(t *testing.T) {
	var wire []byte
	for range paddingCount - 1 {
		wire = append(wire, frame(0, 2, 0)...)
	}

	connection := &paddingConn{enabled: true}
	buffer := make([]byte, 64)
	n, err := connection.readWithPadding(bytes.NewReader(wire), buffer)
	if n != 0 {
		t.Fatalf("got %d bytes from empty frames", n)
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a stream of only empty frames must end in EOF, got %v", err)
	}
}

// TestTruncatedZeroFrameReportsError asserts a truncated frame is an error, not
// a silent zero-length success.
func TestTruncatedZeroFrameReportsError(t *testing.T) {
	// Declares 10 padding bytes but supplies 2.
	wire := []byte{0, 0, 10, 0, 0}
	connection := &paddingConn{enabled: true}
	buffer := make([]byte, 64)
	n, err := connection.readWithPadding(bytes.NewReader(wire), buffer)
	if err == nil {
		t.Fatalf("a truncated frame must report an error, got n=%d nil", n)
	}
}
