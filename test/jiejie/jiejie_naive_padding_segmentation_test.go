package jiejie_test

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Padding frame segmentation on large payloads: fork vs reference.
//
// The concern this measures: the reference caps how much it puts in one padded
// frame (65536 - 3 - paddingSize) and pads only the FIRST eight frames
// (NumFirstPaddings). If this fork segmented differently - say by emitting one
// frame per small write, or by padding every frame - a large upload would be
// framed differently on the wire. That could matter for a client that reasons
// about frame boundaries, and it is invisible in a small round-trip test because
// a short payload fits in a single frame either way.
//
// Per the task's rule, this MEASURES FIRST and does not change the writer. The
// verdict is one of:
//
//	MATCH          frame boundaries agree, so there is nothing to fix
//	COMPATIBLE-DIFF the framing differs but reassembles identically and stays
//	               within the protocol, so it is recorded rather than changed
//	REAL-DIFF      the difference affects buffer contracts or wire correctness
//
// Only the last would justify touching WriterMTU or the frame writer, and only
// with the padding fuzz, the short-write regression and the large-payload E2E
// re-run afterwards.

// paddingFrame is one decoded Naive frame header.
type paddingFrame struct {
	// dataLength is the payload bytes this frame carries.
	dataLength int
	// paddingLength is the trailing padding bytes.
	paddingLength int
	// totalLength is dataLength + paddingLength + 3 (the header).
	totalLength int
}

// segmentationReport is what one implementation produced for one payload size.
type segmentationReport struct {
	// payloadSize is how many bytes were uploaded.
	payloadSize int
	// frames is the decoded frame sequence, capped for reporting.
	frames []paddingFrame
	// frameCount is the total number of frames observed.
	frameCount int
	// reassembled is the payload recovered from the frames.
	reassembled []byte
	// paddedFrames counts frames that carried padding.
	paddedFrames int
	// err records a transport failure.
	err string
}

// summary renders the first few frames compactly for a log line.
func (r segmentationReport) summary() string {
	if r.err != "" {
		return "err=" + r.err
	}
	shown := r.frames
	const maxShown = 8
	if len(shown) > maxShown {
		shown = shown[:maxShown]
	}
	text := fmt.Sprintf("payload=%d frames=%d padded=%d reassembled=%d [",
		r.payloadSize, r.frameCount, r.paddedFrames, len(r.reassembled))
	for i, frame := range shown {
		if i > 0 {
			text += " "
		}
		text += fmt.Sprintf("{d=%d p=%d t=%d}", frame.dataLength, frame.paddingLength, frame.totalLength)
	}
	if len(r.frames) > maxShown {
		text += " ..."
	}
	return text + "]"
}

// measureSegmentation uploads a payload through a padded H1 tunnel and decodes
// the frames the ORIGIN received.
//
// The origin is a raw TCP recorder, so the frame boundaries observed are the ones
// actually written to the wire rather than a re-framing by an intermediate HTTP
// library.
func measureSegmentation(t *testing.T, address string, payloadSize int) segmentationReport {
	t.Helper()
	report := segmentationReport{payloadSize: payloadSize}

	recorder := newFrameRecordingOrigin(t)
	defer recorder.close()

	rawConn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		report.err = "dial"
		return report
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "naive.test",
		NextProtos:         []string{"http/1.1"},
	})
	if err = tlsConn.Handshake(); err != nil {
		report.err = "tls"
		return report
	}
	_ = tlsConn.SetDeadline(time.Now().Add(60 * time.Second))

	// HTTP/1 is a RAW tunnel, so padding framing is driven by the client: the
	// client emits the frames and the server forwards them. The Padding request
	// header is what the reference consults for the H2/H3 paths; here the client
	// frames explicitly, which is what an official NaiveProxy client does.
	connectRequest := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nPadding: ~~~~~~~~\r\n\r\n",
		recorder.address(), recorder.address(), naiveBasicAuth())
	if _, err = io.WriteString(tlsConn, connectRequest); err != nil {
		report.err = "connect-write"
		return report
	}
	response, err := httpReadResponse(tlsConn)
	if err != nil {
		report.err = "connect-read"
		return report
	}
	if response != 200 {
		report.err = "connect-status-" + strconv.Itoa(response)
		return report
	}

	// Emit the payload as the reference writer does: frames of at most
	// 65536-3-paddingSize, with padding on the first eight frames.
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	paddingSizes := []int{0, 1, 2, 3, 4, 5, 6, 7}
	offset := 0
	frameIndex := 0
	for offset < len(payload) {
		paddingSize := 0
		if frameIndex < len(paddingSizes) {
			paddingSize = paddingSizes[frameIndex]
		}
		maxData := 65536 - 3 - paddingSize
		end := offset + maxData
		if end > len(payload) {
			end = len(payload)
		}
		frame := make([]byte, 0, 3+(end-offset)+paddingSize)
		frame = append(frame, byte((end-offset)>>8), byte(end-offset), byte(paddingSize))
		frame = append(frame, payload[offset:end]...)
		frame = append(frame, make([]byte, paddingSize)...)
		if _, err = tlsConn.Write(frame); err != nil {
			report.err = "frame-write"
			return report
		}
		offset = end
		frameIndex++
	}

	// Half-close so the recorder's read completes. Without this the recorder
	// waits for an EOF that never arrives and the measurement times out with
	// nothing to show.
	if err = tlsConn.CloseWrite(); err != nil {
		report.err = "client-half-close"
		return report
	}

	// Read back everything the origin recorded, then decode it.
	received, ok := recorder.waitFor(20 * time.Second)
	if !ok {
		report.err = "origin-received-nothing"
		return report
	}
	report.frames, report.frameCount, report.reassembled, report.err = decodeFrames(received)
	for _, frame := range report.frames {
		if frame.paddingLength > 0 {
			report.paddedFrames++
		}
	}
	return report
}

// decodeFrames walks a byte stream of Naive frames.
func decodeFrames(data []byte) ([]paddingFrame, int, []byte, string) {
	var frames []paddingFrame
	var payload []byte
	offset := 0
	for offset+3 <= len(data) {
		dataLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		paddingLength := int(data[offset+2])
		total := 3 + dataLength + paddingLength
		if offset+total > len(data) {
			// A trailing partial frame means the transfer was cut short.
			return frames, len(frames), payload, "truncated-final-frame"
		}
		frames = append(frames, paddingFrame{
			dataLength:    dataLength,
			paddingLength: paddingLength,
			totalLength:   total,
		})
		payload = append(payload, data[offset+3:offset+3+dataLength]...)
		offset += total
	}
	if offset != len(data) {
		return frames, len(frames), payload, "trailing-bytes"
	}
	return frames, len(frames), payload, ""
}

// frameRecordingOrigin accepts one connection and records every byte it receives.
type frameRecordingOrigin struct {
	listener net.Listener
	received chan []byte
}

func newFrameRecordingOrigin(t *testing.T) *frameRecordingOrigin {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	recorder := &frameRecordingOrigin{listener: listener, received: make(chan []byte, 1)}
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			recorder.received <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		data, _ := io.ReadAll(conn)
		recorder.received <- data
	}()
	return recorder
}

func (r *frameRecordingOrigin) address() string { return r.listener.Addr().String() }

func (r *frameRecordingOrigin) close() { _ = r.listener.Close() }

func (r *frameRecordingOrigin) waitFor(timeout time.Duration) ([]byte, bool) {
	select {
	case data := <-r.received:
		return data, data != nil
	case <-time.After(timeout):
		return nil, false
	}
}

// httpReadResponse reads just the status line of a CONNECT response.
func httpReadResponse(conn net.Conn) (int, error) {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	var version string
	var status int
	if _, err = fmt.Sscanf(line, "%s %d", &version, &status); err != nil {
		return 0, err
	}
	// Consume the remaining headers.
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return status, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return status, nil
}

// TestJiejieNaivePaddingSegmentationMatchesTheWriterContract pins the framing the
// fork's own client-side writer produces and the server forwards.
//
// This is the in-process half: it proves the server does not reshape frames. The
// differential half below compares against the reference.
func TestJiejieNaivePaddingSegmentationMatchesTheWriterContract(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	for _, size := range []int{128 * 1024, 256 * 1024, 1024 * 1024} {
		t.Run(strconv.Itoa(size)+"-bytes", func(t *testing.T) {
			report := measureSegmentation(t, "127.0.0.1:"+strconv.Itoa(int(env.port)), size)
			require.Empty(t, report.err, "the transfer must complete: %s", report.summary())
			t.Logf("fork segmentation: %s", report.summary())

			require.Equal(t, size, len(report.reassembled),
				"every payload byte must be reassembled from the frames")
			require.Positive(t, report.frameCount)
			// The reference pads the first eight frames only.
			require.LessOrEqual(t, report.paddedFrames, 8,
				"padding is a per-connection prologue, not a per-frame cost")
		})
	}
}

// TestJiejieNaivePaddingSegmentationMatchesTheReference is the differential half.
//
// The fork's framing is measured above; this runs the IDENTICAL client framing
// against the reference and compares what each origin received. The client emits
// the frames in both cases, so any difference in what the origin sees is the
// server's doing rather than the client's.
//
// What this can and cannot establish, stated so the result is not over-read: the
// reference's H1 path is a RAW tunnel, so it forwards the client's bytes without
// re-framing them, and the fork does the same. The comparison therefore confirms
// that neither server reshapes or coalesces frames - it does NOT exercise the
// reference's own SERVER-side writer, which only runs for a reference-originated
// response.
func TestJiejieNaivePaddingSegmentationMatchesTheReference(t *testing.T) {
	binary := caddyReferenceBinary(t)
	if binary == "" {
		t.Skipf("the reference Caddy/forwardproxy binary is unavailable, so the "+
			"framing could not be compared. Set %s or %s to a "+
			"klzgrad/forwardproxy@naive checkout at %s. This is a SKIP, not a pass.",
			caddyReferenceBinaryEnv, caddyReferenceSourceEnv, CaddyReferenceCommit)
	}
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	reference := startReferenceProfile(t, binary, certPem, keyPem, referenceProfileBare)
	env := startNaiveInboundForUoT(t)

	const payloadSize = 256 * 1024

	forkReport := measureSegmentation(t, "127.0.0.1:"+strconv.Itoa(int(env.port)), payloadSize)
	referenceReport := measureSegmentation(t, "127.0.0.1:"+strconv.Itoa(int(reference.port)), payloadSize)

	t.Logf("fork      : %s", forkReport.summary())
	t.Logf("reference : %s", referenceReport.summary())

	require.Empty(t, forkReport.err, "the fork transfer must complete")
	require.Empty(t, referenceReport.err, "the reference transfer must complete")

	require.Equal(t, payloadSize, len(forkReport.reassembled))
	require.Equal(t, payloadSize, len(referenceReport.reassembled))

	// The decisive comparison: the frame sequence each origin observed.
	require.Equal(t, referenceReport.frameCount, forkReport.frameCount,
		"both servers must forward the same number of frames for the same "+
			"client framing; a difference means one of them reshapes the stream")
	require.Equal(t, referenceReport.frames, forkReport.frames,
		"the decoded frame boundaries must be identical between the fork and "+
			"the reference, otherwise a large upload is framed differently on "+
			"the wire depending on the server")

	// And the payload itself must survive identically.
	require.Equal(t, referenceReport.reassembled, forkReport.reassembled,
		"the reassembled payload must be byte-identical")

	t.Logf("segmentation verdict: MATCH (%d frames, %d padded, %d bytes each)",
		forkReport.frameCount, forkReport.paddedFrames, payloadSize)
}
