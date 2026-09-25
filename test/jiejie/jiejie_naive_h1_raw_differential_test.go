package jiejie_test

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// H1 tunnel framing, decided by BYTE-FOR-BYTE observation at the origin.
//
// The pinned reference source is unambiguous:
//
//	case 1:
//	    return serveHijack(w, targetConn)
//
// and serveHijack ends in
//
//	return dualStream(targetConn, clientConn, clientConn, false)   // padding = false
//
// so an HTTP/1 tunnel is RAW regardless of the Padding header. An earlier version
// of the differential harness nevertheless reported that the reference answered
// raw bytes with 407, and recorded that as a KNOWN-DIFF. That report was a PROBE
// ARTIFACT: the reference also enforces a connection ACL (dialContextCheckACL)
// which denies loopback by default, so it flushed 200 (CONNECT fast open) and
// then refused the dial with 403, and the probe misread the following stream as a
// fresh HTTP response.
//
// This file settles the question the only way that cannot be argued with: a RAW
// TCP RECORDING ORIGIN that never parses HTTP. It accepts, reads the exact bytes,
// and records them. Whatever arrives is reported as hex, and the two
// implementations are compared byte for byte.
//
// If the runtime ever disagreed with the pinned source, this test would show it
// rather than hide it behind a divergence label.

// byteRecordingOrigin is a TCP origin that records everything it receives without
// interpreting it.
type byteRecordingOrigin struct {
	address string

	mu       sync.Mutex
	received []byte
	accepted int
	conns    chan struct{}
}

// startByteRecordingOrigin binds a raw recording origin on loopback.
func startByteRecordingOrigin(t *testing.T) *byteRecordingOrigin {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	origin := &byteRecordingOrigin{
		address: listener.Addr().String(),
		conns:   make(chan struct{}, 8),
	}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			origin.mu.Lock()
			origin.accepted++
			origin.mu.Unlock()
			select {
			case origin.conns <- struct{}{}:
			default:
			}
			go func() {
				defer conn.Close()
				// Read for a bounded window; the client stops writing and the
				// connection is not necessarily closed, so a read deadline is the
				// only way to know the byte stream has settled.
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				buffer := make([]byte, 4096)
				for {
					n, readErr := conn.Read(buffer)
					if n > 0 {
						origin.mu.Lock()
						origin.received = append(origin.received, buffer[:n]...)
						origin.mu.Unlock()
					}
					if readErr != nil {
						return
					}
				}
			}()
		}
	}()
	return origin
}

// bytes returns a copy of everything received so far.
func (o *byteRecordingOrigin) bytes() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]byte(nil), o.received...)
}

// waitForBytes waits until at least n bytes arrive or the deadline passes.
func (o *byteRecordingOrigin) waitForBytes(n int) []byte {
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if got := o.bytes(); len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	return o.bytes()
}

// h1ProbeResult is what one implementation did with a given payload.
type h1ProbeResult struct {
	status      int
	receivedHex string
	receivedLen int
	err         string
}

// runH1Probe performs an authenticated H1 CONNECT and then writes `payload`
// verbatim into the tunnel, returning what the origin recorded.
func runH1Probe(t *testing.T, address, target string, withPadding bool, payload []byte) h1ProbeResult {
	t.Helper()
	var result h1ProbeResult

	origin := startByteRecordingOrigin(t)
	_ = origin

	raw, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		result.err = "dial: " + err.Error()
		return result
	}
	defer raw.Close()
	tlsConn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "naive.test",
		NextProtos:         []string{"http/1.1"},
	})
	if err = tlsConn.Handshake(); err != nil {
		result.err = "tls: " + err.Error()
		return result
	}
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))

	request := "CONNECT " + origin.address + " HTTP/1.1\r\n" +
		"Host: " + origin.address + "\r\n" +
		"Proxy-Authorization: Basic " + basicAuthValue() + "\r\n"
	if withPadding {
		request += "Padding: ~~~~~~~~\r\n"
	}
	request += "\r\n"
	if _, err = io.WriteString(tlsConn, request); err != nil {
		result.err = "write request: " + err.Error()
		return result
	}

	response, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		result.err = "read response: " + err.Error()
		return result
	}
	result.status = response.StatusCode
	if response.StatusCode != http.StatusOK {
		return result
	}

	if _, err = tlsConn.Write(payload); err != nil {
		result.err = "write payload: " + err.Error()
		return result
	}

	got := origin.waitForBytes(len(payload))
	result.receivedLen = len(got)
	result.receivedHex = hexOf(got)
	return result
}

func hexOf(data []byte) string {
	const digits = "0123456789abcdef"
	var builder strings.Builder
	for _, b := range data {
		builder.WriteByte(digits[b>>4])
		builder.WriteByte(digits[b&0x0f])
	}
	return builder.String()
}

// TestJiejieNaiveH1TunnelIsRawByByteComparison decides H1 framing by observation.
//
// Two payloads are sent: arbitrary binary that is NOT a valid HTTP request, and a
// well-formed Naive padding frame. In both cases the origin must receive exactly
// the bytes written, because the reference's HTTP/1 tunnel is raw.
//
// The binary payload matters: if the reference were re-parsing tunnel bytes as
// HTTP, valid-looking data could be misread as a request and an invalid-looking
// one could not, so a request-shaped payload alone would not settle the question.
func TestJiejieNaiveH1TunnelIsRawByByteComparison(t *testing.T) {
	env := startNaiveInbound(t, false)

	// Arbitrary binary. Never valid HTTP, so if either implementation parses the
	// tunnel as HTTP this payload cannot survive.
	binaryPayload := []byte{0x01, 0x02, 0x03, 0x04, 0xff, 0xfe, 0x00, 0x7f}

	// A literal Naive padding frame: 2-byte length, 1-byte padding size, payload,
	// then that many zero bytes. Sent as opaque bytes; whether the server frames
	// or not is exactly what is being measured.
	framePayload := make([]byte, 0, 3+5+3)
	framePayload = append(framePayload, 0x00, 0x05, 0x03)
	framePayload = append(framePayload, []byte("HELLO")...)
	framePayload = append(framePayload, 0x00, 0x00, 0x00)

	for _, testCase := range []struct {
		name        string
		payload     []byte
		withPadding bool
	}{
		{"binary payload, request with Padding", binaryPayload, true},
		{"binary payload, request without Padding", binaryPayload, false},
		{"naive frame payload, request with Padding", framePayload, true},
		{"naive frame payload, request without Padding", framePayload, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			result := runH1Probe(t, "127.0.0.1:"+strconv.Itoa(int(env.port)),
				env.originAddr, testCase.withPadding, testCase.payload)

			require.Empty(t, result.err, "the probe must complete")
			require.Equal(t, http.StatusOK, result.status,
				"an authenticated CONNECT must be accepted")

			want := hexOf(testCase.payload)
			require.Equal(t, want, result.receivedHex,
				"the HTTP/1 tunnel must deliver the bytes VERBATIM.\n"+
					"  sent:     %s\n  received: %s\n"+
					"A difference means the server either framed bytes that should "+
					"have passed through, or stripped framing that should have been "+
					"preserved. The reference's serveHijack ends in dualStream(..., "+
					"false), so HTTP/1 is unframed in both directions.",
				want, result.receivedHex)
			t.Logf("sent %d bytes, origin received exactly %d bytes: %s",
				len(testCase.payload), result.receivedLen, result.receivedHex)
		})
	}
}

// TestJiejieNaiveH1RawDifferentialAgainstReference runs the same probe against
// the pinned reference and against sing-box and compares the ORIGIN BYTES.
//
// This is the differential that the earlier harness got wrong. It SKIPs, with the
// reason stated, when the reference cannot be built - never passing silently.
func TestJiejieNaiveH1RawDifferentialAgainstReference(t *testing.T) {
	requireFullNaiveRegistry(t)

	binary := caddyReferenceBinary(t)
	if binary == "" {
		t.Skipf("the reference Caddy/forwardproxy binary is unavailable, so no "+
			"differential comparison was performed. Set %s to a built reference "+
			"or %s to a klzgrad/forwardproxy@naive checkout at %s. This is a "+
			"SKIP, not a pass.", caddyReferenceBinaryEnv, caddyReferenceSourceEnv,
			CaddyReferenceCommit)
	}

	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	referencePort, _ := startCaddyReference(t, binary, certPem, keyPem)

	// The reference must be allowed to reach the test origin. Its default ACL
	// denies loopback, and that denial is what produced the earlier false "407"
	// observation, so the reference used here is started with the origin allowed.
	_ = referencePort

	env := startNaiveInbound(t, false)

	payloads := []struct {
		name    string
		payload []byte
	}{
		{"arbitrary binary", []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}},
		{"naive frame", []byte{0x00, 0x03, 0x02, 'A', 'B', 'C', 0x00, 0x00}},
	}

	for _, testCase := range payloads {
		t.Run(testCase.name, func(t *testing.T) {
			singBoxResult := runH1Probe(t, "127.0.0.1:"+strconv.Itoa(int(env.port)),
				env.originAddr, true, testCase.payload)
			require.Empty(t, singBoxResult.err)

			referenceResult := runH1Probe(t,
				"127.0.0.1:"+strconv.Itoa(int(referencePort)),
				"", true, testCase.payload)
			if referenceResult.err != "" {
				t.Skipf("the reference probe did not complete (%s), so no "+
					"comparison was possible. This is a SKIP, not a pass.",
					referenceResult.err)
			}

			t.Logf("reference: status=%d bytes=%s", referenceResult.status, referenceResult.receivedHex)
			t.Logf("sing-box:  status=%d bytes=%s", singBoxResult.status, singBoxResult.receivedHex)

			require.Equal(t, referenceResult.status, singBoxResult.status,
				"both implementations must answer the same status")
			require.Equal(t, referenceResult.receivedHex, singBoxResult.receivedHex,
				"the two implementations must deliver the SAME bytes to the origin "+
					"for the same tunnelled payload")
		})
	}
}
