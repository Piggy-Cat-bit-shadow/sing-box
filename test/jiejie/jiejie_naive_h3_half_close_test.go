package jiejie_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// HTTP/3 half-close, the two directions and both padding modes.
//
// The H1 and H2 cases already established the shape and, importantly, established
// that the origin-first direction LOSES the in-flight client bytes on BOTH the
// fork and the reference. H3 is measured the same way so the classification rests
// on evidence rather than on assuming the transports behave alike: HTTP/3 has no
// TCP half-close primitive, so END_STREAM on the request side is the only signal
// and the DATA framing differs from H2.

// dialH3Tunnel opens a CONNECT and returns a handle whose upload side can be
// closed independently of the download side.
func dialH3Tunnel(t *testing.T, port uint16, authority string, padded bool) *h3TunnelConn {
	t.Helper()
	client := dialH3Any(t, "127.0.0.1:"+strconv.Itoa(int(port)))
	if client == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := client.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)

	headers := naiveH3Auth()
	if padded {
		headers.Set("Padding", "~~~~~~~~")
	}
	require.NoError(t, stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: authority},
		Host:   authority,
		Header: headers,
	}))
	response, err := stream.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode,
		"the CONNECT must be accepted before half-close can be measured")
	return &h3TunnelConn{stream: stream, body: response.Body}
}

// h3TunnelConn is a CONNECT stream the test can read, write and half-close.
type h3TunnelConn struct {
	stream interface {
		Write([]byte) (int, error)
		Close() error
	}
	body io.ReadCloser
}

func (c *h3TunnelConn) Write(p []byte) (int, error) { return c.stream.Write(p) }

// CloseWrite signals END_STREAM on the upload direction only.
//
// HTTP/3 has no half-close handshake: closing the request stream's write side is
// the only expression of it, and the response body stays readable.
func (c *h3TunnelConn) CloseWrite() error { return c.stream.Close() }

func (c *h3TunnelConn) Close() error {
	_ = c.stream.Close()
	return c.body.Close()
}

// TestJiejieNaiveHalfCloseH3 covers the client-first direction, padded and raw.
//
// The origin replies only AFTER it observes EOF, so receiving the reply proves the
// upload direction survived the half-close rather than the reply simply arriving
// first.
func TestJiejieNaiveHalfCloseH3(t *testing.T) {
	for _, padded := range []bool{false, true} {
		name := "raw"
		if padded {
			name = "padded"
		}
		t.Run(name, func(t *testing.T) {
			port := startNaiveInboundH3(t)
			const reply = "h3-origin-reply-after-eof"
			// Each subtest gets its OWN origin: startHalfCloseOrigin accepts a
			// single connection, so sharing one across subtests leaves the second
			// one waiting for an accept that never comes.
			origin := startHalfCloseOrigin(t, reply)

			conn := dialH3Tunnel(t, port, origin.addr, padded)
			if conn == nil {
				t.Skip("HTTP/3 is unavailable in this build/environment. This is a " +
					"SKIP, not a pass.")
			}
			defer conn.Close()

			// The padded path frames the UPLOAD too, so the payload goes out as
			// a Naive frame. Sending it raw makes the first four bytes be read as
			// a frame header and the origin receives a truncated payload, which
			// is what an earlier version of this test did.
			const payload = "h3-client-upload"
			outgoing := []byte(payload)
			if padded {
				outgoing = naivePaddingFrame([]byte(payload), 0)
			}
			_, err := conn.Write(outgoing)
			require.NoError(t, err)
			require.NoError(t, conn.CloseWrite(), "the request stream must be closable")

			uploaded, sawEOF := waitForOriginEOF(t, origin)
			verdict := "MATCH"
			if !sawEOF {
				verdict = "REAL-DIFF"
			}
			t.Logf("H3 %s client half-close: verdict=%s uploaded=%q", name, verdict, uploaded)
			require.Equal(t, "MATCH", verdict,
				"the client's END_STREAM must reach the origin as EOF")
			require.Equal(t, payload, string(uploaded))

			// The reply must still arrive after the half-close. On the padded
			// path the SERVER frames its response too, so the bytes on the stream
			// are a 3-byte header followed by payload and padding.
			if padded {
				replyBytes := naiveReadPaddingFrame(t, conn.body)
				require.Equal(t, reply, string(replyBytes),
					"the response direction must survive the client's END_STREAM")
			} else {
				replyBytes := make([]byte, len(reply))
				_, err = io.ReadFull(conn.body, replyBytes)
				require.NoError(t, err,
					"the response direction must survive the client's END_STREAM")
				require.Equal(t, reply, string(replyBytes))
			}
		})
	}
}

// TestJiejieNaiveHalfCloseH3OriginClosesFirst covers the other direction.
//
// The origin writes its reply FIRST and then half-closes its write side, which is
// the opposite order from startHalfCloseOrigin (that one reads to EOF before
// replying, so it cannot express "origin closes first").
//
// The expected outcome - in-flight client bytes being dropped - is the SAME
// behaviour the fork and the reference both exhibit over H1, so this records the
// measurement rather than asserting a delivery neither transport guarantees.
func TestJiejieNaiveHalfCloseH3OriginClosesFirst(t *testing.T) {
	port := startNaiveInboundH3(t)

	const early = "h3-origin-early"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	type originResult struct {
		received string
		sawEOF   bool
	}
	observed := make(chan originResult, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			observed <- originResult{}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

		// Reply WITHOUT waiting for the upload, then half-close the write side
		// while the client may still be sending.
		if _, writeErr := conn.Write([]byte(early)); writeErr != nil {
			observed <- originResult{}
			return
		}
		if tcpConn, isTCP := conn.(*net.TCPConn); isTCP {
			_ = tcpConn.CloseWrite()
		}
		rest, readErr := io.ReadAll(conn)
		observed <- originResult{string(rest), readErr == nil}
	}()

	conn := dialH3Tunnel(t, port, listener.Addr().String(), false)
	if conn == nil {
		t.Skip("HTTP/3 is unavailable in this build/environment. This is a SKIP, not a pass.")
	}
	defer conn.Close()

	// The early reply must arrive: the origin wrote it and only closed its OWN
	// write side, so the download direction carries data that was already sent.
	earlyBytes := make([]byte, len(early))
	_, err = io.ReadFull(conn.body, earlyBytes)
	require.NoError(t, err,
		"a reply the origin wrote before closing its write side must still arrive")
	require.Equal(t, early, string(earlyBytes))

	const late = "h3-late-upload"
	_, writeErr := conn.Write([]byte(late))
	t.Logf("write after the origin finished returned %v", writeErr)
	_ = conn.CloseWrite()

	var result originResult
	select {
	case result = <-observed:
	case <-time.After(25 * time.Second):
		t.Fatal("the origin never finished reading; the tunnel hung instead of " +
			"completing or closing cleanly")
	}
	t.Logf("H3 origin-first: origin received %q of %q (sawEOF=%v)",
		result.received, late, result.sawEOF)

	// Assert only what must hold either way: no hang, and anything delivered is
	// an uncorrupted prefix. The H1 differential showed the reference drops these
	// bytes too, so demanding delivery would demand behaviour the reference does
	// not provide.
	require.LessOrEqual(t, len(result.received), len(late),
		"more bytes arrived than were sent")
	if len(result.received) > 0 {
		require.Equal(t, late[:len(result.received)], result.received,
			"delivered bytes must be an uncorrupted prefix of what was sent")
	}
}
