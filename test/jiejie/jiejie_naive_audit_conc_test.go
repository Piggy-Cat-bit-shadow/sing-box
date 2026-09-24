package jiejie_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// AUDIT: 20 concurrent HTTP/2 streams, alternating TCP echo and UoT UDP echo,
// each with distinct verifiable payloads. Any cross-stream contamination or
// padding frame misalignment shows up as a byte mismatch.
func TestAuditH2ConcurrencyDataIntegrity(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	// A dedicated TCP echo origin for the TCP streams.
	tcpEcho := startNaiveTCPEcho(t)

	const streams = 20
	type result struct {
		index int
		err   error
	}
	results := make(chan result, streams)

	conn := naiveTLSConn(t, env.port, http2.NextProtoTLS)
	clientConn, err := (&http2.Transport{}).NewClientConn(conn)
	require.NoError(t, err)
	defer clientConn.Close()

	var wg sync.WaitGroup
	for i := range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				results <- result{i, auditH2TCPStream(clientConn, tcpEcho, i)}
			} else {
				results <- result{i, auditH2UoTStream(clientConn, env.echoAddr, i)}
			}
		}()
	}
	wg.Wait()
	close(results)

	failures := 0
	for r := range results {
		if r.err != nil {
			failures++
			t.Errorf("stream %d failed: %v", r.index, r.err)
		}
	}
	require.Zero(t, failures, "%d/%d concurrent streams failed", failures, streams)
}

// auditH2TCPStream sends a unique payload through a CONNECT tunnel and expects it
// echoed back byte-for-byte.
func auditH2TCPStream(clientConn *http2.ClientConn, echoAddr string, index int) error {
	pipeReader, pipeWriter := io.Pipe()
	defer pipeWriter.Close()

	response, err := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: echoAddr},
		Host:   echoAddr,
		Header: http.Header{
			"Proxy-Authorization": []string{naiveBasicAuth()},
			"Padding":             []string{"~~~~~~~~"},
		},
		Body: pipeReader,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", response.StatusCode)
	}

	// A distinct payload per stream, long enough to span several padding frames.
	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte('A' + index%26)
	}
	if _, err = pipeWriter.Write(naivePaddingFrame(payload, 0)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	echoed := readPaddingFrameRaw(response.Body)
	if string(echoed) != string(payload) {
		return fmt.Errorf("TCP payload mismatch: sent %d bytes, got %d bytes "+
			"(first sent %q first got %q)", len(payload), len(echoed), payload[:8], echoed[:minInt(8, len(echoed))])
	}
	return nil
}

// auditH2UoTStream runs a UoT v2 session on its own HTTP/2 stream.
func auditH2UoTStream(clientConn *http2.ClientConn, echoAddr string, index int) error {
	pipeReader, pipeWriter := io.Pipe()
	defer pipeWriter.Close()

	magic := uot.RequestDestination(uot.Version).String()
	response, err := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: magic},
		Host:   magic,
		Header: http.Header{
			"Proxy-Authorization": []string{naiveBasicAuth()},
			"Padding":             []string{"~~~~~~~~"},
		},
		Body: pipeReader,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("uot status %d", response.StatusCode)
	}

	writer := &sliceWriter{}
	if err = metadata.SocksaddrSerializer.WriteAddrPort(writer, metadata.ParseSocksaddr(echoAddr)); err != nil {
		return err
	}
	if _, err = pipeWriter.Write(naivePaddingFrame(append([]byte{1}, writer.data...), 0)); err != nil {
		return err
	}

	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte('a' + index%26)
	}
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	if _, err = pipeWriter.Write(naivePaddingFrame(append(length, payload...), 0)); err != nil {
		return err
	}

	frame, err := readPaddingFrameRaw2(response.Body)
	if err != nil {
		return err
	}
	if len(frame) < 2 || string(frame[2:]) != string(payload) {
		return fmt.Errorf("UoT payload mismatch on stream %d", index)
	}
	return nil
}

// readPaddingFrameRaw decodes one padding frame without testing.T, for goroutines.
func readPaddingFrameRaw(r io.Reader) []byte {
	data, _ := readPaddingFrameRaw2(r)
	return data
}

func readPaddingFrameRaw2(r io.Reader) ([]byte, error) {
	h := make([]byte, 3)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	size := int(h[0])<<8 | int(h[1])
	pad := int(h[2])
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	if pad > 0 {
		if _, err := io.ReadFull(r, make([]byte, pad)); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// startNaiveTCPEcho starts a TCP echo server that echoes exactly what it receives.
func startNaiveTCPEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer c.Close()
				// The origin is a plain TCP peer: it echoes RAW bytes. The tunnel
				// applies the padding framing, so re-framing here would double it.
				buffer := make([]byte, 4096)
				for {
					n, readErr := c.Read(buffer)
					if n > 0 {
						if _, writeErr := c.Write(buffer[:n]); writeErr != nil {
							return
						}
					}
					if readErr != nil {
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().String()
}
