package jiejie_test

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// DETERMINISTIC REGRESSION TEST for the root cause of the intermittent UoT
// datagram loss.
//
// Root cause, proven by the instrumented harness: when the client's CONNECT
// request and its first tunnel bytes arrive close enough together, net/http reads
// the tunnel bytes into the connection's bufio.Reader while parsing the request.
// The inbound discarded that reader, so the tunnel began mid-stream and the
// datagram never left the server. The evidence was an aggregate echo count of 999
// against 1000 client sends, with the failing Packet ID having NO server-side
// event at all.
//
// The generic hijack test writes everything in one Write, which is deterministic.
// THIS test instead reproduces the RACE: the CONNECT request and the tunnel bytes
// are written as two separate writes with no delay, so the server may or may not
// have buffered them together depending on scheduling. That is exactly the shape
// the original 1% loss had, and running many iterations makes it reliable.
//
// Without the fix this test fails; with it, every iteration succeeds.

// TestJiejieHijackCoalescedProbeRace drives many sessions where the request and
// the first tunnel frame are separate writes with no delay between them.
func TestJiejieHijackCoalescedProbeRace(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	trace := newTrace()
	echo := startInstrumentedEcho(t, trace)

	const (
		iterations  = 400
		concurrency = 8
		replyWait   = 2 * time.Second
	)

	var (
		mu       sync.Mutex
		failures []string
		nextID   uint32
		wg       sync.WaitGroup
	)
	allocateID := func() uint32 {
		mu.Lock()
		defer mu.Unlock()
		nextID++
		return nextID
	}

	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations / concurrency {
				id := allocateID()
				if err := raceOneSession(env.port, echo.address, id, trace); err != nil {
					mu.Lock()
					failures = append(failures, fmt.Sprintf("packet %d: %v\n%s",
						id, err, trace.summarizeFor(id)))
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	if len(failures) > 0 {
		for _, line := range failures {
			t.Log(line)
		}
	}
	t.Logf("coalesced-probe race: %d iterations, %d failures; echo.ReadFromUDP=%d",
		iterations, len(failures), trace.countStage(StageEchoReadFromUDP))

	require.Empty(t, failures,
		"no datagram may be lost when the CONNECT request and the first tunnel "+
			"frame arrive close together: a lost datagram here means the buffered "+
			"request bytes were discarded and the tunnel started mid-stream")
}

// raceOneSession writes the CONNECT request and the UoT prologue as two separate
// writes with no delay, which is what creates the coalescing window.
func raceOneSession(port uint16, echoAddress string, packetID uint32, trace *Trace) error {
	raw, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer raw.Close()

	tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
	if err = tlsConn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))

	magic := uot.RequestDestination(uot.Version).String()
	request := "CONNECT " + magic + " HTTP/1.1\r\nHost: " + magic + "\r\n" +
		"Proxy-Authorization: " + naiveBasicAuth() + "\r\nPadding: ~~~~~~~~\r\n\r\n"

	// Write 1: the CONNECT request alone.
	if _, err = io.WriteString(tlsConn, request); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	// Write 2: the UoT v2 request header, IMMEDIATELY, with no delay. Whether the
	// server has already hijacked by now is a race -- and that race is the bug.
	writer := &sliceWriter{}
	if err = metadata.SocksaddrSerializer.WriteAddrPort(writer,
		metadata.ParseSocksaddr(echoAddress)); err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	// Raw, not framed: this session is HTTP/1, which is an unframed tunnel in the
	// reference (serveHijack -> dualStream(..., false)). The Padding header in the
	// request still causes a response Padding header, but it does not enable
	// Naive framing on this transport.
	if _, err = tlsConn.Write(append([]byte{1}, writer.data...)); err != nil {
		return fmt.Errorf("write uot header: %w", err)
	}

	// Read the CONNECT response through a reader we KEEP, so no tunnel bytes are
	// dropped on the client side either.
	reader := bufio.NewReader(tlsConn)
	if _, err = readHTTPResponseHead(reader); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Write 3: the datagram carrying the Packet ID.
	payload := encodePacketWithID(packetID, "race")
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	if _, err = tlsConn.Write(append(length, payload...)); err != nil {
		return fmt.Errorf("write datagram: %w", err)
	}

	// The reply must carry the SAME Packet ID. Raw tunnel, so the reply is the
	// UoT datagram itself: a 2-byte length prefix followed by the payload.
	body := make([]byte, 2+len(payload))
	if _, err = io.ReadFull(reader, body); err != nil {
		return fmt.Errorf("read reply: %w", err)
	}
	if len(body) < 2 {
		return fmt.Errorf("short reply: %d bytes", len(body))
	}
	got := payloadPacketID(body[2:])
	if got != packetID {
		return fmt.Errorf("reply Packet ID mismatch: got %d want %d", got, packetID)
	}
	return nil
}
