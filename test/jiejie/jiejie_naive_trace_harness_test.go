package jiejie_test

import (
	"bufio"
	stdTLS "crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// Instrumented UoT harness for locating the intermittent datagram loss.
//
// Every packet carries a unique Packet ID, and every hop in the data path records
// an event against that ID with a timestamp. When a session fails, the trace
// shows the LAST event that succeeded and the FIRST that failed, which is what
// distinguishes "the server never received it" from "the reply never came back".
//
// The previous investigation could only say "the padding layer read the frames"
// and therefore concluded the loss was downstream in shared code. That conclusion
// was not proven: it did not record the outbound UDP write, the echo's receive,
// the echo's reply write, or the tunnel write. This harness records all of them.

// EventStage names a hop in the data path.
type EventStage string

const (
	StageUoTReadPacket   EventStage = "uot.ReadPacket"   // server: frame decoded
	StageRouterUDPWrite  EventStage = "router.UDPWrite"  // server: sent to the UDP target
	StageEchoReadFromUDP EventStage = "echo.ReadFromUDP" // echo: received
	StageEchoWriteToUDP  EventStage = "echo.WriteToUDP"  // echo: replied
	StageOutboundUDPRead EventStage = "outbound.UDPRead" // server: got the reply
	StageUoTWritePacket  EventStage = "uot.WritePacket"  // server: framed the reply
	StageNaiveTCPWrite   EventStage = "naive.Write"      // server: wrote to the tunnel
	StageClientReceived  EventStage = "client.Received"  // test: client got the payload
)

// TraceEvent is one observation, tied to a Packet ID.
type TraceEvent struct {
	PacketID  uint32
	Stage     EventStage
	At        time.Time
	Detail    string
	Err       error
	SessionID int
}

// Trace collects events from every hop. It is safe for concurrent use.
type Trace struct {
	mu     sync.Mutex
	events []TraceEvent
}

func newTrace() *Trace { return &Trace{} }

func (t *Trace) record(sessionID int, packetID uint32, stage EventStage, detail string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, TraceEvent{
		PacketID:  packetID,
		Stage:     stage,
		At:        time.Now(),
		Detail:    detail,
		Err:       err,
		SessionID: sessionID,
	})
}

// eventsFor returns the recorded events for one Packet ID, in order.
func (t *Trace) eventsFor(packetID uint32) []TraceEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []TraceEvent
	for _, event := range t.events {
		if event.PacketID == packetID {
			out = append(out, event)
		}
	}
	return out
}

// countStage counts how many times a stage was reached for any packet.
func (t *Trace) countStage(stage EventStage) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	for _, event := range t.events {
		if event.Stage == stage {
			count++
		}
	}
	return count
}

// summarizeFor renders the timeline for one Packet ID as a readable string.
func (t *Trace) summarizeFor(packetID uint32) string {
	events := t.eventsFor(packetID)
	if len(events) == 0 {
		return fmt.Sprintf("packet %d: NO EVENTS AT ALL", packetID)
	}
	base := events[0].At
	var out string
	for _, event := range events {
		line := fmt.Sprintf("packet %d  +%7.3fms  %-20s %s",
			event.PacketID, float64(event.At.Sub(base).Microseconds())/1000.0, event.Stage, event.Detail)
		if event.Err != nil {
			line += fmt.Sprintf("  ERR=%v", event.Err)
		}
		out += line + "\n"
	}
	return out
}

// InstrumentedEcho is a UDP echo server that records every packet and never
// discards an error, which is what the previous echo server did.
type InstrumentedEcho struct {
	conn    *net.UDPConn
	address string
	trace   *Trace
}

// startInstrumentedEcho starts a recording UDP echo server.
//
// The Packet ID is the FIRST 4 BYTES of the payload, written big-endian. The
// echo reads it, records the REAL source address it observed, writes the reply,
// and records the write result INCLUDING the byte count and any error -- the
// previous echo used `_, _ = WriteToUDP(...)`, which would have hidden a failure.
func startInstrumentedEcho(t *testing.T, trace *Trace) *InstrumentedEcho {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	echo := &InstrumentedEcho{conn: conn, address: conn.LocalAddr().String(), trace: trace}
	go func() {
		buffer := make([]byte, 64*1024)
		for {
			n, from, readErr := conn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			packetID := payloadPacketID(buffer[:n])
			echo.trace.record(0, packetID, StageEchoReadFromUDP,
				fmt.Sprintf("n=%d from=%s (echo's real observed source)", n, from), nil)

			written, writeErr := conn.WriteToUDP(buffer[:n], from)
			echo.trace.record(0, packetID, StageEchoWriteToUDP,
				fmt.Sprintf("n=%d to=%s", written, from), writeErr)
			if writeErr != nil {
				// Recorded, not swallowed. A failed echo write is a real cause of
				// a lost reply and must be visible.
				continue
			}
			if written != n {
				echo.trace.record(0, packetID, StageEchoWriteToUDP,
					fmt.Sprintf("SHORT WRITE: wrote %d of %d", written, n), io.ErrShortWrite)
			}
		}
	}()
	return echo
}

// payloadPacketID extracts the big-endian Packet ID from the first 4 bytes.
func payloadPacketID(payload []byte) uint32 {
	if len(payload) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(payload[:4])
}

// encodePacketWithID builds a payload whose first 4 bytes are the Packet ID.
func encodePacketWithID(packetID uint32, tail string) []byte {
	out := make([]byte, 4, 4+len(tail))
	binary.BigEndian.PutUint32(out, packetID)
	return append(out, []byte(tail)...)
}

// uotTraceSession is one UoT v2 session instrumented with a Trace.
type uotTraceSession struct {
	conn        io.Writer
	reader      *bufio.Reader
	padding     bool
	sessionID   int
	trace       *Trace
	echoAddress string
	// framesSent and framesReceived track the BOUNDED padding window on each
	// direction independently, because the window is 8 frames per direction.
	framesSent     int
	framesReceived int
	// closeFn releases the session's transport. Using a function keeps the
	// HTTP/1.1 and HTTP/2 lifetimes together without a type switch at each call.
	closeFn func()

	// replies carries decoded reply payloads from a single background reader.
	//
	// awaitReply must NOT start a fresh read per call: on a timeout the old
	// reader stays blocked on the stream, and a second call would race it for
	// the same bytes, so a reply that DID arrive could be swallowed by the
	// abandoned goroutine and reported as a timeout. One reader owns the stream
	// and hands payloads over by channel.
	replies     chan []byte
	readerOnce  sync.Once
	readerErr   error
	readerErrMu sync.Mutex
}

// startReplyReader launches the single background reader for this session.
func (s *uotTraceSession) startReplyReader() {
	s.readerOnce.Do(func() {
		s.replies = make(chan []byte, 16)
		go func() {
			defer close(s.replies)
			for {
				payload, err := s.readFrame()
				if err != nil {
					s.readerErrMu.Lock()
					if s.readerErr == nil {
						s.readerErr = err
					}
					s.readerErrMu.Unlock()
					return
				}
				s.replies <- payload
			}
		}()
	})
}

// replyReaderError returns the terminal reader error, if any.
func (s *uotTraceSession) replyReaderError() error {
	s.readerErrMu.Lock()
	defer s.readerErrMu.Unlock()
	return s.readerErr
}

// close releases the session.
func (s *uotTraceSession) close() {
	if s.closeFn != nil {
		s.closeFn()
	}
}

// dialTracedUoT opens a UoT v2 session over HTTP/2 and sends the request header.
//
// HTTP/2 is used deliberately: the task requires the HTTP/1.1 and HTTP/2 cases to
// be measured separately rather than assuming the transport is irrelevant.
func dialTracedUoT(t *testing.T, port uint16, echoAddress string, sessionID int, trace *Trace) *uotTraceSession {
	t.Helper()
	conn := naiveTLSConn(t, port, http2.NextProtoTLS)
	clientConn, err := (&http2.Transport{}).NewClientConn(conn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientConn.Close() })

	pipeReader, pipeWriter := io.Pipe()
	t.Cleanup(func() { _ = pipeWriter.Close() })

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
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	t.Cleanup(func() { _ = response.Body.Close() })

	writer := &sliceWriter{}
	require.NoError(t, metadata.SocksaddrSerializer.WriteAddrPort(writer,
		metadata.ParseSocksaddr(echoAddress)))
	if _, err = pipeWriter.Write(naivePaddingFrame(append([]byte{1}, writer.data...), 0)); err != nil {
		t.Fatal(err)
	}

	return &uotTraceSession{
		conn:        pipeWriter,
		reader:      bufio.NewReader(response.Body),
		padding:     true,
		sessionID:   sessionID,
		trace:       trace,
		echoAddress: echoAddress,
	}
}

// openTracedSession opens a UoT session over the named transport.
//
// The three transports are kept separate because the earlier loss was observed
// only through the HTTP/1.1 helper. Measuring them independently is what makes it
// possible to say whether the transport matters, instead of assuming it.
func openTracedSession(t *testing.T, port uint16, echoAddress string, sessionID int, trace *Trace, transport string) (*uotTraceSession, error) {
	t.Helper()
	switch transport {
	case "http2-padded":
		return dialTracedUoTH2(t, port, echoAddress, sessionID, trace, true)
	case "http1-padded":
		return dialTracedUoTH1(t, port, echoAddress, sessionID, trace, true)
	case "http1-unpadded":
		return dialTracedUoTH1(t, port, echoAddress, sessionID, trace, false)
	default:
		return nil, fmt.Errorf("unknown transport %q", transport)
	}
}

// dialTracedUoTH2 opens a UoT session over HTTP/2.
func dialTracedUoTH2(t *testing.T, port uint16, echoAddress string, sessionID int, trace *Trace, padded bool) (*uotTraceSession, error) {
	t.Helper()
	conn := naiveTLSConn(t, port, http2.NextProtoTLS)
	clientConn, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		return nil, err
	}
	pipeReader, pipeWriter := io.Pipe()

	headers := http.Header{"Proxy-Authorization": []string{naiveBasicAuth()}}
	if padded {
		headers.Set("Padding", "~~~~~~~~")
	}
	magic := uot.RequestDestination(uot.Version).String()
	response, err := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: magic},
		Host:   magic,
		Header: headers,
		Body:   pipeReader,
	})
	if err != nil {
		_ = pipeWriter.Close()
		_ = clientConn.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		_ = pipeWriter.Close()
		_ = response.Body.Close()
		_ = clientConn.Close()
		return nil, fmt.Errorf("CONNECT status %d", response.StatusCode)
	}

	session := &uotTraceSession{
		conn:        pipeWriter,
		reader:      bufio.NewReader(response.Body),
		padding:     padded,
		sessionID:   sessionID,
		trace:       trace,
		echoAddress: echoAddress,
		closeFn: func() {
			_ = pipeWriter.Close()
			_ = response.Body.Close()
			_ = clientConn.Close()
		},
	}

	// The UoT v2 request header is the first frame on the tunnel.
	writer := &sliceWriter{}
	if err = metadata.SocksaddrSerializer.WriteAddrPort(writer, metadata.ParseSocksaddr(echoAddress)); err != nil {
		session.close()
		return nil, err
	}
	requestPayload := append([]byte{1}, writer.data...)
	var frame []byte
	if padded {
		frame = naivePaddingFrame(requestPayload, 0)
		session.framesSent++
	} else {
		frame = requestPayload
	}
	if _, err = pipeWriter.Write(frame); err != nil {
		session.close()
		return nil, err
	}
	return session, nil
}

// dialTracedUoTH1 opens a UoT session over HTTP/1.1 by hijacking a raw CONNECT.
//
// This is the transport the earlier loss was observed on, so it must be measured
// on its own rather than folded into the HTTP/2 numbers.
func dialTracedUoTH1(t *testing.T, port uint16, echoAddress string, sessionID int, trace *Trace, padded bool) (*uotTraceSession, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 10*time.Second)
	if err != nil {
		return nil, err
	}
	tlsConn := stdTLS.Client(raw, &stdTLS.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
	if err = tlsConn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))

	magic := uot.RequestDestination(uot.Version).String()
	crlf := "\r\n"
	request := "CONNECT " + magic + " HTTP/1.1" + crlf +
		"Host: " + magic + crlf +
		"Proxy-Authorization: " + naiveBasicAuth() + crlf
	if padded {
		request += "Padding: ~~~~~~~~" + crlf
	}
	request += crlf
	if _, err = io.WriteString(tlsConn, request); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	reader := bufio.NewReader(tlsConn)
	status, err := readHTTPResponseHead(reader)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if status != http.StatusOK {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("CONNECT status %d", status)
	}

	session := &uotTraceSession{
		conn:        tlsConn,
		reader:      reader,
		padding:     padded,
		sessionID:   sessionID,
		trace:       trace,
		echoAddress: echoAddress,
		closeFn:     func() { _ = tlsConn.Close() },
	}

	writer := &sliceWriter{}
	if err = metadata.SocksaddrSerializer.WriteAddrPort(writer, metadata.ParseSocksaddr(echoAddress)); err != nil {
		session.close()
		return nil, err
	}
	requestPayload := append([]byte{1}, writer.data...)
	var frame []byte
	if padded {
		frame = naivePaddingFrame(requestPayload, 0)
		session.framesSent++
	} else {
		frame = requestPayload
	}
	if _, err = tlsConn.Write(frame); err != nil {
		session.close()
		return nil, err
	}
	return session, nil
}

// sendDatagram sends one Packet ID and records the send.
func (s *uotTraceSession) sendDatagram(t *testing.T, packetID uint32) error {
	t.Helper()
	payload := encodePacketWithID(packetID, "payload")
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	body := append(length, payload...)

	var frame []byte
	// The padding window is bounded at 8 frames; past it the tunnel is raw.
	if s.padding && s.framesSent < 8 {
		frame = naivePaddingFrame(body, 0)
	} else {
		frame = body
	}
	s.framesSent++

	written, err := s.conn.Write(frame)
	if err != nil {
		s.trace.record(s.sessionID, packetID, StageNaiveTCPWrite,
			fmt.Sprintf("client->server write failed (wrote %d of %d)", written, len(frame)), err)
		return err
	}
	return nil
}

// awaitReply reads one reply frame and records the outcome against packetID.
//
// A bounded read deadline is used so a lost reply is reported as a timeout on a
// specific Packet ID rather than hanging the whole run.
func (s *uotTraceSession) awaitReply(t *testing.T, packetID uint32, timeout time.Duration) error {
	t.Helper()
	s.startReplyReader()

	deadline := time.After(timeout)
	for {
		select {
		case payload, open := <-s.replies:
			if !open {
				err := fmt.Errorf("session closed before a reply to packet %d arrived: %w",
					packetID, s.replyReaderError())
				s.trace.record(s.sessionID, packetID, StageClientReceived,
					"stream ended", err)
				return err
			}
			receivedID := payloadPacketID(payload)
			if receivedID != packetID {
				// A reply for another Packet ID is recorded and skipped rather
				// than mistaken for this one. This is what makes the withheld-
				// reply scenario observable: the first datagram's reply never
				// comes, so any payload arriving must belong to a later packet.
				s.trace.record(s.sessionID, receivedID, StageClientReceived,
					fmt.Sprintf("reply for a different packet id=%d (skipped while waiting for %d)",
						receivedID, packetID), nil)
				continue
			}
			s.trace.record(s.sessionID, packetID, StageClientReceived,
				fmt.Sprintf("received %d bytes, id matches", len(payload)), nil)
			return nil
		case <-deadline:
			err := fmt.Errorf("timeout after %v waiting for reply to packet %d", timeout, packetID)
			s.trace.record(s.sessionID, packetID, StageClientReceived, "TIMEOUT", err)
			return err
		}
	}
}

// readFrame reads one reply, decoding a padding frame while the window is open.
func (s *uotTraceSession) readFrame() ([]byte, error) {
	if s.padding && s.framesReceived < 8 {
		s.framesReceived++
		header := make([]byte, 3)
		if _, err := io.ReadFull(s.reader, header); err != nil {
			return nil, err
		}
		size := int(header[0])<<8 | int(header[1])
		pad := int(header[2])
		body := make([]byte, size)
		if _, err := io.ReadFull(s.reader, body); err != nil {
			return nil, err
		}
		if pad > 0 {
			if _, err := io.ReadFull(s.reader, make([]byte, pad)); err != nil {
				return nil, err
			}
		}
		if len(body) < 2 {
			return nil, io.ErrUnexpectedEOF
		}
		size = int(binary.BigEndian.Uint16(body[:2]))
		if size != len(body)-2 {
			return nil, io.ErrUnexpectedEOF
		}
		return body[2:], nil
	}
	// Past the window the reply is a raw UoT datagram.
	length := make([]byte, 2)
	if _, err := io.ReadFull(s.reader, length); err != nil {
		return nil, err
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(length)))
	if _, err := io.ReadFull(s.reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// FaultInjectingEcho is an echo server that deliberately withholds the reply for
// chosen Packet IDs, so a lost reply can be produced ON DEMAND instead of being
// waited for.
//
// Why this exists: the same-session resend behaviour used to be tested by
// churning thousands of sessions until one happened to fail, which SKIPPED on
// any machine where the loss did not reproduce - so the behaviour was usually
// unverified. Injecting the loss makes the scenario deterministic and keeps the
// session open by construction, which is exactly the state the test needs.
//
// It is an ORIGIN-SIDE fault, not a client-side shortcut: the request still
// travels the real Naive UoT path and the echo still records that it received
// it. Only the reply is withheld.
type FaultInjectingEcho struct {
	conn    *net.UDPConn
	address string
	trace   *Trace

	mu       sync.Mutex
	suppress map[uint32]int // packet ID -> number of replies still to withhold
	observed map[uint32]int // packet ID -> times the echo received it
}

func startFaultInjectingEcho(t *testing.T, trace *Trace) *FaultInjectingEcho {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	echo := &FaultInjectingEcho{
		conn:     conn,
		address:  conn.LocalAddr().String(),
		trace:    trace,
		suppress: make(map[uint32]int),
		observed: make(map[uint32]int),
	}
	go func() {
		buffer := make([]byte, 64*1024)
		for {
			n, from, readErr := conn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			packetID := payloadPacketID(buffer[:n])

			echo.mu.Lock()
			echo.observed[packetID]++
			remaining := echo.suppress[packetID]
			if remaining > 0 {
				echo.suppress[packetID] = remaining - 1
			}
			echo.mu.Unlock()

			echo.trace.record(0, packetID, StageEchoReadFromUDP,
				fmt.Sprintf("n=%d from=%s", n, from), nil)

			if remaining > 0 {
				// The reply is withheld on purpose. The request DID arrive, so
				// this is a lost REPLY, not a lost datagram.
				echo.trace.record(0, packetID, StageEchoWriteToUDP,
					fmt.Sprintf("WITHHELD on purpose (%d more)", remaining-1),
					errors.New("reply withheld by fault injection"))
				continue
			}

			written, writeErr := conn.WriteToUDP(buffer[:n], from)
			echo.trace.record(0, packetID, StageEchoWriteToUDP,
				fmt.Sprintf("n=%d to=%s", written, from), writeErr)
		}
	}()
	return echo
}

// withholdReplies makes the echo drop the next `count` replies for packetID.
func (e *FaultInjectingEcho) withholdReplies(packetID uint32, count int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.suppress[packetID] = count
}

// receivedCount reports how many times the echo actually received packetID.
func (e *FaultInjectingEcho) receivedCount(packetID uint32) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.observed[packetID]
}
