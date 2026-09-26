package reference_test

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// Zero-length UDP datagrams, and the CONNECT-IP mirror case.
//
// A zero-length UDP datagram is LEGAL (RFC 768 permits a datagram with a zero-length
// data field), so a CONNECT-UDP proxy must carry one. The trap is that "I received no
// datagram" and "I received a datagram of length zero" are different outcomes that a
// careless test conflates - and a careless implementation conflates too, because a
// zero payload is exactly what an empty read looks like.
//
// So the fixture below COUNT the datagrams it receives and records their lengths, and
// the test asserts on that count rather than on the bytes that came back. A server
// that silently dropped the empty datagram leaves the count at zero, which is
// distinguishable from a server that delivered it.
//
// CONNECT-IP is the opposite case: after the context ID, an empty payload is not a
// valid IP packet, so it must be dropped without killing the tunnel.

// zeroLengthEchoOrigin is a UDP origin that echoes zero-length datagrams AND reports
// what it received.
//
// A plain echo server cannot prove this case: it would echo a zero-length datagram
// back, and the client would then have to distinguish "an empty reply" from "no
// reply" using a timeout, which is ambiguous under load. Recording the received
// lengths makes the assertion direct.
type zeroLengthEchoOrigin struct {
	address string
	access  sync.Mutex
	// receivedLen records the length of every datagram the origin was handed, in
	// order. A zero entry is a zero-length datagram.
	receivedLen []int
}

// startZeroLengthEchoOrigin starts the recording origin.
func startZeroLengthEchoOrigin(t *testing.T) *zeroLengthEchoOrigin {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	origin := &zeroLengthEchoOrigin{address: conn.LocalAddr().String()}
	go func() {
		// A one-byte buffer is enough: this origin only needs to know HOW MANY bytes
		// arrived, and a read into a small buffer still reports the true datagram
		// length for a datagram that fits. Zero-length datagrams are the case under
		// test and they need no buffer at all.
		buffer := make([]byte, 1500)
		for {
			n, address, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			origin.access.Lock()
			origin.receivedLen = append(origin.receivedLen, n)
			origin.access.Unlock()
			// Echo the datagram EXACTLY, including its length. A zero-length reply is
			// what the client must be able to observe.
			_, _ = conn.WriteTo(buffer[:n], address)
		}
	}()
	return origin
}

// lengths returns a copy of the recorded lengths.
func (o *zeroLengthEchoOrigin) lengths() []int {
	o.access.Lock()
	defer o.access.Unlock()
	return append([]int(nil), o.receivedLen...)
}

// awaitLengthCount waits until the origin has recorded at least count datagrams.
func (o *zeroLengthEchoOrigin) awaitLengthCount(t *testing.T, count int, timeout time.Duration) []int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		lengths := o.lengths()
		if len(lengths) >= count || time.Now().After(deadline) {
			return lengths
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestReferenceConnectUDPZeroLengthDatagramOverQUICDatagrams carries a zero-length
// UDP datagram over the DATAGRAM path.
//
// The two directions are asserted separately, because they are different claims:
//
//	origin received ONE datagram, of length 0   (the request was forwarded)
//	client received ONE datagram, of length 0   (the empty reply came back)
//
// A server that treated "payload length 0" as malformed leaves the origin count at
// zero. A server that forwarded it but dropped the empty REPLY leaves the client
// waiting. Both are real failure modes and the test names which one occurred.
func TestReferenceConnectUDPZeroLengthDatagramOverQUICDatagrams(t *testing.T) {
	origin := startZeroLengthEchoOrigin(t)
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	client := startConnectUDPControlPeer(t, server, true)
	stream, _ := client.openTunnel(t, origin.address)

	// A NON-empty datagram first, so the fixture is proven to work before the empty
	// case is measured. Without this, an empty origin length list would be ambiguous
	// between "the empty datagram was dropped" and "nothing works at all".
	require.NoError(t, stream.SendDatagram(append([]byte{0}, []byte("warmup")...)))
	warmupReply, ok := readContextZeroDatagram(t, stream, 10*time.Second)
	require.True(t, ok, "a non-empty datagram must round trip before the empty case")
	require.Equal(t, "warmup", string(warmupReply))

	lengths := origin.awaitLengthCount(t, 1, 10*time.Second)
	require.Equal(t, []int{6}, lengths,
		"the origin must have received exactly the six-byte warmup datagram")

	// Now the case under test: a context-0 datagram with a ZERO-length UDP payload.
	require.NoError(t, stream.SendDatagram([]byte{0}),
		"a zero-length UDP payload must be SENDABLE under context 0")

	// The origin must receive a datagram of length 0. This is the assertion that
	// distinguishes "dropped" from "delivered empty".
	lengths = origin.awaitLengthCount(t, 2, 10*time.Second)
	require.Equal(t, []int{6, 0}, lengths,
		"the origin must have received the zero-length datagram as a datagram of length "+
			"0. Got %v: a second entry of a different length means the framing was "+
			"misread, and no second entry at all means the server treated a legal "+
			"zero-length UDP payload as malformed", lengths)

	// And the empty REPLY must come back. This is the direction an implementation is
	// most likely to get wrong, because an empty datagram and no datagram look alike
	// to a reader that does not check its result.
	reply, ok := readContextZeroDatagram(t, stream, 10*time.Second)
	require.True(t, ok,
		"the origin's zero-length reply must reach the client. No datagram here means "+
			"the server dropped the empty reply - a zero-length UDP datagram is a "+
			"delivered packet, not an absent one")
	require.Empty(t, reply,
		"the client must receive a context-0 datagram whose UDP payload is EXACTLY zero "+
			"bytes")

	// The tunnel must still work afterwards, so the empty exchange was not terminal.
	require.NoError(t, stream.SendDatagram(append([]byte{0}, []byte("after-empty")...)))
	afterReply, ok := readContextZeroDatagram(t, stream, 10*time.Second)
	require.True(t, ok, "the tunnel must still carry traffic after a zero-length exchange")
	require.Equal(t, "after-empty", string(afterReply))
}

// TestReferenceConnectUDPZeroLengthDatagramOverCapsules is the same case on the
// CAPSULE fallback.
//
// The capsule path frames the payload with an explicit length, so it is a genuinely
// different code path: the empty payload becomes a capsule of length 1 (the context
// ID alone). transport/http/capsule.go readDatagramCapsule discards a capsule whose
// payload is empty AFTER the context ID, which is correct - but nothing had driven a
// zero-length UDP payload through it.
func TestReferenceConnectUDPZeroLengthDatagramOverCapsules(t *testing.T) {
	origin := startZeroLengthEchoOrigin(t)
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	client := startConnectUDPControlPeer(t, server, false) // datagrams OFF: capsule path
	stream, _ := client.openTunnel(t, origin.address)

	require.NoError(t, writeDatagramCapsuleToStream(stream, []byte("warmup")))
	lengths := origin.awaitLengthCount(t, 1, 10*time.Second)
	require.Equal(t, []int{6}, lengths,
		"the warmup capsule must have been forwarded, so the fixture is proven before "+
			"the empty case is measured")

	// The warmup's reply must be CONSUMED before the empty case is measured.
	//
	// Capsules arrive on the ordered request stream, so skipping this read does not
	// lose the reply - it becomes the answer to the NEXT read. The first version of
	// this test omitted it and then asserted that the empty reply was empty, which
	// failed on the warmup's six bytes and looked like a framing defect.
	require.Equal(t, "warmup", string(readDatagramCapsuleWithTimeout(t, stream, 10*time.Second)),
		"the warmup reply must be read before the empty case, so the capsule reads stay "+
			"in step with the exchanges")

	// The case under test: a DATAGRAM capsule whose UDP payload is zero bytes. The
	// capsule still has a payload (the context ID), so it is a length-1 capsule, not a
	// zero-length capsule.
	require.NoError(t, writeDatagramCapsuleToStream(stream, nil))

	lengths = origin.awaitLengthCount(t, 2, 10*time.Second)
	require.Equal(t, []int{6, 0}, lengths,
		"the origin must have received the zero-length UDP datagram over the CAPSULE "+
			"path too. A zero-length UDP payload is legal, and a DATAGRAM capsule "+
			"carrying only a context ID is well-formed - it is not the same as a "+
			"zero-length capsule, which carries no context ID at all. Got %v", lengths)

	// The empty reply must come back as a capsule carrying a context ID and NOTHING
	// else.
	//
	// A dedicated reader is used rather than readDatagramCapsuleWithTimeout, and the
	// reason is a limitation of the shared helper that this case exposes: that helper
	// SKIPS any capsule whose payload is exactly the context ID (`len(payload) ==
	// contextLength`), because for a general-purpose reader an empty datagram is
	// indistinguishable from one it should ignore. That is the right default, but it is
	// exactly wrong here - this test exists to prove that an empty payload ARRIVED.
	//
	// So the framing is read here at the level of the capsule itself, where the length
	// is unambiguous: a capsule of length 1 whose payload is a single zero context ID.
	reply := readDatagramCapsuleIncludingEmpty(t, stream, 10*time.Second)
	require.True(t, reply.arrived,
		"the origin's zero-length reply must arrive as a capsule. Nothing arriving means "+
			"the server dropped the empty reply - a zero-length UDP datagram is a "+
			"delivered packet, not an absent one")
	require.Empty(t, reply.payload,
		"the capsule must carry an empty UDP payload, so the client sees a delivered "+
			"datagram of length 0 rather than no datagram at all")

	// The tunnel must still work.
	require.NoError(t, writeDatagramCapsuleToStream(stream, []byte("after-empty")))
	require.Equal(t, "after-empty", string(readDatagramCapsuleWithTimeout(t, stream, 10*time.Second)),
		"the tunnel must still carry traffic after a zero-length exchange")
}

// TestReferenceConnectIPEmptyPayloadIsDroppedAndTheTunnelSurvives is the CONNECT-IP
// mirror case, and it is the OPPOSITE requirement.
//
// After the context ID, an empty payload is not a valid IP packet: there is no
// version nibble, no header and no addresses. It must be DROPPED, and the tunnel must
// survive so a following valid packet still works. Delivering it would push a
// zero-length packet into the IP stack.
func TestReferenceConnectIPEmptyPayloadIsDroppedAndTheTunnelSurvives(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	client := startDatagramCapableConnectIPClient(t, server)
	stream, response := client.openTunnel(t, server)
	defer response.Body.Close()

	assigned, routes := readAddressAssignmentAndRoutes(t, stream)
	require.True(t, assigned.IsValid())
	require.NotEmpty(t, routes)
	gateway := serverGatewayAddress(t)

	// Baseline: a real packet round trips.
	baseline := connectIPDatagramRoundTrip(t, stream, assigned, gateway, 0x6100, 1,
		[]byte{0x00}, "baseline")
	require.Equal(t, uint8(0), baseline[20])

	// Now the case under test: a context-0 datagram with NO payload after the context
	// ID. This is a well-formed HTTP Datagram carrying an empty application payload.
	require.NoError(t, stream.SendDatagram([]byte{0x00}))

	_, answered := readConnectIPDatagramWithTimeout(t, stream, 1200*time.Millisecond)
	require.False(t, answered,
		"an empty CONNECT-IP payload is not a valid IP packet and must be dropped, not "+
			"answered")

	// The tunnel must survive it.
	after := connectIPDatagramRoundTrip(t, stream, assigned, gateway, 0x6200, 2,
		[]byte{0x00}, "after-empty")
	require.Equal(t, uint8(0), after[20],
		"the CONNECT-IP session must survive an empty payload; dropping it is a "+
			"per-datagram decision, not a session failure")
}

// TestReferenceConnectIPEmptyPayloadOverCapsules is the capsule-fallback form of the
// case above.
func TestReferenceConnectIPEmptyPayloadOverCapsules(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	client := startDatagramDisabledConnectIPPeer(t, server)
	stream, response := client.openTunnel(t, server)
	defer response.Body.Close()

	assigned, routes := readAddressAssignmentAndRoutes(t, stream)
	require.True(t, assigned.IsValid())
	require.NotEmpty(t, routes)

	gateway := serverGatewayAddress(t)
	const identifier = 0x6300
	packet := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, identifier, 1,
		[]byte("baseline"))
	require.NoError(t, writeDatagramCapsuleToStream(stream, packet))
	baseline := readDatagramCapsuleWithTimeout(t, stream, 10*time.Second)
	require.Equal(t, uint8(0), baseline[20], "the baseline must be answered")

	// A DATAGRAM capsule whose payload is the context ID alone: an empty IP payload.
	require.NoError(t, writeDatagramCapsuleToStream(stream, nil))

	// And the tunnel survives.
	//
	// # Why there is no speculative "nothing arrived" read here
	//
	// The obvious shape is to read with a short timeout and assert that nothing came
	// back. That shape is WRONG on this stream, and it was measured rather than
	// reasoned about: a read has to be issued from a goroutine (a stream read has no
	// deadline), and a goroutine whose read is still parked when the timeout fires goes
	// on to consume the NEXT capsule. The empty case produces no reply, so the parked
	// reader silently swallowed the reply to the request below and the test failed with
	// "no DATAGRAM capsule arrived" - which reads like a server defect and is a test
	// artefact.
	//
	// So the property is asserted WITHOUT an ambiguous read. What proves the empty
	// payload was not delivered is the next clause: the following request is answered
	// with sequence number 2, and the server numbers replies by request. Had the empty
	// capsule been delivered to the IP stack as a packet, the stack would have had a
	// zero-length packet to answer or reject, and the exchange below would not come back
	// cleanly with the tag this test set.
	after := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, identifier, 2,
		[]byte("after-empty"))
	require.NoError(t, writeDatagramCapsuleToStream(stream, after))
	reply := readDatagramCapsuleWithTimeout(t, stream, 10*time.Second)
	require.Equal(t, uint8(0), reply[20],
		"the CONNECT-IP capsule session must survive an empty payload; a stream that "+
			"stalled here would mean the empty capsule desynchronised the framing")
	require.Equal(t, uint16(2), uint16(reply[26])<<8|uint16(reply[27]),
		"the reply must answer the SECOND request. This is also what proves the empty "+
			"payload produced NO reply of its own: replies arrive in order on this "+
			"stream, so a reply to the empty capsule would have been read here instead")
	require.Equal(t, []byte("after-empty"), reply[28:],
		"the reply must carry this request's payload, so it cannot be a stale answer to "+
			"the baseline")
}

// contextZeroDatagramResult is one datagram read with an explicit "did one arrive"
// flag, so a zero-length payload is not confused with an absent datagram.
type contextZeroDatagramResult struct {
	payload []byte
	arrived bool
	err     error
}

// readContextZeroDatagram reads one context-0 HTTP Datagram.
//
// The arrived flag is the whole point: a successful read that returned zero bytes is
// reported as arrived=true with an empty payload, while a timeout is arrived=false.
// Collapsing those two is the mistake this file exists to prevent.
func readContextZeroDatagram(t *testing.T, stream *http3.RequestStream, timeout time.Duration) ([]byte, bool) {
	t.Helper()
	result := readContextZeroDatagramResult(t, stream, timeout)
	return result.payload, result.arrived
}

func readContextZeroDatagramResult(t *testing.T, stream *http3.RequestStream, timeout time.Duration) contextZeroDatagramResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type raw struct {
		data []byte
		err  error
	}
	done := make(chan raw, 1)
	go func() {
		data, err := stream.ReceiveDatagram(ctx)
		done <- raw{data, err}
	}()

	select {
	case received := <-done:
		if received.err != nil {
			return contextZeroDatagramResult{err: received.err}
		}
		contextID, contextLength, valid := decodeVarint(received.data)
		if !valid || contextID != 0 {
			return contextZeroDatagramResult{err: errContextMismatch}
		}
		// arrived=true even when the payload is empty. This is the distinction the
		// whole file turns on.
		return contextZeroDatagramResult{
			payload: received.data[contextLength:],
			arrived: true,
		}
	case <-time.After(timeout):
		return contextZeroDatagramResult{}
	}
}

// errContextMismatch reports a datagram that was not context 0.
var errContextMismatch = errors.New("the datagram did not carry context 0")

// datagramCapsuleReply is one DATAGRAM capsule read at the framing level.
type datagramCapsuleReply struct {
	payload []byte
	arrived bool
	err     error
}

// readDatagramCapsuleIncludingEmpty reads one DATAGRAM capsule WITHOUT applying the
// "drop an empty datagram" rule, so a context-0 capsule with a zero-length payload is
// reported as arrived.
//
// This is the reader the zero-length case needs, and the distinction is the point of
// the whole file: readDatagramCapsule (the shared helper) deliberately skips empty
// datagrams, which makes it unable to observe the very outcome under test. Reading at
// the framing level removes the ambiguity, because the capsule LENGTH states whether a
// capsule arrived independently of what it carried.
func readDatagramCapsuleIncludingEmpty(t *testing.T, reader interface{ Read([]byte) (int, error) }, timeout time.Duration) datagramCapsuleReply {
	t.Helper()

	type result struct {
		payload []byte
		err     error
	}
	done := make(chan result, 1)
	go func() {
		for {
			capsuleType, _, err := readVarint(reader)
			if err != nil {
				done <- result{nil, err}
				return
			}
			length, _, err := readVarint(reader)
			if err != nil {
				done <- result{nil, err}
				return
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(reader, payload); err != nil {
				done <- result{nil, err}
				return
			}
			if capsuleType != capsuleTypeDatagram {
				// A control capsule: consumed, not data.
				continue
			}
			contextID, contextLength, ok := decodeVarint(payload)
			if !ok || contextID != 0 {
				continue
			}
			// arrived=true even for an empty payload. No other reader in this suite
			// does that, on purpose.
			done <- result{payload[contextLength:], nil}
			return
		}
	}()

	select {
	case received := <-done:
		if received.err != nil {
			return datagramCapsuleReply{err: received.err}
		}
		return datagramCapsuleReply{payload: received.payload, arrived: true}
	case <-time.After(timeout):
		return datagramCapsuleReply{}
	}
}
