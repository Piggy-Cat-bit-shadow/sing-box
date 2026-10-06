package mixed

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/auth"
	N "github.com/sagernet/sing/common/network"
)

// ---------------------------------------------------------------------------
// Focused fuzzing of the cooperative fast path's parsers.
//
// The target is not "fuzz all of sing-box". It is the boundary this work
// touches: protocol discrimination, the handshake, and the hand-off of
// already-buffered payload.
//
// Two properties are checked for every input:
//
//	no panic / no hang -- the byte stream is attacker-controlled, and the test
//	                      connection is finite, so a missing terminator must
//	                      surface as a clean failure rather than a wait.
//	fragment invariance -- splitting a stream into arbitrary chunks must produce
//	                      the same routing decision, the same metadata and the
//	                      same routed payload as delivering it whole.
//
// The second is the one an example test cannot cover: every off-by-one in a
// replay buffer shows up as a disagreement between two fragmentations of the
// same bytes.
// ---------------------------------------------------------------------------

// recordingRouter records the routing decision synchronously, so a fuzz
// iteration can assert on it without waiting on a channel.
type recordingRouter struct {
	adapter.Router
	mu     sync.Mutex
	routed []routedRecord
}

type routedRecord struct {
	metadata adapter.InboundContext
	conn     net.Conn
}

func (r *recordingRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.mu.Lock()
	r.routed = append(r.routed, routedRecord{metadata: metadata, conn: conn})
	r.mu.Unlock()
}

func (r *recordingRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.mu.Lock()
	r.routed = append(r.routed, routedRecord{metadata: metadata})
	r.mu.Unlock()
}

func (r *recordingRouter) first() (routedRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.routed) == 0 {
		return routedRecord{}, false
	}
	return r.routed[0], true
}

type fuzzResult struct {
	routed   bool
	metadata adapter.InboundContext
	payload  []byte
}

// fuzzParse delivers data to the fast path according to plan and reports what
// the parser did.
//
// It never blocks longer than the timeout, and the test connection is finite, so
// a parser that waits for more input fails its iteration rather than the run.
func fuzzParse(t *testing.T, data []byte, plan []int, users []auth.User, expectPayload int) fuzzResult {
	t.Helper()
	router := &recordingRouter{}
	created, err := NewInbound(context.Background(), router, testNOPLogger(), "mixed-in", httpMixedOptions(users))
	if err != nil {
		t.Fatalf("NewInbound: %v", err)
	}
	inbound := created.(*Inbound)
	defer inbound.listener.Close()

	conn := newScriptedConn(append([]byte{}, data...), plan...)
	done := make(chan struct{})
	go func() {
		defer close(done)
		harness := &inboundHarness{inbound: inbound}
		harness.newConnection(context.Background(), conn, testSource(), nil)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("parser did not return for %d bytes with plan %v", len(data), plan)
	}

	record, ok := router.first()
	if !ok {
		return fuzzResult{}
	}
	result := fuzzResult{routed: true, metadata: record.metadata}
	if record.conn == nil || expectPayload <= 0 {
		return result
	}
	// Read EXACTLY the expected payload length. Reading more would consume bytes
	// the client never sent, which is the failure mode under test; reading less
	// would make a correct implementation look wrong.
	payload, err := readExact(record.conn, expectPayload)
	if err != nil {
		// A short read is itself the finding: report the prefix that arrived so
		// the caller's comparison shows it.
		result.payload = payload
		return result
	}
	result.payload = payload
	return result
}

// FuzzMixedProtocolDetection requires that no fragmentation changes the routing
// decision or the metadata.
func FuzzMixedProtocolDetection(f *testing.F) {
	seeds := [][]byte{
		[]byte(httpConnectNoAuth),
		[]byte(httpConnectTo("[2001:db8::1]:8443")),
		socks5NoAuth("example.com", 443, nil),
		socks5NoAuthIPv4([4]byte{192, 0, 2, 1}, 80, nil),
		socks5NoAuthIPv6([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 443, nil),
		socks4a("example.com", 443, "", nil),
		[]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
		{0x05},
		{0x04},
		// The malformed shape rejected at the boundary: a complete SOCKS5
		// exchange whose ATYP=domain address has a zero-length host. It must be
		// rejected identically at every fragmentation.
		{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50, 0x30},
		{0x05, 0x02, 0x00, 0x02, 0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's',
			0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50, 0x30},
		{},
		[]byte("CONNECT"),
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
	}
	for _, seed := range seeds {
		for mode := uint8(0); mode < 4; mode++ {
			f.Add(seed, mode)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte, fragMode uint8) {
		if len(data) > 8192 {
			data = data[:8192]
		}
		var whole []int
		if len(data) > 0 {
			whole = []int{len(data)}
		}
		wholeResult := fuzzParse(t, data, whole, nil, 0)

		var plan []int
		switch fragMode % 4 {
		case 0:
			plan = whole
		case 1:
			plan = chunkPlan(len(data), 1)
		case 2:
			plan = chunkPlan(len(data), 2)
		default:
			plan = randomChunkPlan(len(data), uint32(len(data))*2654435761)
		}
		fragResult := fuzzParse(t, data, plan, nil, 0)

		if wholeResult.routed != fragResult.routed {
			t.Fatalf("routing decision depends on fragmentation: whole=%v fragmented=%v for %q",
				wholeResult.routed, fragResult.routed, data)
		}
		if !wholeResult.routed {
			return
		}
		if wholeResult.metadata.Destination != fragResult.metadata.Destination ||
			wholeResult.metadata.User != fragResult.metadata.User {
			t.Fatalf("metadata depends on fragmentation: whole=%v/%q fragmented=%v/%q for %q",
				wholeResult.metadata.Destination, wholeResult.metadata.User,
				fragResult.metadata.Destination, fragResult.metadata.User, data)
		}
	})
}

// FuzzHTTPConnectFragmentation fuzzes the HTTP CONNECT shape with a real
// handshake plus an arbitrary payload and requires exact payload delivery.
func FuzzHTTPConnectFragmentation(f *testing.F) {
	f.Add("example.com:443", []byte{0x16, 0x03, 0x01, 0x00, 0x05}, uint32(1))
	f.Add("[2001:db8::1]:8443", []byte("payload"), uint32(7))
	f.Add("192.0.2.1:80", []byte{}, uint32(3))

	f.Fuzz(func(t *testing.T, hostport string, payload []byte, seed uint32) {
		if len(hostport) > 256 || len(payload) > 4096 {
			return
		}
		if bytes.ContainsAny([]byte(hostport), "\r\n ") {
			return
		}
		stream := append([]byte(httpConnectTo(hostport)), payload...)
		plan := randomChunkPlan(len(stream), seed)
		result := fuzzParse(t, stream, plan, nil, len(payload))
		if !result.routed {
			// An unusable CONNECT target is a legitimate rejection.
			return
		}
		if !bytes.Equal(result.payload, payload) {
			t.Fatalf("payload mismatch for %q: got %x, want %x", hostport, result.payload, payload)
		}
	})
}

// FuzzSOCKSHandshakeFragmentation fuzzes the SOCKS4/4a/5 shapes the same way.
func FuzzSOCKSHandshakeFragmentation(f *testing.F) {
	f.Add("example.com", uint16(443), []byte{1, 2, 3}, uint8(1))
	f.Add("", uint16(80), []byte{}, uint8(3))
	f.Add("a.example", uint16(1), bytes.Repeat([]byte{9}, 64), uint8(6))
	// Empty-domain seeds for every SOCKS5 family the target builds, including
	// the authenticated one, because the sub-negotiation shifts the offset the
	// check has to reach.
	f.Add("", uint16(0), []byte("0"), uint8(0))
	f.Add("", uint16(80), []byte{}, uint8(0))
	f.Add("", uint16(65535), []byte{0xAA}, uint8(2))
	f.Add("", uint16(1), []byte{}, uint8(3))

	f.Fuzz(func(t *testing.T, domain string, port uint16, payload []byte, version uint8) {
		if len(domain) > 200 || len(payload) > 4096 {
			return
		}
		if bytes.ContainsAny([]byte(domain), "\x00") {
			return
		}
		// An EMPTY domain is deliberately included. It is the malformed shape
		// this work rejects at the boundary -- see ValidateSOCKS5Address -- and a
		// zero-length ATYP=domain address otherwise desynchronises the stream by
		// two bytes instead of failing cleanly. Keeping it in the corpus is what
		// makes the rejection a fuzzed property rather than a single example.
		//
		// The SOCKS4 family is excluded only because SOCKS4a has no length byte:
		// an empty host there is an unterminated string, a different defect with
		// its own coverage.
		// The inbound's authenticator must match the stream's shape: an
		// authenticated stream presented to a no-users inbound is not a valid
		// handshake, and asserting delivery on it would test nothing.
		var (
			stream []byte
			users  []auth.User
		)
		socks4Family := version%5 == 1 || version%5 == 4
		if domain == "" && socks4Family {
			// SOCKS4a carries the host as a NUL-terminated string, so an empty
			// host is an unterminated string rather than a zero-length address.
			// That is a different malformed shape with its own coverage.
			return
		}
		switch version % 5 {
		case 0:
			stream = socks5NoAuth(domain, port, payload)
		case 1:
			stream = socks4a(domain, port, "", payload)
		case 2:
			stream = socks5Auth("user", "pass", domain, port, payload)
			users = []auth.User{{Username: "user", Password: "pass"}}
		case 3:
			stream = socks5NoAuthIPv4([4]byte{1, 2, 3, 4}, port, payload)
		default:
			// A SOCKS4 user id is an IDENT claim, not a credential.
			stream = socks4a(domain, port, "ident", payload)
		}
		plan := randomChunkPlan(len(stream), uint32(len(stream))*31+7)
		result := fuzzParse(t, stream, plan, users, len(payload))
		if !result.routed {
			return
		}
		if !bytes.Equal(result.payload, payload) {
			t.Fatalf("payload mismatch for domain %q version %d: got %x, want %x",
				domain, version%5, result.payload, payload)
		}
	})
}
