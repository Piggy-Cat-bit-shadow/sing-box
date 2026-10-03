package transport

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
)

// Tests for serial (non-pipelining) TCP DNS connection reuse.
//
// # The behaviour under test
//
// A resolver that refuses concurrent outstanding queries is not a resolver that cannot
// be reused: the transport keeps one connection for sequential queries, so a lookup does
// not pay a TCP handshake each time. (This used to be reached by demoting after a failed
// pipelining probe; the probe is gone, and this is now simply how the transport works.)
//
// The distinction matters most on a phone: a TCP handshake per DNS lookup is radio work
// and latency, and it happens on the connection-setup path of every new flow.

// newSequentialDNSServer accepts connections and answers queries in order on each one,
// WITHOUT pipelining: while a query is outstanding the next is not read, so a probe that
// writes two queries at once sees only one reply.
//
// This is the shape that used to force a dial per query. It differs from the multiplexed
// test server only in that it does not answer concurrent queries, which is what makes the
// transport demote to the serial path.
func newSequentialDNSServer(t *testing.T) (net.Listener, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				for {
					request, readErr := ReadMessage(conn)
					if readErr != nil {
						return
					}
					response := new(mDNS.Msg)
					response.SetReply(request)
					if writeErr := WriteMessage(conn, request.Id, response); writeErr != nil {
						return
					}
					// Refuse to read another query until this one has been answered AND a
					// short pause has passed. Without the pause the server answers the
					// probe's two queries back to back and looks pipelining-capable, so
					// the transport keeps the multiplexed path and this test would be
					// measuring the wrong thing entirely.
					time.Sleep(noPipelineDelay)
				}
			}()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return listener, &accepted
}

// noPipelineDelay spaces out the server's replies so a caller cannot observe two answers
// back to back. It makes the server's one-at-a-time behaviour explicit rather than
// relying on scheduling, which keeps the fixture honest about what it models.
//
// It deliberately does NOT try to defeat the pipelining probe: that probe allows five
// seconds, and a delay long enough to beat it would make these tests slower than the
// thing they measure. The serial tests force the state instead.
const noPipelineDelay = 150 * time.Millisecond

// settle waits for the connection count to stop rising, so the assertion measures the
// steady state rather than racing the accept loop.
func settle(accepted *atomic.Int32) int32 {
	last := accepted.Load()
	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		current := accepted.Load()
		if current == last {
			return current
		}
		last = current
	}
	return last
}

// TestTCPTransportReusesSequentially is the core regression.
//
// Sequential queries against a non-pipelining server must NOT cost a connection each.
func TestTCPTransportReusesSequentially(t *testing.T) {
	t.Parallel()
	listener, accepted := newSequentialDNSServer(t)
	transport := newTestTCPTransport(t, listener)

	// The serial path is the only path: the pipelining capability probe was removed because it
	// generated DNS queries the caller never authorised. Nothing needs to be forced here.

	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("first query: ", err)
	}
	afterFirst := int32(settle(accepted))

	const subsequent = 12
	for range subsequent {
		if err := testExchange(transport, "example.com."); err != nil {
			t.Fatal("query: ", err)
		}
	}
	afterAll := int32(settle(accepted))

	if added := afterAll - afterFirst; added >= subsequent {
		t.Fatalf("expected serial reuse to avoid a connection per query: %d queries added %d connections",
			subsequent, added)
	}
	t.Logf("%d sequential queries added %d connection(s) after the first", subsequent, afterAll-afterFirst)
}

// TestTCPTransportSerialReuseSurvivesRepeatedQueries checks that the pooled connection is
// genuinely reused across many queries rather than being re-dialed periodically.
func TestTCPTransportSerialReuseSurvivesRepeatedQueries(t *testing.T) {
	t.Parallel()
	listener, accepted := newSequentialDNSServer(t)
	transport := newTestTCPTransport(t, listener)
	// Serial path under test; see TestTCPTransportReusesSequentially.

	const total = 30
	for i := range total {
		if err := testExchange(transport, "example.com."); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	count := settle(accepted)

	// Every query over the same pooled connection should need at most a handful of
	// connections in total (dial + probe + any keep-alive close the server causes).
	// One-per-query would be 30+.
	if count >= total {
		t.Fatalf("expected reuse, but %d queries opened %d connections", total, count)
	}
	t.Logf("%d queries used %d connection(s)", total, count)
}

// TestTCPTransportSerialReuseConcurrentQueriesStayCorrect is the invariant that makes
// serial reuse safe: several callers in flight at once must all get their own answer,
// because the pool hands out one connection at a time.
func TestTCPTransportSerialReuseConcurrentQueriesStayCorrect(t *testing.T) {
	t.Parallel()
	listener, _ := newSequentialDNSServer(t)
	transport := newTestTCPTransport(t, listener)
	// Serial path under test; see TestTCPTransportReusesSequentially.

	const concurrency = 8
	results := make(chan error, concurrency)
	for i := range concurrency {
		go func(index int) {
			results <- testExchange(transport, "example.com.")
		}(i)
	}
	for range concurrency {
		if err := <-results; err != nil {
			t.Fatal("concurrent query failed: ", err)
		}
	}
}

// TestTCPTransportSerialReuseCancellationDoesNotCorruptThePool checks that cancelling a
// query in flight does not leave a poisoned connection behind for the next caller.
//
// The connection is closed underneath the caller on cancellation, so it must NOT return
// to the idle pool. Reusing it would deliver a stale or absent response to whatever query
// picked it up next, which is a correctness bug rather than a performance one.
func TestTCPTransportSerialReuseCancellationDoesNotCorruptThePool(t *testing.T) {
	t.Parallel()
	listener, _ := newSequentialDNSServer(t)
	transport := newTestTCPTransport(t, listener)

	// A query with an already-expired context must fail, not hang.
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	if _, err := transport.Exchange(expired, message); err == nil {
		t.Fatal("a cancelled query must not report success")
	}

	// And the pool must still serve a healthy query afterwards.
	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("the pool did not recover after cancellation: ", err)
	}
}

// TestTCPTransportSerialReuseCloseAndReset checks the lifecycle entry points do not hang
// or panic with a connection outstanding.
func TestTCPTransportSerialReuseCloseAndReset(t *testing.T) {
	t.Parallel()
	listener, _ := newSequentialDNSServer(t)
	transport := newTestTCPTransport(t, listener)

	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("query: ", err)
	}
	// Reset drops pooled connections; a following query must re-dial and succeed.
	transport.Reset()
	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("query after Reset: ", err)
	}
	// Teardown is scope-owned; closing the scope is what releases the pooled connections.
	if err := testScopeOf(t, transport).Close(); err != nil {
		t.Fatal("Close: ", err)
	}
	// A query after Close must fail rather than block.
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := transport.Exchange(ctx, message); err == nil {
		t.Fatal("a query after Close must not succeed")
	}
}

// BenchmarkTCPDNSSerialReuse measures the per-query cost with and without serial reuse.
//
// The number that matters is not ns/op - a loopback dial is cheap on a developer machine
// and wildly expensive on a phone's radio. It is the connection count, which is the
// syscall and handshake work being removed:
//
//	before   one TCP dial, write, read and close per query
//	after    one dial, then one write+read per query on the kept connection
func BenchmarkTCPDNSSerialReuse(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				for {
					request, readErr := ReadMessage(conn)
					if readErr != nil {
						return
					}
					response := new(mDNS.Msg)
					response.SetReply(request)
					if WriteMessage(conn, request.Id, response) != nil {
						return
					}
				}
			}()
		}
	}()

	for _, variant := range []struct {
		name string
	}{
		{"serial-reuse"},
	} {
		b.Run(variant.name, func(b *testing.B) {
			transportDialer, dialErr := dialer.NewDefault(context.Background(), option.DialerOptions{})
			if dialErr != nil {
				b.Fatal(dialErr)
			}
			transport := NewTCPRaw(
				boxDNS.NewTransportAdapter(C.DNSTypeTCP, "bench", nil),
				transportDialer,
				M.SocksaddrFromNet(listener.Addr()),
			)

			message := new(mDNS.Msg)
			message.SetQuestion("example.com.", mDNS.TypeA)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if _, err := transport.Exchange(ctx, message); err != nil {
					cancel()
					b.Fatal(err)
				}
				cancel()
			}
			b.StopTimer()
			b.ReportMetric(float64(accepted.Load()), "conns")
		})
	}
}
