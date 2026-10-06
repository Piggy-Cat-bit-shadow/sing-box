package mixed

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
)

// ---------------------------------------------------------------------------
// Benchmarks for the cooperative fast path.
//
// Everything measured here is the FRONT HALF: the listener-equivalent hand-off
// into mixed.NewConnection, protocol discrimination, the handshake, metadata
// construction and the hand-off to RouteConnectionEx. The routed connection is
// captured by a sink router, so no time is spent in the shared core -- which is
// the point, because the shared core is not what this work changes.
//
// The connection double serves the whole client stream in one Read, which is
// what a real socket does when the client writes handshake + payload in one
// segment. That is deliberately the case that exercises the early-data path.
// ---------------------------------------------------------------------------

// benchHarness builds an inbound that routes into a buffered sink channel. The
// channel is drained non-blockingly in the loop, so no routing is lost and no
// per-connection allocation is added by the harness itself.
func benchHarness(tb testing.TB, users []auth.User) *inboundHarness {
	tb.Helper()
	router := newCaptureRouter()
	created, err := NewInbound(context.Background(), router, testNOPLogger(), "mixed-in", httpMixedOptions(users))
	if err != nil {
		tb.Fatalf("NewInbound: %v", err)
	}
	inbound := created.(*Inbound)
	tb.Cleanup(func() {
		_ = inbound.listener.Close()
	})
	return &inboundHarness{inbound: inbound, router: router}
}

func benchRun(b *testing.B, stream []byte, plan []int) {
	b.Helper()
	harness := benchHarness(b, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := newScriptedConn(stream, plan...)
		harness.newConnection(context.Background(), conn, testSource(), nil)
		select {
		case <-harness.router.connection:
		default:
		}
	}
}

func BenchmarkHTTPConnectNoAuth(b *testing.B) {
	benchRun(b, []byte(httpConnectNoAuth), nil)
}

func BenchmarkHTTPConnectAuth(b *testing.B) {
	harness := benchHarness(b, []auth.User{{Username: "user", Password: "pass"}})
	stream := []byte(httpConnectAuth)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := newScriptedConn(stream)
		harness.newConnection(context.Background(), conn, testSource(), nil)
		select {
		case <-harness.router.connection:
		default:
		}
	}
}

func BenchmarkSOCKS5ConnectNoAuth(b *testing.B) {
	benchRun(b, socks5NoAuth("example.com", 443, nil), nil)
}

func BenchmarkSOCKS5ConnectAuth(b *testing.B) {
	harness := benchHarness(b, []auth.User{{Username: "user", Password: "pass"}})
	stream := socks5Auth("user", "pass", "example.com", 443, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := newScriptedConn(stream)
		harness.newConnection(context.Background(), conn, testSource(), nil)
		select {
		case <-harness.router.connection:
		default:
		}
	}
}

func BenchmarkSOCKS4aConnectNoAuth(b *testing.B) {
	benchRun(b, socks4a("example.com", 443, "", nil), nil)
}

func BenchmarkEarlyDataHTTP32B(b *testing.B) {
	stream := append([]byte(httpConnectNoAuth), bytes.Repeat([]byte{0xA5}, 32)...)
	benchRun(b, stream, nil)
}

func BenchmarkEarlyDataSOCKS5_512B(b *testing.B) {
	stream := socks5NoAuth("example.com", 443, bytes.Repeat([]byte{0x5A}, 512))
	benchRun(b, stream, nil)
}

// BenchmarkHTTPConnectFragment1B measures the worst-case syscall pattern a slow
// client produces, where every byte is its own read.
func BenchmarkHTTPConnectFragment1B(b *testing.B) {
	stream := []byte(httpConnectNoAuth)
	benchRun(b, stream, chunkPlan(len(stream), 1))
}

// BenchmarkFastPathSetupLatency reports the wall-clock cost of one full
// hand-off, which is the front half's share of connection setup latency.
func BenchmarkFastPathSetupLatency(b *testing.B) {
	harness := benchHarness(b, nil)
	stream := []byte(httpConnectNoAuth)
	var total time.Duration
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := newScriptedConn(stream)
		start := time.Now()
		harness.newConnection(context.Background(), conn, testSource(), nil)
		select {
		case <-harness.router.connection:
		default:
		}
		total += time.Since(start)
	}
	b.StopTimer()
	b.ReportMetric(float64(total.Nanoseconds())/float64(b.N), "ns/setup")
}

var _ = option.HTTPMixedInboundOptions{}
