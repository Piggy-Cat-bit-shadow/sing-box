//go:build with_quic

package httpclient

import (
	"io"
	"net/http"
	"testing"
)

// benchPoolTarget is the loopback HTTP/3 server shared by the pool benchmarks.
type benchPoolTarget struct {
	address string
	server  interface{ Close() error }
}

// newBenchPoolTarget starts one loopback HTTP/3 server for a benchmark.
func newBenchPoolTarget(tb testing.TB) *benchPoolTarget {
	tb.Helper()
	server, address, _ := startH3ServerWithHandler(tb, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	}))
	return &benchPoolTarget{address: address, server: server}
}

func benchmarkPoolRoundTrip(b *testing.B, size int) {
	target := newBenchPoolTarget(b)
	b.Cleanup(func() { target.server.Close() })

	pool := newTestPoolB(b, size)
	b.Cleanup(func() { pool.Close() })

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(parallel *testing.PB) {
		for parallel.Next() {
			request, err := http.NewRequest(http.MethodGet, "https://"+target.address+"/", nil)
			if err != nil {
				b.Errorf("new request: %v", err)
				return
			}
			response, err := pool.RoundTrip(request)
			if err != nil {
				b.Errorf("round trip: %v", err)
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
	})
}

// BenchmarkHTTP3Pool1 is the regression reference for the upstream
// single-transport behaviour (pool size 1).
func BenchmarkHTTP3Pool1(b *testing.B) {
	benchmarkPoolRoundTrip(b, 1)
}

// BenchmarkHTTP3Pool2 is the regression reference for the recommended
// two-connection pool. It is a reference only: results on a CI runner do not
// predict throughput on a real VPS.
func BenchmarkHTTP3Pool2(b *testing.B) {
	benchmarkPoolRoundTrip(b, 2)
}

// BenchmarkHTTP3PoolPick measures the selection overhead itself, with no I/O.
func BenchmarkHTTP3PoolPick(b *testing.B) {
	for _, size := range []int{1, 2, 4} {
		pool := newTestPoolB(b, size)
		request, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		if err != nil {
			b.Fatalf("new request: %v", err)
		}
		b.Run(benchSizeName(size), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				pool.pick(request)
			}
		})
	}
}

func benchSizeName(size int) string {
	switch size {
	case 1:
		return "size=1"
	case 2:
		return "size=2"
	default:
		return "size=4"
	}
}
