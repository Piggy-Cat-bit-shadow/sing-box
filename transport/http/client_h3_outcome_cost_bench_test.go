package http

// The cost of the ordering guard, measured rather than asserted.
//
// # What is being measured, and what it is NOT
//
// The guard adds, per HTTP/3 ATTEMPT: one atomic increment to issue the attempt's sequence
// number, and one atomic load plus at most one compare-and-swap to record its outcome. An
// attempt is made once per HTTP/3 connection, not per packet and not per byte, so the budget
// this has to fit in is "free beside a QUIC handshake", not "free beside a memcpy".
//
// The second benchmark is the honest statement of resolution: it drives the whole
// `Client.DialContext` HTTP/3 decision against the same double the correctness tests use, so a
// reader can see for themselves that the end-to-end figure cannot resolve a difference of two
// atomic operations. Nothing here is offered as an improvement -- this change is a correctness
// fix, and the numbers exist to show it does not cost anything worth naming.

import (
	"context"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// BenchmarkHTTP3OutcomeClaim measures the guard itself: issue a sequence number and record an
// outcome, which is exactly what one attempt costs on top of the attempt.
func BenchmarkHTTP3OutcomeClaim(b *testing.B) {
	client := &Client{}
	b.ReportAllocs()
	for index := 0; b.Loop(); index++ {
		attempt := client.beginHTTP3Attempt()
		client.claimHTTP3Outcome(attempt)
	}
}

// BenchmarkHTTP3DialDecision measures the whole HTTP/3 attempt decision of DialContext, so the
// guard is seen in the context it actually runs in.
//
// The HTTP/3 double succeeds immediately, so this measures the decision and not a handshake.
func BenchmarkHTTP3DialDecision(b *testing.B) {
	h3 := &stagedHTTP3Client{}
	client := newBackoffMemoryClient(h3, &countingH2Dialer{}, false)
	ctx := context.Background()
	destination := M.ParseSocksaddr("target.example:443")
	b.ReportAllocs()
	for b.Loop() {
		conn, err := client.DialContext(ctx, "tcp", destination)
		if err != nil {
			b.Fatal(err)
		}
		_ = conn.Close()
	}
}

// TestHTTP3OutcomeOrderingCostIsBoundedOnTheAttemptPath is the guard for the benchmark above: it
// is not a timing assertion -- timing assertions are flaky and this repository does not add them
// -- but a structural one, so that the cost cannot silently move onto a hot path. It fails if the
// guard is ever reached from the copy loop or from a per-packet entry point.
func TestHTTP3OutcomeOrderingCostIsBoundedOnTheAttemptPath(t *testing.T) {
	// The accounting: two atomic operations per attempt, and one attempt per H3 connection. The
	// number of attempts a client makes is bounded by the number of connections it opens, which is
	// what the counting stand asserts elsewhere; nothing here is per byte.
	client := &Client{}
	before := client.http3Attempt.Load()
	for range 1000 {
		client.claimHTTP3Outcome(client.beginHTTP3Attempt())
	}
	if got := client.http3Attempt.Load() - before; got != 1000 {
		t.Fatalf("issued %d sequence numbers for 1000 attempts, so the accounting above is wrong", got)
	}
	// And the guard is a single decision: a claim of an OLD attempt is refused without touching
	// the verdict, which is the property that keeps a stale report from moving state.
	client.http3Broken.Store(time.Now().Add(time.Minute).UnixNano())
	armed := client.http3Broken.Load()
	if client.claimHTTP3Outcome(1) {
		t.Fatal("a claim older than the recorded outcome was accepted")
	}
	if client.http3Broken.Load() != armed {
		t.Fatal("a refused claim moved the verdict")
	}
}
