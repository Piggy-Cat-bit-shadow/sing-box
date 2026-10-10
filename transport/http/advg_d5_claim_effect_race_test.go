package http

// Adversary G, D5: the attempt-sequence guard orders the CLAIMS, not the EFFECTS.
//
// # The attack
//
// `claimHTTP3Outcome` is the serialisation point the author's fix introduces: it makes the HIGHEST
// attempt number the one that is allowed to write, and refuses every older one. Its own tests force
// the report order and then assert on the memory, so they cover the case where the two outcomes
// report one after the other.
//
// What the guard does NOT do is make the claim and the state mutation it licenses one operation.
// Every caller is
//
//	if !c.claimHTTP3Outcome(attempt) { return }   // <- the ordering decision
//	... c.http3Broken.Load()/Store/CAS ...        // <- the effect, NOT ordered by anything
//
// so two attempts can BOTH pass the claim -- the older one first, the newer one second -- and then
// have their effects land in the opposite order. The claim decides who may write, not when.
//
// All three of the outcomes the fix's own file claims to prevent are therefore still reachable,
// each in a window of a few instructions:
//
//	1. an OLD failure arms the verdict after a NEWER success cleared it   (pinned to HTTP/2)
//	2. an OLD success clears a NEWER failure                              (the memory is dead code)
//	3. an attempt from the network just LEFT re-arms the verdict after ResetConnections cleared it
//
// # Why this test drives the two methods directly
//
// This is the production interleaving, not an approximation of it. Both methods are what
// `DialContext` and `openTunnel` call, on the goroutine that returned from the HTTP/3 attempt, and
// the attempt numbers are the ones `beginHTTP3Attempt` issued. Two dials in flight are two
// goroutines by the fix's own comment on claimHTTP3Outcome. Driving the methods from two goroutines
// released from one gate is the same concurrency with the H3 client factored out.
//
// # Calibration
//
// Every assertion below is on `http3Broken` -- the same field, and the same claim ("the newest
// attempt decides"), that `client_h3_outcome_order_test.go` asserts on. The pairs are symmetric, so
// a violation is pinned to the ordering and not to "failure always wins" or "success always wins":
// the same test counts both directions separately.

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// advgD5IdleHTTP3Client is the smallest http3Client that lets the real ResetConnections run: it
// performs no attempt of its own, so the only attempt in the test is the one the test issues.
type advgD5IdleHTTP3Client struct{}

func (c *advgD5IdleHTTP3Client) DialContext(context.Context, M.Socksaddr) (net.Conn, error) {
	return nil, ErrHTTP3Unavailable
}

func (c *advgD5IdleHTTP3Client) OpenTunnel(context.Context, tunnelRequest) (DatagramStream, error) {
	return nil, ErrHTTP3Unavailable
}

func (c *advgD5IdleHTTP3Client) ResetConnection() {}
func (c *advgD5IdleHTTP3Client) Close() error     { return nil }

// advgD5Iterations is large enough that the interleaving shows up in a normal run and small enough
// that the package's test budget is not spent here. It is overridable so a slow machine can lower
// it without editing the file.
func advgD5Iterations() int {
	if raw := os.Getenv("ADVG_D5_ITERATIONS"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			return parsed
		}
	}
	return 100000
}

// advgD5Pair runs two outcomes released from one gate and reports the verdict left behind.
func advgD5Pair(older func(*Client), newer func(*Client)) uint64 {
	client := &Client{}
	gate := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-gate
		older(client)
	}()
	go func() {
		defer wait.Done()
		<-gate
		newer(client)
	}()
	close(gate)
	wait.Wait()
	return uint64(client.http3Broken.Load())
}

// TestAdvGD5ANewerClaimedOutcomeMustBeTheVisibleOne is the race the author's forced-order tests
// cannot see: both outcomes claim, in attempt order, and the effects land in whichever order the
// scheduler produces.
func TestAdvGD5ANewerClaimedOutcomeMustBeTheVisibleOne(t *testing.T) {
	iterations := advgD5Iterations()
	var staleFailureWins, staleSuccessWins, staleFailureAfterResetWins int

	for index := 0; index < iterations; index++ {
		// (1) attempt 1 fails, attempt 2 succeeds. Attempt 2 is the newest observation, so the
		// verdict must be clear. A non-zero verdict here is the OLD failure overwriting the NEWER
		// success.
		if verdict := advgD5Pair(
			func(client *Client) { client.markHTTP3Broken(1) },
			func(client *Client) { client.clearHTTP3Broken(2) },
		); verdict != 0 {
			staleFailureWins++
		}

		// (2) attempt 1 succeeds, attempt 2 fails. Attempt 2 is the newest observation, so the
		// verdict must be armed. A zero verdict here is the OLD success clearing the NEWER failure
		// - the direction in which the memory stops working and every dial pays a failed HTTP/3
		// attempt.
		if verdict := advgD5Pair(
			func(client *Client) { client.clearHTTP3Broken(1) },
			func(client *Client) { client.markHTTP3Broken(2) },
		); verdict == 0 {
			staleSuccessWins++
		}

		// (3) the production transition. One attempt (number 1) is in flight when
		// ResetConnections runs: supersede marks it stale and the verdict is cleared. Its failure
		// must not re-arm the verdict on the network just entered. The real ResetConnections is
		// called, so the order inside it is the production order and not this test's reading of it.
		client := &Client{http3: &advgD5IdleHTTP3Client{}}
		client.http3Attempt.Store(1)
		gate := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-gate
			client.markHTTP3Broken(1)
		}()
		go func() {
			defer wait.Done()
			<-gate
			client.ResetConnections()
		}()
		close(gate)
		wait.Wait()
		if client.http3Broken.Load() != 0 {
			staleFailureAfterResetWins++
		}
	}

	t.Logf("ADVG_D5 iterations=%d case1_old_failure_armed_after_newer_success=%d "+
		"case2_old_success_cleared_newer_failure=%d case3_old_failure_rearmed_after_reset=%d",
		iterations, staleFailureWins, staleSuccessWins, staleFailureAfterResetWins)

	const explanation = "claimHTTP3Outcome orders the CLAIMS, not the EFFECTS: both attempts pass " +
		"the claim (older first, newer second) and the http3Broken/Store/CAS that implements each " +
		"outcome is a separate unguarded read-modify-write, so it can land in the opposite order. " +
		"The verdict is then decided by the attempt that reported last, which is exactly the " +
		"property the sequence guard was added to remove"
	require.Zero(t, staleFailureWins, explanation)
	require.Zero(t, staleSuccessWins, explanation)
	require.Zero(t, staleFailureAfterResetWins, explanation)
}
