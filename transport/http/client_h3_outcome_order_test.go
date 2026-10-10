package http

// The HTTP/3 fallback memory must be decided by the NEWEST attempt the client started.
//
// # The failure this file exists for
//
// `markHTTP3Broken` and `clearHTTP3Broken` are called when an HTTP/3 attempt REPORTS its outcome,
// and nothing ordered those reports. Two attempts can be in flight at once -- the HTTP/3 client
// serialises the handshake itself, but a dial that has already returned from its attempt and a
// dial that is about to make one are two independent goroutines -- so the report that arrives
// last is not the attempt that started last.
//
// The consequence is a verdict about the wrong network:
//
//	attempt 1 starts, meets a transient UDP stall
//	attempt 2 starts later and SUCCEEDS      -> the memory is cleared, HTTP/3 is working
//	attempt 1 finally reports its failure    -> the memory is ARMED again
//
// The client is then pinned to HTTP/2 for 5 seconds (and, because the escalation step is charged,
// for up to 5 minutes on the next event) on the strength of an observation that a newer attempt
// has already disproved. The user-visible form is the one the memory file's own header warns
// about: "HTTP/3 never works here", decided by an event that was already over.
//
// # The same shape across a transition
//
// The second test is the same defect with the network as the variable rather than another dial.
// A path change runs `ResetConnections`, which clears the memory -- and an attempt that was in
// flight against the network being LEFT then reports its failure and arms the memory on the
// network that has just been entered. The first dial on the new network is then charged for a
// failure that belonged to the old one, which is exactly "an old callback resurrecting an old
// generation".
//
// # Why the assertions are on the memory and not on the error
//
// Both dials report what they report either way; the defect is entirely in what the client
// REMEMBERS. So every assertion below is on `http3Broken` / `http3Backoff` and on whether the
// NEXT dial still attempts HTTP/3, which is the only place the memory is observable.

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// scriptedAttempt is one HTTP/3 attempt the test decides the timing and outcome of.
type scriptedAttempt struct {
	// entered is closed once the attempt is inside DialContext, so the test can act while it is
	// genuinely in flight rather than hoping.
	entered chan struct{}
	// release is what the attempt waits for before reporting. nil reports immediately.
	release chan struct{}
	// err is what the attempt reports once released. nil is a successful attempt.
	err error
}

// stagedHTTP3Client is an HTTP/3 client whose attempts are released one at a time, so a test can
// decide the ORDER in which two concurrent attempts report their outcome. That order is the whole
// subject of this file: `scriptableHTTP3Client` in the backoff-memory file holds every attempt
// against one shared gate, which makes them concurrent but not orderable.
type stagedHTTP3Client struct {
	access sync.Mutex
	calls  int
	steps  []scriptedAttempt
}

func (c *stagedHTTP3Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	c.access.Lock()
	index := c.calls
	c.calls++
	var step scriptedAttempt
	var scripted bool
	if index < len(c.steps) {
		step = c.steps[index]
		scripted = true
	}
	c.access.Unlock()
	if scripted {
		if step.entered != nil {
			close(step.entered)
		}
		if step.release != nil {
			select {
			case <-step.release:
			case <-ctx.Done():
				// The attempt's own window (or the caller) gave up on it. Reporting the
				// context error is what the real client does, and it keeps a test that
				// forgot to release from hanging.
				return nil, ctx.Err()
			}
		}
		if step.err != nil {
			return nil, step.err
		}
	}
	return &backoffProbeConn{}, nil
}

func (c *stagedHTTP3Client) attemptCount() int {
	c.access.Lock()
	defer c.access.Unlock()
	return c.calls
}

// OpenTunnel is not what these tests drive.
func (c *stagedHTTP3Client) OpenTunnel(ctx context.Context, request tunnelRequest) (DatagramStream, error) {
	return nil, ErrHTTP3Unavailable
}

func (c *stagedHTTP3Client) ResetConnection() {}
func (c *stagedHTTP3Client) Close() error     { return nil }

// dialStandTarget dials without touching *testing.T, so it is safe from the goroutine that holds
// an attempt in flight. dialOnce in the backoff-memory file calls t.Helper() and is therefore only
// usable from the test goroutine.
func dialStandTarget(client *Client) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return client.DialContext(ctx, "tcp", dialTarget)
}

// TestHTTP3StaleFailureDoesNotOverwriteANewerSuccess is the reproduction.
//
// The order is forced rather than raced: attempt 1 is held INSIDE its HTTP/3 call, attempt 2 runs
// to completion and succeeds, and only then is attempt 1 allowed to report. At baseline the
// success is overwritten by the older failure and the client is pinned to the fallback.
func TestHTTP3StaleFailureDoesNotOverwriteANewerSuccess(t *testing.T) {
	stale := scriptedAttempt{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		err:     ErrHTTP3Unavailable,
	}
	genuine := scriptedAttempt{err: ErrHTTP3Unavailable}
	h3 := &stagedHTTP3Client{steps: []scriptedAttempt{stale, {}, genuine}}
	fallback := &countingH2Dialer{}
	client := newBackoffMemoryClient(h3, fallback, false)

	// Attempt 1: the stale one. It is inside the HTTP/3 attempt and has not reported yet.
	staleResult := make(chan error, 1)
	go func() {
		_, err := dialStandTarget(client)
		staleResult <- err
	}()
	select {
	case <-stale.entered:
	case <-time.After(15 * time.Second):
		t.Fatal("the first HTTP/3 attempt never started")
	}
	require.Equal(t, 1, h3.attemptCount())

	// Attempt 2: started later, succeeds, and is therefore the newest observation. It must be
	// served over HTTP/3 with no fallback involvement.
	fallbackBefore := fallback.callCount()
	conn, err := dialStandTarget(client)
	require.NoError(t, err, "the newer attempt succeeds, so the dial must succeed")
	require.NotNil(t, conn)
	_ = conn.Close()
	require.Equal(t, 2, h3.attemptCount())
	require.Equal(t, fallbackBefore, fallback.callCount(),
		"the newer attempt succeeded over HTTP/3, so it must not touch the fallback")
	require.Zero(t, client.http3Broken.Load(),
		"precondition: a successful attempt leaves no verdict behind")

	// Now the older attempt reports. It is an observation of a moment that has already been
	// superseded, and it must not decide anything.
	close(stale.release)
	select {
	case err = <-staleResult:
	case <-time.After(15 * time.Second):
		t.Fatal("the stale HTTP/3 attempt never reported")
	}
	require.Error(t, err, "the stale attempt itself still fails; only its verdict is refused")

	require.Zero(t, client.http3Broken.Load(),
		"an OLD HTTP/3 failure overwrote a NEWER success: the client is now pinned to the "+
			"fallback transport for the backoff window on the strength of an observation the "+
			"success already disproved")
	require.Zero(t, client.http3Backoff.Load(),
		"and the escalation step was charged for it, so the next genuine failure is remembered "+
			"for twice as long as it should be")
	require.True(t, client.http3Available())

	// The half that makes it a lasting downgrade rather than a bookkeeping slip: the next dial
	// must still ATTEMPT HTTP/3.
	attemptsBefore := h3.attemptCount()
	_, err = dialStandTarget(client)
	require.Error(t, err, "the third attempt is scripted to fail")
	require.Equal(t, attemptsBefore+1, h3.attemptCount(),
		"the dial after the interleave did not attempt HTTP/3 at all: the stale failure became a "+
			"lasting error backoff, which is the user-visible form of this defect")
	require.Equal(t, int64(http3BrokenBackoffInitial), client.http3Backoff.Load(),
		"and the one failure that IS fresh must be charged at the initial step, not at the "+
			"step the stale failure escalated to")
	require.LessOrEqual(t, http3BrokenWindow(client), http3BrokenBackoffInitial)
}

// TestHTTP3StaleSuccessDoesNotClearANewerFailure is the mirror image, and it is asserted for the
// same reason: the rule is "the newest attempt decides", not "success wins".
//
// A success that started BEFORE a failure describes an earlier moment. Letting it clear the
// verdict would mean a client that has just watched HTTP/3 fail forgets immediately, and pays a
// failed attempt on every dial -- the opposite failure, and the one the memory exists to bound.
func TestHTTP3StaleSuccessDoesNotClearANewerFailure(t *testing.T) {
	stale := scriptedAttempt{entered: make(chan struct{}), release: make(chan struct{})}
	h3 := &stagedHTTP3Client{steps: []scriptedAttempt{stale, {err: ErrHTTP3Unavailable}}}
	fallback := &countingH2Dialer{}
	client := newBackoffMemoryClient(h3, fallback, false)

	staleResult := make(chan error, 1)
	go func() {
		_, err := dialStandTarget(client)
		staleResult <- err
	}()
	select {
	case <-stale.entered:
	case <-time.After(15 * time.Second):
		t.Fatal("the first HTTP/3 attempt never started")
	}

	// The newer attempt fails, and the failure is genuinely remembered.
	_, err := dialStandTarget(client)
	require.Error(t, err)
	require.NotZero(t, client.http3Broken.Load(), "the newer failure is the newest observation")
	armed := client.http3Broken.Load()

	// The older attempt now succeeds. It must not clear the newer failure.
	close(stale.release)
	select {
	case err = <-staleResult:
	case <-time.After(15 * time.Second):
		t.Fatal("the stale HTTP/3 attempt never reported")
	}
	require.NoError(t, err, "the older attempt itself succeeded")

	require.Equal(t, armed, client.http3Broken.Load(),
		"an OLD success cleared a NEWER failure: the client forgets the failure it just observed "+
			"and pays a failed HTTP/3 attempt on every dial, which is the cost the memory exists "+
			"to bound")
}

// TestHTTP3ResetSupersedesAnInFlightAttempt is the transition half.
//
// A network change runs ResetConnections. An attempt that was in flight against the network being
// left belongs to that network: its failure is not evidence about the one just entered, and
// arming the memory with it charges the first dial on the NEW network for the old one's problem.
func TestHTTP3ResetSupersedesAnInFlightAttempt(t *testing.T) {
	inFlight := scriptedAttempt{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		err:     ErrHTTP3Unavailable,
	}
	h3 := &stagedHTTP3Client{steps: []scriptedAttempt{inFlight}}
	fallback := &countingH2Dialer{}
	client := newBackoffMemoryClient(h3, fallback, false)

	result := make(chan error, 1)
	go func() {
		_, err := dialStandTarget(client)
		result <- err
	}()
	select {
	case <-inFlight.entered:
	case <-time.After(15 * time.Second):
		t.Fatal("the HTTP/3 attempt never started")
	}

	// The transition. This is the production entry an InterfaceUpdated reaches.
	client.ResetConnections()
	require.True(t, client.http3Available(), "a transition re-enables HTTP/3")

	// The attempt from the previous network now reports.
	close(inFlight.release)
	select {
	case err := <-result:
		require.Error(t, err, "the abandoned attempt still fails")
	case <-time.After(15 * time.Second):
		t.Fatal("the in-flight HTTP/3 attempt never reported")
	}

	require.Zero(t, client.http3Broken.Load(),
		"a failure that belongs to the network the client just LEFT armed the HTTP/3 verdict on "+
			"the network it just entered: the first dial on the new path is charged for the old "+
			"path's failure")
	require.Zero(t, client.http3Backoff.Load())
	require.True(t, client.http3Available())

	// And a dial on the new network really does attempt HTTP/3 again.
	attemptsBefore := h3.attemptCount()
	_, err := dialStandTarget(client)
	require.NoError(t, err)
	require.Equal(t, attemptsBefore+1, h3.attemptCount(),
		"the first dial after the transition did not attempt HTTP/3")
}

// TestHTTP3GenuineFailureAfterASuccessStartsAtTheInitialStep guards the direction a naive sequence
// guard could break: the guard must refuse only outcomes that are OLDER than one already recorded,
// never a genuine failure that is newer than the last success.
func TestHTTP3GenuineFailureAfterASuccessStartsAtTheInitialStep(t *testing.T) {
	h3 := &stagedHTTP3Client{steps: []scriptedAttempt{{}, {err: ErrHTTP3Unavailable}}}
	fallback := &countingH2Dialer{}
	client := newBackoffMemoryClient(h3, fallback, false)

	conn, err := dialStandTarget(client)
	require.NoError(t, err)
	require.NotNil(t, conn)
	_ = conn.Close()
	require.Zero(t, client.http3Broken.Load())

	_, err = dialStandTarget(client)
	require.Error(t, err, "the second attempt is scripted to fail")
	require.NotZero(t, client.http3Broken.Load(),
		"a genuine failure newer than the last success must still be remembered, or the memory "+
			"would be dead code")
	require.Equal(t, int64(http3BrokenBackoffInitial), client.http3Backoff.Load(),
		"and it must start the schedule from the beginning, because no earlier event is being "+
			"charged for it")
	require.False(t, client.http3Available())
}
