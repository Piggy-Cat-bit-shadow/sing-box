package http

// The HTTP/3 -> HTTP/2 fallback MEMORY, pinned end to end.
//
// # The failure this file exists for
//
// A client that falls back to HTTP/2 after a failed HTTP/3 attempt must REMEMBER that failure, or
// it pays the failed attempt again on every connection. The memory is only safe if it is bounded
// and reversible, because the failure it records is usually transient (a UDP path that is
// rate-limited for a moment, a peer that answers one bad packet, a network that is changing).
// A memory that outlives the failure turns "HTTP/3 was unavailable once" into "this client speaks
// HTTP/2", which is a permanent downgrade decided by a single event -- and on a path such as
// Cloudflare WARP, where HTTP/3 is the point, the user sees "HTTP/3 never works here".
//
// So the properties are:
//
//	1. a fallback-eligible failure falls back            (existing: client_h3_fallback_window_test.go)
//	2. inside the window, HTTP/3 is not attempted again  (here)
//	3. when the window expires, HTTP/3 IS tried again    (here) -- the LX bug: never permanent
//	4. a successful HTTP/3 clears the memory completely  (here) -- deadline AND escalation
//	5. a successful HTTP/2 does not disqualify HTTP/3    (here)
//	6. a neutral outcome arms nothing                    (here) -- cancel, ineligible error, strict
//	7. no stale state survives a restart or reset        (here)
//	8. concurrent failures are one event, not N          (here)
//
// Time is never the EVIDENCE here: the window is a deadline compared against time.Now() on each
// dial, so a test moves the stored deadline into the past to expire it, and every assertion about
// what a dial does is made on observable attempts. The one test that does wait on the production
// clock (TestHTTP3BackoffExpiresOnTheProductionClock) waits so that the claim "this expires by
// itself" is proven without the test writing any state at all.

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// scriptableHTTP3Client is an HTTP/3 client whose outcome the test decides. It counts attempts,
// returns a settable error, and can hold every attempt INSIDE the call so a test can create a
// genuine concurrent burst: every dial has passed the availability check before any of them
// reports failure.
type scriptableHTTP3Client struct {
	access   sync.Mutex
	attempts int
	err      error
	entered  chan struct{}
	release  chan struct{}
}

// newFailingHTTP3Client returns a client that fails with the one error the fallback path treats as
// evidence: ErrHTTP3Unavailable (see retry_boundary_test.go for why that sentinel, and only it, is
// fallback-eligible).
func newFailingHTTP3Client() *scriptableHTTP3Client {
	return &scriptableHTTP3Client{err: ErrHTTP3Unavailable}
}

func (c *scriptableHTTP3Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	c.access.Lock()
	c.attempts++
	err := c.err
	entered, release := c.entered, c.release
	c.access.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if release != nil {
		<-release
	}
	if err != nil {
		return nil, err
	}
	return &backoffProbeConn{}, nil
}

func (c *scriptableHTTP3Client) attemptCount() int {
	c.access.Lock()
	defer c.access.Unlock()
	return c.attempts
}

func (c *scriptableHTTP3Client) setError(err error) {
	c.access.Lock()
	c.err = err
	c.access.Unlock()
}

// OpenTunnel is not what these tests drive; the transport report is covered elsewhere.
func (c *scriptableHTTP3Client) OpenTunnel(ctx context.Context, request tunnelRequest) (DatagramStream, error) {
	return nil, ErrHTTP3Unavailable
}

func (c *scriptableHTTP3Client) ResetConnection() {}
func (c *scriptableHTTP3Client) Close() error     { return nil }

// backoffProbeConn stands in for an established HTTP/3 connection. Nothing reads from it: what is
// under test is which BRANCH was taken, and a connection object is how that branch reports itself.
type backoffProbeConn struct{ closed atomic.Bool }

func (c *backoffProbeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *backoffProbeConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *backoffProbeConn) Close() error                     { c.closed.Store(true); return nil }
func (c *backoffProbeConn) LocalAddr() net.Addr              { return M.Socksaddr{} }
func (c *backoffProbeConn) RemoteAddr() net.Addr             { return M.Socksaddr{} }
func (c *backoffProbeConn) SetDeadline(time.Time) error      { return nil }
func (c *backoffProbeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *backoffProbeConn) SetWriteDeadline(time.Time) error { return nil }

// countingH2Dialer is the HTTP/2 / HTTP-1.1 fallback branch.
//
//	serve == false -> the dial fails, which is how the tests observe "the fallback branch ran"
//	                  without depending on a live server
//	serve == true  -> the dial SUCCEEDS and answers the CONNECT with 200, which is what a working
//	                  HTTP/2 session looks like from this client's side
type countingH2Dialer struct {
	calls atomic.Int64
	err   error
	serve bool
}

func (d *countingH2Dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.calls.Add(1)
	if !d.serve {
		if d.err != nil {
			return nil, d.err
		}
		return nil, ErrHTTP3Unavailable
	}
	clientConn, serverConn := net.Pipe()
	go serveCannedConnect(serverConn)
	return clientConn, nil
}

func (d *countingH2Dialer) callCount() int { return int(d.calls.Load()) }

func (d *countingH2Dialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, ErrHTTP3Unavailable
}

// serveCannedConnect answers one CONNECT with 200 and then holds the pipe open until the client
// closes it, so the returned connection is a live fallback session rather than a torn-down one.
func serveCannedConnect(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}
	_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, reader)
}

// newBackoffMemoryClient builds a client whose HTTP/3 is the injected double and whose fallback is
// the counting dialer, so every assertion below is about WHICH branch ran and what was remembered.
func newBackoffMemoryClient(http3 http3Client, fallback N.Dialer, disableFallback bool) *Client {
	return &Client{
		http3:                  http3,
		http1Dialer:            fallback,
		disableVersionFallback: disableFallback,
	}
}

// dialTarget is the destination these tests dial. Nothing resolves it: the doubles answer directly.
var dialTarget = M.ParseSocksaddr("target.example:443")

func dialOnce(t *testing.T, client *Client) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return client.DialContext(ctx, "tcp", dialTarget)
}

// http3BrokenWindow reports the remaining time on the remembered verdict, or 0 when none is armed.
func http3BrokenWindow(client *Client) time.Duration {
	brokenUntil := client.http3Broken.Load()
	if brokenUntil == 0 {
		return 0
	}
	return time.Duration(brokenUntil - time.Now().UnixNano())
}

// expireHTTP3Window is the controllable clock. The decision under test is
// `time.Now().UnixNano() >= brokenUntil`, so moving the stored deadline into the past is exactly
// what the passage of the window does -- without a sleep, and without touching the escalation
// counter, so a test can tell "the deadline expired" from "the schedule was reset".
func expireHTTP3Window(client *Client) {
	client.http3Broken.Store(time.Now().Add(-time.Nanosecond).UnixNano())
}

// Invariant 2: inside the window the client does not hammer HTTP/3, and traffic inside the window
// does not extend or escalate the memory. A window that were merely a delay would retry HTTP/3 on
// every connection and pay the failed attempt every time.
func TestHTTP3BackoffWindowSuppressesRepeatedAttempts(t *testing.T) {
	h3 := newFailingHTTP3Client()
	fallback := &countingH2Dialer{}
	client := newBackoffMemoryClient(h3, fallback, false)

	_, err := dialOnce(t, client)
	require.Error(t, err, "the fallback dialer fails, so the dial reports that failure")
	require.Equal(t, 1, h3.attemptCount(), "the first dial must attempt HTTP/3")
	require.Equal(t, 1, fallback.callCount(), "and fall back to the other transport")

	armed := client.http3Broken.Load()
	require.NotZero(t, armed, "a fallback-eligible failure must be remembered")
	require.Greater(t, http3BrokenWindow(client), time.Duration(0))
	require.LessOrEqual(t, http3BrokenWindow(client), http3BrokenBackoffInitial,
		"the first window is the initial backoff, not something longer")

	for attempt := 0; attempt < 8; attempt++ {
		_, err = dialOnce(t, client)
		require.Error(t, err)
	}
	require.Equal(t, 1, h3.attemptCount(),
		"no HTTP/3 attempt may be made inside the backoff window, or the window is not a memory at all")
	require.Equal(t, 9, fallback.callCount(),
		"every dial inside the window still gets the fallback transport")
	require.Equal(t, armed, client.http3Broken.Load(),
		"traffic inside the window must not move the deadline: the window is a period, not a countdown that traffic restarts")
	require.Equal(t, int64(http3BrokenBackoffInitial), client.http3Backoff.Load(),
		"and it must not escalate: nothing failed again")
}

// Invariant 3, deterministic half: the memory is a DEADLINE, not a flag. The LX failure was a
// client that never tried HTTP/3 again after one fast failure; the difference between that and
// this is entirely whether the expiry test can flip the decision back.
func TestHTTP3BackoffWindowExpiresAndHTTP3IsRetried(t *testing.T) {
	h3 := newFailingHTTP3Client()
	fallback := &countingH2Dialer{}
	client := newBackoffMemoryClient(h3, fallback, false)

	_, err := dialOnce(t, client)
	require.Error(t, err)
	require.Equal(t, 1, h3.attemptCount())
	require.False(t, client.http3Available(), "HTTP/3 is suppressed while the window is open")

	expireHTTP3Window(client)

	require.True(t, client.http3Available(),
		"an expired verdict must stop suppressing HTTP/3: a permanent preference for HTTP/2 is the bug this pins")
	_, err = dialOnce(t, client)
	require.Error(t, err)
	require.Equal(t, 2, h3.attemptCount(),
		"the dial after expiry must actually attempt HTTP/3 again, not merely consider it available")
	require.Equal(t, 2, fallback.callCount(),
		"and it still falls back when the re-attempt fails")
	require.Equal(t, int64(2*http3BrokenBackoffInitial), client.http3Backoff.Load(),
		"a second failed EVENT escalates the schedule by one step")
}

// Invariant 3, production-clock half: expiry happens with the test writing NOTHING. The window has
// no timer behind it -- it is a stored deadline compared on each dial -- so this waits it out and
// then requires an actual re-attempt. It is the only evidence that the memory cannot outlive the
// failure on its own.
func TestHTTP3BackoffExpiresOnTheProductionClock(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the production backoff window")
	}
	h3 := newFailingHTTP3Client()
	fallback := &countingH2Dialer{}
	client := newBackoffMemoryClient(h3, fallback, false)

	_, err := dialOnce(t, client)
	require.Error(t, err)
	require.Equal(t, 1, h3.attemptCount())
	require.False(t, client.http3Available())

	giveUp := time.Now().Add(http3BrokenBackoffInitial + 5*time.Second)
	for !client.http3Available() && time.Now().Before(giveUp) {
		time.Sleep(25 * time.Millisecond)
	}
	require.True(t, client.http3Available(),
		"the production window must expire by itself; if it does not, the client is stuck on HTTP/2 forever")

	_, err = dialOnce(t, client)
	require.Error(t, err)
	require.Equal(t, 2, h3.attemptCount(), "and the next dial must attempt HTTP/3")
	require.Equal(t, 2, fallback.callCount())
}

// Invariant 4: a successful HTTP/3 restores HTTP/3 -- both the deadline and the escalation. If the
// escalation survived the success, a path that recovered would keep paying the penalty it earned
// while it was broken, and the penalty would grow across recoveries instead of being forgotten.
func TestHTTP3SuccessClearsBackoffAndEscalation(t *testing.T) {
	h3 := newFailingHTTP3Client()
	fallback := &countingH2Dialer{}
	client := newBackoffMemoryClient(h3, fallback, false)

	// Failure event 1.
	_, err := dialOnce(t, client)
	require.Error(t, err)
	require.Equal(t, int64(http3BrokenBackoffInitial), client.http3Backoff.Load())

	// Failure event 2, after the window: one escalation step.
	expireHTTP3Window(client)
	_, err = dialOnce(t, client)
	require.Error(t, err)
	require.Equal(t, 2, h3.attemptCount())
	require.Equal(t, int64(2*http3BrokenBackoffInitial), client.http3Backoff.Load())
	require.LessOrEqual(t, http3BrokenWindow(client), 2*http3BrokenBackoffInitial)

	// HTTP/3 recovers.
	h3.setError(nil)
	expireHTTP3Window(client)
	fallbackBefore := fallback.callCount()
	conn, err := dialOnce(t, client)
	require.NoError(t, err, "a recovered HTTP/3 must be used")
	require.NotNil(t, conn)
	_ = conn.Close()
	require.Equal(t, fallbackBefore, fallback.callCount(),
		"a successful HTTP/3 must not touch the fallback transport at all")
	require.Zero(t, client.http3Broken.Load(), "success clears the verdict")
	require.Zero(t, client.http3Backoff.Load(),
		"and clears the escalation, not only the deadline: the schedule must restart from the beginning")
	require.True(t, client.http3Available())

	// The proof that the escalation was really forgotten: the next failure starts at the initial
	// backoff rather than continuing from the doubled one.
	h3.setError(ErrHTTP3Unavailable)
	_, err = dialOnce(t, client)
	require.Error(t, err)
	require.Equal(t, int64(http3BrokenBackoffInitial), client.http3Backoff.Load(),
		"a failure after a success must arm the INITIAL window, so a transient failure is never charged at the rate of an old outage")
	require.LessOrEqual(t, http3BrokenWindow(client), http3BrokenBackoffInitial)
}

// Invariant 5: HTTP/2 working is not evidence about HTTP/3. A session that succeeds over the
// fallback must neither extend nor clear the HTTP/3 memory, and -- the half that matters -- must
// not stop HTTP/3 from being tried when the window expires.
func TestHTTP2SuccessDoesNotDisqualifyHTTP3(t *testing.T) {
	h3 := newFailingHTTP3Client()
	fallback := &countingH2Dialer{serve: true}
	client := newBackoffMemoryClient(h3, fallback, false)

	conn, err := dialOnce(t, client)
	require.NoError(t, err, "the session must be established over the fallback transport")
	require.NotNil(t, conn)
	_ = conn.Close()
	require.Equal(t, 1, h3.attemptCount())
	require.Equal(t, 1, fallback.callCount())
	armed := client.http3Broken.Load()
	require.NotZero(t, armed)

	// Four more successful fallback sessions inside the window.
	for session := 0; session < 4; session++ {
		conn, err = dialOnce(t, client)
		require.NoError(t, err)
		require.NotNil(t, conn)
		_ = conn.Close()
	}
	require.Equal(t, 5, fallback.callCount())
	require.Equal(t, 1, h3.attemptCount(), "an HTTP/2 session is not evidence about HTTP/3 and must not add an attempt")
	require.Equal(t, armed, client.http3Broken.Load(),
		"a successful HTTP/2 must neither extend nor clear the HTTP/3 memory")

	// The window expires while HTTP/2 is working perfectly.
	expireHTTP3Window(client)
	h3.setError(nil)
	fallbackBefore := fallback.callCount()
	conn, err = dialOnce(t, client)
	require.NoError(t, err)
	require.NotNil(t, conn)
	_ = conn.Close()
	require.Equal(t, 2, h3.attemptCount(),
		"HTTP/2 succeeding must not permanently disqualify HTTP/3: the next window must be spent on a real re-attempt")
	require.Equal(t, fallbackBefore, fallback.callCount(), "and the recovered dial must not need the fallback")
	require.Zero(t, client.http3Broken.Load())
}

// Invariant 6: outcomes that say nothing about HTTP/3 must arm NOTHING -- neither the deadline nor
// the escalation. Arming the memory on a neutral event is a fallback in itself, because it makes
// the NEXT dial skip HTTP/3 (which is exactly the P1-4 defect fixed in
// client_h3_strict_fallback_test.go, re-pinned here for the backoff counter as well).
func TestNeutralOutcomesArmNoHTTP3Memory(t *testing.T) {
	assertNothingArmed := func(t *testing.T, client *Client) {
		t.Helper()
		require.Zero(t, client.http3Broken.Load(), "no HTTP/3 verdict may be recorded")
		require.Zero(t, client.http3Backoff.Load(), "and no escalation may be scheduled")
		require.True(t, client.http3Available(), "HTTP/3 must stay available")
	}

	t.Run("caller cancellation", func(t *testing.T) {
		h3 := &hangingHTTP3Client{started: make(chan struct{}, 1)}
		fallback := &countingH2Dialer{}
		client := newBackoffMemoryClient(h3, fallback, false)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := client.DialContext(ctx, "tcp", dialTarget)
			done <- err
		}()
		<-h3.started
		cancel()
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(15 * time.Second):
			t.Fatal("the dial did not return after the caller cancelled")
		}
		require.Zero(t, fallback.callCount(), "a cancelled caller must not start a fallback dial: nobody is waiting")
		assertNothingArmed(t, client)
	})

	t.Run("error that is not fallback eligible", func(t *testing.T) {
		protocolViolation := errors.New("QUIC PROTOCOL_VIOLATION")
		h3 := newFailingHTTP3Client()
		h3.setError(protocolViolation)
		fallback := &countingH2Dialer{}
		client := newBackoffMemoryClient(h3, fallback, false)

		_, err := dialOnce(t, client)
		require.ErrorIs(t, err, protocolViolation, "an ineligible error must reach the caller unchanged")
		require.Zero(t, fallback.callCount(), "and must not trigger a fallback the retry boundary forbids")
		assertNothingArmed(t, client)
	})

	t.Run("strict configuration", func(t *testing.T) {
		h3 := newFailingHTTP3Client()
		fallback := &countingH2Dialer{}
		client := newBackoffMemoryClient(h3, fallback, true)

		_, err := dialOnce(t, client)
		require.Error(t, err, "disable_version_fallback must report the HTTP/3 failure")
		require.Zero(t, fallback.callCount(), "and must not fall back, on this dial or any later one")
		assertNothingArmed(t, client)

		// The reason arming matters: a remembered verdict would skip HTTP/3 on the NEXT dial, which
		// is a fallback the user's configuration forbade.
		_, err = dialOnce(t, client)
		require.Error(t, err)
		require.Equal(t, 2, h3.attemptCount(), "every strict dial must keep trying HTTP/3")
		require.Zero(t, fallback.callCount())
	})
}

// Invariant 7: the memory belongs to ONE client, and both ways of starting over discard it. A
// package-level or process-wide verdict would survive a reconnect and outlive the failure that
// created it -- the shape that makes "HTTP/3 never works" permanent for the life of the process.
func TestHTTP3MemoryIsPerClientAndFullyReset(t *testing.T) {
	firstH3 := newFailingHTTP3Client()
	first := newBackoffMemoryClient(firstH3, &countingH2Dialer{}, false)
	_, err := dialOnce(t, first)
	require.Error(t, err)
	require.NotZero(t, first.http3Broken.Load())
	require.Equal(t, int64(http3BrokenBackoffInitial), first.http3Backoff.Load())

	// A restart is a NEW client: it must inherit nothing.
	secondH3 := newFailingHTTP3Client()
	second := newBackoffMemoryClient(secondH3, &countingH2Dialer{}, false)
	require.True(t, second.http3Available(), "a fresh client must start with HTTP/3 enabled")
	require.Zero(t, second.http3Broken.Load(), "no process-wide verdict may exist")
	require.Zero(t, second.http3Backoff.Load())
	_, err = dialOnce(t, second)
	require.Error(t, err)
	require.Equal(t, 1, secondH3.attemptCount(), "and its first dial must actually attempt HTTP/3")

	// The in-place restart (a network change) discards the verdict AND the schedule.
	first.ResetConnections()
	require.True(t, first.http3Available(), "a reset must re-enable HTTP/3")
	require.Zero(t, first.http3Broken.Load())
	require.Zero(t, first.http3Backoff.Load(), "a reset must also discard the escalation schedule")
	_, err = dialOnce(t, first)
	require.Error(t, err)
	require.Equal(t, 2, firstH3.attemptCount(), "and the next dial must attempt HTTP/3 again")

	// Closing is a local lifecycle event: it must not panic, and it must not leave the memory in a
	// state a later dial reads as a verdict. There is no timer to leak -- the window is a stored
	// deadline compared on each dial, which is what the production-clock test above proves -- so
	// Close has no scheduled work to cancel and the only observable requirement is that the state
	// survives no longer than the object does.
	armed := first.http3Broken.Load()
	require.NoError(t, first.Close())
	require.NoError(t, first.Close(), "close must be idempotent")
	require.Equal(t, armed, first.http3Broken.Load(),
		"close must not rewrite the verdict of the object being discarded; what matters is that no other client can read it")
	// `second` armed its own memory when its own dial failed, so what proves isolation is the SHAPE
	// of its state: one failure of its own, at the initial backoff, not the first client's verdict
	// and not the schedule the first client had escalated.
	require.Equal(t, int64(http3BrokenBackoffInitial), second.http3Backoff.Load(),
		"the other client's memory is its own: one failure of its own, at the initial backoff")
	require.LessOrEqual(t, http3BrokenWindow(second), http3BrokenBackoffInitial)
}

// Invariant 8: concurrent dials are one event. A burst of parallel connections -- a page load, a
// reconnect storm -- that meets ONE transient HTTP/3 failure must escalate the schedule ONCE. If
// each failing dial escalates, the burst multiplies the backoff by 2^N in that instant and lands
// on the ceiling, so a single fast failure is remembered for minutes: the user-visible form of
// "HTTP/3 is never tried again".
//
// The burst is made genuine rather than hoped for: every dial is held INSIDE the HTTP/3 attempt
// before any of them fails, so all of them passed the availability check while the memory was
// still unarmed.
func TestConcurrentHTTP3FailuresAreOneEscalationStep(t *testing.T) {
	const dials = 16

	h3 := newFailingHTTP3Client()
	h3.entered = make(chan struct{})
	h3.release = make(chan struct{})
	fallback := &countingH2Dialer{}
	client := newBackoffMemoryClient(h3, fallback, false)

	var group sync.WaitGroup
	start := make(chan struct{})
	for dial := 0; dial < dials; dial++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, _ = client.DialContext(ctx, "tcp", dialTarget)
		}()
	}
	close(start)
	for entered := 0; entered < dials; entered++ {
		select {
		case <-h3.entered:
		case <-time.After(15 * time.Second):
			t.Fatalf("only %d of %d dials reached the HTTP/3 attempt", entered, dials)
		}
	}
	require.Equal(t, dials, h3.attemptCount())
	require.Zero(t, client.http3Broken.Load(),
		"no verdict may exist while every attempt is still in flight: this is ONE failure observed by many dials")

	close(h3.release)
	group.Wait()

	require.Equal(t, dials, fallback.callCount(), "every dial must still reach the fallback")
	require.NotZero(t, client.http3Broken.Load(), "the failure must be remembered")
	require.Equal(t, int64(http3BrokenBackoffInitial), client.http3Backoff.Load(),
		"one transient failure must escalate the schedule once, not once per concurrent dial")
	window := http3BrokenWindow(client)
	require.Greater(t, window, time.Duration(0))
	require.LessOrEqual(t, window, http3BrokenBackoffInitial,
		"a single burst must not pin the client to HTTP/2 for the ceiling: that is the failure this test exists for")
	require.LessOrEqual(t, time.Duration(client.http3Backoff.Load()), http3BrokenBackoffMax,
		"and the schedule must never exceed its ceiling")
}
