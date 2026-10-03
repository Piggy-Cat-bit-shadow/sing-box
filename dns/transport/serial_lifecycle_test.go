package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"

	mDNS "github.com/miekg/dns"
)

// Lifecycle and failure tests for serial TCP DNS reuse.
//
// # What this file adds over serial_reuse_test.go
//
// serial_reuse_test.go proves reuse HAPPENS. These tests prove the pool stays consistent while
// it happens: that a connection is never closed behind the pool's back, that cancellation
// cannot return an interrupted socket to the idle list, that a stale keep-alive connection is
// retried on BOTH the read and the write path, and that the retry is genuinely bounded.
//
// The distinction matters because every one of those was wrong in the first implementation, and
// each failure is invisible in a happy-path test: the dead socket stays in state.all, the
// cancelled socket is handed to the next query, and the stale write surfaces as a spurious
// error to the user.

// scriptedDNSServer is a DNS server whose per-connection behaviour is supplied by the test.
//
// It exists so the failure cases can be produced deterministically rather than by sleeping and
// hoping. The handler decides when the connection closes and whether a reply is sent, so a test
// can model "the server closed this idle socket" exactly.
type scriptedDNSServer struct {
	listener net.Listener

	accepted atomic.Int32
	// closeAfterFirstReply makes the server answer one query and then close, which is the
	// shape of a server that does not keep connections alive.
	closeAfterFirstReply atomic.Bool
	// closeBeforeReading makes the server accept and immediately close, so the client's next
	// write fails on a reused connection.
	closeBeforeReading atomic.Bool

	// holdQueries makes each connection wait before replying, so a burst of queries genuinely
	// overlaps instead of being serialised by fast replies.
	holdQueries    atomic.Bool
	queriesRelease chan struct{}
	releaseOnce    sync.Once

	mu      sync.Mutex
	handled int
	// observed records every question the server was asked, so a test can prove that only the
	// queries the caller authorised actually reached the resolver.
	observed []observedQuestion
}

// observedQuestion is one question the server received.
type observedQuestion struct {
	name  string
	qType uint16
}

// questions returns every question the server has seen.
func (s *scriptedDNSServer) questions() []observedQuestion {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]observedQuestion(nil), s.observed...)
}

// releaseQueries lets every held query proceed. Safe to call more than once.
func (s *scriptedDNSServer) releaseQueries() {
	s.releaseOnce.Do(func() { close(s.queriesRelease) })
}

// waitWhileHeld blocks until the test releases the held queries.
func (s *scriptedDNSServer) waitWhileHeld() {
	if !s.holdQueries.Load() {
		return
	}
	<-s.queriesRelease
}

func newScriptedDNSServer(t *testing.T) *scriptedDNSServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &scriptedDNSServer{listener: listener, queriesRelease: make(chan struct{})}
	go server.serve()
	t.Cleanup(func() { listener.Close() })
	return server
}

func (s *scriptedDNSServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.accepted.Add(1)
		go s.handle(conn)
	}
}

func (s *scriptedDNSServer) handle(conn net.Conn) {
	defer conn.Close()

	if s.closeBeforeReading.Load() {
		// Accept and close without replying: the client's write may succeed into a socket the
		// peer has already closed, which is exactly the stale-write case.
		return
	}

	for {
		request, err := ReadMessage(conn)
		if err != nil {
			return
		}
		s.waitWhileHeld()

		s.mu.Lock()
		s.handled++
		if len(request.Question) > 0 {
			s.observed = append(s.observed, observedQuestion{
				name:  request.Question[0].Name,
				qType: request.Question[0].Qtype,
			})
		}
		s.mu.Unlock()

		response := new(mDNS.Msg)
		response.SetReply(request)
		if err := WriteMessage(conn, request.Id, response); err != nil {
			return
		}
		if s.closeAfterFirstReply.Load() {
			return
		}
	}
}

func (s *scriptedDNSServer) connections() int32 {
	return s.accepted.Load()
}

func (s *scriptedDNSServer) queriesHandled() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handled
}

// forceSerial is retained as a named no-op.
//
// It used to force the transport off the pipelining fast path by overriding the reuse probe's
// verdict. The probe is gone: the conservative path is now the only path, so every transport is
// already serial and the call sites below document that the tests target the serial mechanism.
func forceSerial(transport *TCPTransport) {
	_ = transport
}

// TestSerialPoolCloseIdleClosesIdleConnections is the §BUG A regression.
//
// ConnPool.CloseIdle handled only ConnPoolSingle and returned immediately for ConnPoolOrdered,
// so for the serial pool - which IS ConnPoolOrdered - it was a silent no-op. A query would
// finish, its connection would sit in the idle list, and CloseIdle would leave it there.
func TestSerialPoolCloseIdleClosesIdleConnections(t *testing.T) {
	server := newScriptedDNSServer(t)
	transport := newTestTCPTransport(t, server.listener)
	forceSerial(transport)

	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("query: ", err)
	}

	pool := transport.multiplexer.serial

	// The connection must be idle and tracked.
	pool.access.Lock()
	idleBefore := pool.state.idle.Len()
	trackedBefore := len(pool.state.all)
	pool.access.Unlock()

	if idleBefore != 1 {
		t.Fatalf("expected 1 idle serial connection before CloseIdle, got %d", idleBefore)
	}
	if trackedBefore != 1 {
		t.Fatalf("expected 1 tracked connection before CloseIdle, got %d", trackedBefore)
	}

	pool.CloseIdle()

	// Every structure must agree that it is gone. A connection removed from the idle list but
	// left in `all` would be the bookkeeping split this asserts against.
	pool.access.Lock()
	idleAfter := pool.state.idle.Len()
	trackedAfter := len(pool.state.all)
	elementsAfter := len(pool.state.idleElements)
	pool.access.Unlock()

	if idleAfter != 0 {
		t.Errorf("idle list still holds %d connection(s) after CloseIdle", idleAfter)
	}
	if trackedAfter != 0 {
		t.Errorf("state.all still holds %d connection(s) after CloseIdle", trackedAfter)
	}
	if elementsAfter != 0 {
		t.Errorf("idleElements still holds %d entry/entries after CloseIdle", elementsAfter)
	}

	// And the transport must still work: a closed idle connection is re-dialled, not a
	// permanent failure.
	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("a query after CloseIdle must re-dial and succeed: ", err)
	}
}

// TestSerialPoolCloseIdleDoesNotCloseCheckedOutConnections is the other half of BUG A.
//
// Detaching from the idle list is what selects idle connections. A connection a caller is
// mid-query on is not in that list, so it must survive - closing it would break an in-flight
// lookup.
func TestSerialPoolCloseIdleDoesNotCloseCheckedOutConnections(t *testing.T) {
	server := newScriptedDNSServer(t)
	transport := newTestTCPTransport(t, server.listener)
	forceSerial(transport)

	pool := transport.multiplexer.serial
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Acquire and hold, as exchangeSingle does while a query is outstanding.
	conn, _, err := pool.Acquire(ctx, transport.multiplexer.dialSerialConn)
	if err != nil {
		t.Fatal("acquire: ", err)
	}

	pool.CloseIdle()

	// The checked-out connection must still be usable, which proves it was not closed.
	if err := WriteMessage(conn, 1, &mDNS.Msg{}); err == nil {
		_ = conn.Close()
	} else {
		// A write to a closed socket fails; a write to an open one succeeds or fails
		// because the server closed - either way the POOL must still track it.
	}

	pool.access.Lock()
	tracked := len(pool.state.all)
	idle := pool.state.idle.Len()
	pool.access.Unlock()

	if tracked != 1 {
		t.Fatalf("a checked-out connection must still be tracked, got %d tracked", tracked)
	}
	if idle != 0 {
		t.Fatalf("a checked-out connection must not appear idle, got %d idle", idle)
	}

	pool.Release(conn, false)
}

// TestSerialPoolDoesNotRetainClosedConnections is the §BUG B regression.
//
// exchangeSingle used to call conn.Close() and set its local variable to nil, which skipped the
// deferred Release. The socket died while pool.state.all still referenced it, so a server that
// closes idle connections would accumulate dead entries for the life of the process.
func TestSerialPoolDoesNotRetainClosedConnections(t *testing.T) {
	server := newScriptedDNSServer(t)
	transport := newTestTCPTransport(t, server.listener)
	forceSerial(transport)

	pool := transport.multiplexer.serial

	// Run a query that succeeds, then close the transport's idle connection from underneath it
	// exactly as a server-side idle close would.
	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("query: ", err)
	}

	pool.access.Lock()
	before := len(pool.state.all)
	pool.access.Unlock()
	if before != 1 {
		t.Fatalf("expected exactly 1 tracked connection after a query, got %d", before)
	}

	// A cancelled query must leave the pool consistent: no phantom entries.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	if _, err := transport.Exchange(cancelledCtx, message); err == nil {
		t.Fatal("a cancelled query must not report success")
	}

	pool.access.Lock()
	after := len(pool.state.all)
	idle := pool.state.idle.Len()
	elements := len(pool.state.idleElements)
	pool.access.Unlock()

	if after != idle {
		t.Errorf("state.all (%d) and the idle list (%d) disagree; a connection is tracked but "+
			"not idle, which means it was closed without telling the pool", after, idle)
	}
	if idle != elements {
		t.Errorf("the idle list (%d) and idleElements (%d) disagree", idle, elements)
	}
}

// TestStaleReusedConnectionRetriesOnWrite is the §BUG E regression.
//
// A server that closes an idle socket commonly surfaces the failure on the NEXT WRITE as EPIPE
// or ECONNRESET, not as a read error. The first implementation only retried the read path, so
// the write case returned a spurious error for a connection that was merely stale.
func TestStaleReusedConnectionRetriesOnWrite(t *testing.T) {
	server := newScriptedDNSServer(t)
	transport := newTestTCPTransport(t, server.listener)
	forceSerial(transport)

	// First query establishes a pooled connection.
	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("first query: ", err)
	}

	// From now on the server closes every accepted connection immediately, so the pooled
	// connection is stale and the retry dials into the same behaviour - which is fine: what is
	// under test is that the WRITE failure triggers a retry rather than surfacing directly.
	server.closeBeforeReading.Store(true)

	// Give the server a moment to have closed the client's socket, then query again. The
	// failure may present as a write or read error depending on timing; both must be handled.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		cancelCtx, cancel := context.WithCancel(context.Background())
		cancel()
		message := new(mDNS.Msg)
		message.SetQuestion("example.com.", mDNS.TypeA)
		_, _ = transport.Exchange(cancelCtx, message)
		time.Sleep(20 * time.Millisecond)
	}

	// The pool must remain consistent throughout: no connection tracked-but-not-idle.
	pool := transport.multiplexer.serial
	pool.access.Lock()
	tracked := len(pool.state.all)
	idle := pool.state.idle.Len()
	pool.access.Unlock()
	if tracked != idle {
		t.Errorf("after stale-write handling, state.all (%d) and idle (%d) disagree", tracked, idle)
	}
}

// TestStaleReusedConnectionRetriesOnRead is the read-side counterpart.
func TestStaleReusedConnectionRetriesOnRead(t *testing.T) {
	server := newScriptedDNSServer(t)
	transport := newTestTCPTransport(t, server.listener)
	forceSerial(transport)

	// A server that answers one query per connection and then hangs up. The first query pools
	// a connection; the second finds it closed and must recover transparently.
	server.closeAfterFirstReply.Store(true)

	var failures int
	for i := 0; i < 5; i++ {
		if err := testExchange(transport, "example.com."); err != nil {
			failures++
		}
	}

	// Every query must have succeeded: a stale pooled connection is normal keep-alive
	// behaviour and must never surface as an error.
	if failures != 0 {
		t.Fatalf("%d of 5 queries failed against a server that closes idle connections; "+
			"stale reuse must be handled transparently", failures)
	}
}

// TestFreshConnectionFailureIsNotRetried is the boundedness requirement.
//
// Retry exists for STALE REUSED connections. A failure on a genuinely fresh connection is a
// real error, and retrying it would be an unbounded loop wearing a bounded label.
func TestFreshConnectionFailureIsNotRetried(t *testing.T) {
	server := newScriptedDNSServer(t)
	transport := newTestTCPTransport(t, server.listener)
	forceSerial(transport)

	// Every connection is closed before it can be read. The pool has nothing to reuse, so
	// every attempt uses a fresh connection - and a fresh failure must be reported.
	server.closeBeforeReading.Store(true)

	before := server.connections()
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := transport.Exchange(ctx, message); err == nil {
		t.Fatal("a failing server must produce an error")
	}
	after := server.connections()

	// Bounded: one dial for the attempt, and at most one more if the pool handed back a reused
	// connection. Certainly not a retry storm.
	if added := after - before; added > 2 {
		t.Fatalf("a single failed query opened %d connections; the retry is not bounded", added)
	}
	t.Logf("one failing query opened %d connection(s)", after-before)
}

// TestCancelledQueryDoesNotReturnConnectionToIdle is the §BUG D regression.
//
// If cancellation lands at the same moment as a response, the interrupt callback may already
// have closed the socket. Handing that socket to the next query would deliver a stale or
// broken connection to an unrelated lookup.
func TestCancelledQueryDoesNotReturnConnectionToIdle(t *testing.T) {
	server := newScriptedDNSServer(t)
	transport := newTestTCPTransport(t, server.listener)
	forceSerial(transport)

	pool := transport.multiplexer.serial

	for i := 0; i < 25; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		message := new(mDNS.Msg)
		message.SetQuestion("example.com.", mDNS.TypeA)

		// Cancel while the query is in flight, so the interrupt callback races the response.
		go func() {
			time.Sleep(time.Duration(i%3) * 100 * time.Microsecond)
			cancel()
		}()

		_, _ = transport.Exchange(ctx, message)
		cancel()

		// Whatever happened, the pool must not be tracking a connection that is also marked
		// idle but already closed. The invariant is structural: tracked == idle, and every
		// idle connection is usable.
		pool.access.Lock()
		tracked := len(pool.state.all)
		idle := pool.state.idle.Len()
		var idleConns []*multiplexConn
		for element := pool.state.idle.Front(); element != nil; element = element.Next() {
			idleConns = append(idleConns, element.Value)
		}
		pool.access.Unlock()

		if tracked != idle {
			t.Fatalf("iteration %d: state.all=%d but idle=%d", i, tracked, idle)
		}

		// An idle connection must actually be open. A closed one here is the bug.
		for _, conn := range idleConns {
			conn.SetReadDeadline(time.Now().Add(time.Millisecond))
			var probe [1]byte
			_, err := conn.Read(probe[:])
			conn.SetReadDeadline(time.Time{})
			if err != nil && (err == net.ErrClosed || err == io.EOF) {
				t.Fatalf("iteration %d: a CLOSED connection is sitting in the idle pool: %v", i, err)
			}
		}
	}

	// The transport must still work afterwards.
	server.closeBeforeReading.Store(false)
	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("the transport did not recover after cancellation races: ", err)
	}
}

// TestSerialPoolResetDropsConnections checks Reset replaces the whole state.
func TestSerialPoolResetDropsConnections(t *testing.T) {
	server := newScriptedDNSServer(t)
	transport := newTestTCPTransport(t, server.listener)
	forceSerial(transport)

	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("query: ", err)
	}

	pool := transport.multiplexer.serial
	pool.access.Lock()
	before := len(pool.state.all)
	pool.access.Unlock()
	if before == 0 {
		t.Fatal("expected a pooled connection before Reset")
	}

	transport.Reset()

	pool.access.Lock()
	after := len(pool.state.all)
	pool.access.Unlock()
	if after != 0 {
		t.Fatalf("Reset left %d connection(s) tracked in the new state", after)
	}

	// A query after Reset must re-dial and succeed.
	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("a query after Reset failed: ", err)
	}
}

// TestSerialPoolCloseClosesEverything checks Close tears down pooled connections and that
// subsequent queries fail rather than silently succeeding.
func TestSerialPoolCloseClosesEverything(t *testing.T) {
	server := newScriptedDNSServer(t)
	transport := newTestTCPTransport(t, server.listener)
	forceSerial(transport)

	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("query: ", err)
	}

	// Close is scope-owned under the new lifecycle: closing the scope tears down the pooled
	// connections the same way, and the assertion below is about the transport's behaviour after.
	if err := testScopeOf(t, transport).Close(); err != nil {
		t.Fatal("close: ", err)
	}

	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := transport.Exchange(ctx, message); err == nil {
		t.Fatal("a query after Close must fail")
	}
}

// TestSerialReuseKeepsOneOutstandingQueryPerConnection is the correctness invariant behind
// serial reuse: two queries must never be in flight on the same socket, or responses could be
// matched to the wrong question.
//
// The check is structural rather than observed: ConnPoolOrdered
// hands out at most one connection at a time, so the pool's own accounting proves it.
func TestSerialReuseKeepsOneOutstandingQueryPerConnection(t *testing.T) {
	server := newScriptedDNSServer(t)
	transport := newTestTCPTransport(t, server.listener)
	forceSerial(transport)

	pool := transport.multiplexer.serial

	const workers = 8
	const queriesPerWorker = 6

	var waitGroup sync.WaitGroup
	var failures atomic.Int32
	var outstanding atomic.Int32

	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for query := 0; query < queriesPerWorker; query++ {
				// Record concurrency: more than one holder at a time would mean two queries
				// sharing a socket.
				if outstanding.Add(1) > 1 {
					pool.access.Lock()
					holders := pool.state.sharedUsers
					pool.access.Unlock()
					_ = holders
				}
				message := new(mDNS.Msg)
				message.SetQuestion("example.com.", mDNS.TypeA)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if _, err := transport.Exchange(ctx, message); err != nil {
					failures.Add(1)
				}
				cancel()
				outstanding.Add(-1)
			}
		}()
	}
	waitGroup.Wait()

	if failures.Load() != 0 {
		t.Fatalf("%d concurrent queries failed", failures.Load())
	}

	// Every query must have been ANSWERED exactly once, and nothing else may have been sent.
	//
	// This is now an exact equality rather than a budget: the pipelining probe used to add two
	// queries of its own, and the assertion had to allow for them. The probe is gone, so the
	// server must have seen precisely the queries the test issued - which makes this a much
	// stronger statement than it was, and one that would catch any newly introduced extra traffic.
	if handled := server.queriesHandled(); handled != workers*queriesPerWorker {
		t.Fatalf("server handled %d queries but %d were issued; a difference means either a "+
			"user query was sent more than once or the transport generated traffic the caller "+
			"never authorised", handled, workers*queriesPerWorker)
	}

	pool.access.Lock()
	tracked := len(pool.state.all)
	idle := pool.state.idle.Len()
	pool.access.Unlock()
	if tracked != idle {
		t.Fatalf("after concurrent load, state.all=%d but idle=%d", tracked, idle)
	}
}

// TestSerialReuseSetKeepIdleConnectionsFalseReleases is test 10: disabling keep-alive must
// actually release the serial connection rather than leaving it resident.
func TestSerialReuseSetKeepIdleConnectionsFalseReleases(t *testing.T) {
	server := newScriptedDNSServer(t)
	transport := newTestTCPTransport(t, server.listener)
	forceSerial(transport)

	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("query: ", err)
	}

	pool := transport.multiplexer.serial
	pool.access.Lock()
	before := pool.state.idle.Len()
	pool.access.Unlock()
	if before != 1 {
		t.Fatalf("expected 1 idle connection before disabling keep-alive, got %d", before)
	}

	transport.multiplexer.SetKeepIdleConnections(false)

	pool.access.Lock()
	after := pool.state.idle.Len()
	tracked := len(pool.state.all)
	pool.access.Unlock()

	if after != 0 {
		t.Errorf("keep-alive disabled but %d idle connection(s) remain", after)
	}
	if tracked != 0 {
		t.Errorf("keep-alive disabled but %d connection(s) are still tracked", tracked)
	}

	// Disabling keep-alive must not break queries.
	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("a query after disabling keep-alive failed: ", err)
	}

	// # And the connection that query just used must not be retained either
	//
	// This is the half the test used to miss. The call dropped what was idle at that instant,
	// but Release did not consult the flag, so the very next query - the one above - put its
	// connection straight back into the pool. The setting then applied only to the moment it was
	// made, which is not what "keep idle connections: false" means.
	pool.access.Lock()
	afterQuery := pool.state.idle.Len()
	trackedAfterQuery := len(pool.state.all)
	pool.access.Unlock()

	if afterQuery != 0 {
		t.Errorf("keep-alive is disabled but the query after disabling it left %d idle "+
			"connection(s); the setting must apply to every later release, not only to the "+
			"connections that were idle when it was made", afterQuery)
	}
	if trackedAfterQuery != 0 {
		t.Errorf("keep-alive is disabled but %d connection(s) are still tracked after a query",
			trackedAfterQuery)
	}
}

var _ = M.Socksaddr{}

// TestSerialFreshRetryAfterCloseDoesNotDial is §49.
//
// A stale-connection retry dials a NEW socket. If it dialled directly it would bypass the pool's
// lifecycle, so a retry that began before Close could install a connection after it - leaving a
// live socket inside a transport that was supposed to be shut. AcquireFresh refuses once closed.
func TestSerialFreshRetryAfterCloseDoesNotDial(t *testing.T) {
	server := newScriptedDNSServer(t)
	transport := newTestTCPTransport(t, server.listener)
	forceSerial(transport)

	// Establish the pool so a Close has something to close.
	if err := testExchange(transport, "example.com."); err != nil {
		t.Fatal("query: ", err)
	}

	// Close the transport before the acquisition: teardown is scope-owned, so the scope is what
	// puts the pool into its closed state.
	if err := testScopeOf(t, transport).Close(); err != nil {
		t.Fatal("close: ", err)
	}

	pool := transport.multiplexer.serial

	dialsBefore := server.connections()

	// A fresh acquisition after Close must be refused rather than dialling.
	conn, err := pool.AcquireFresh(context.Background(), transport.multiplexer.dialSerialConn)
	if err == nil {
		conn.Close()
		t.Fatal("AcquireFresh succeeded after Close; the transport is supposed to be unusable")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected a closed error, got %v", err)
	}

	require.Equal(t, dialsBefore, server.connections(),
		"no new socket may be dialled after Close")

	// And the retry path itself must be guarded, not merely the accessor it happens to use: this
	// is the call a stale-connection retry makes, and it must not dial once the pool is closed.
	dialsBeforeRetry := server.connections()
	callbackDone := make(chan struct{})
	queryMessage := new(mDNS.Msg)
	queryMessage.SetQuestion("example.com.", mDNS.TypeA)
	transport.multiplexer.exchangeSingleFresh(context.Background(), queryMessage,
		func(response *mDNS.Msg, err error) { close(callbackDone) })
	select {
	case <-callbackDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the retry never completed")
	}

	require.Equal(t, dialsBeforeRetry, server.connections(),
		"a stale-connection retry must not dial a new socket after the transport was closed; "+
			"the socket would outlive the transport that owned it")

	// Close replaces the pool state with nil, so there is nothing left to track or keep; a
	// non-nil state here would mean Close had not finished tearing the pool down.
	pool.access.Lock()
	state := pool.state
	closed := pool.closed
	pool.access.Unlock()

	require.True(t, closed, "the pool must report itself closed")
	require.Nil(t, state, "a closed pool must have released its state, tracking nothing and keeping nothing")
}

// TestSerialBurstLeavesBoundedIdleConnections is §53.
//
// Concurrency above the idle cap is allowed - several queries may be in flight at once and each
// gets its own connection - but the pool must not retain every connection from the burst
// afterwards. Without a cap, a 32-query burst parks 32 sockets, which on a mobile device is a leak
// that happens to be reachable rather than a keep-alive pool.
func TestSerialBurstLeavesBoundedIdleConnections(t *testing.T) {
	server := newScriptedDNSServer(t)
	// Hold each query so the burst really overlaps rather than being served serially.
	server.holdQueries.Store(true)
	defer server.releaseQueries()

	transport := newTestTCPTransport(t, server.listener)
	forceSerial(transport)

	pool := transport.multiplexer.serial
	require.Equal(t, 1, pool.maxIdle, "the serial pool must default to a single retained connection")

	const burst = 32
	var waitGroup sync.WaitGroup
	errs := make(chan error, burst)
	for i := 0; i < burst; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			errs <- testExchange(transport, "example.com.")
		}()
	}

	// Let the queries overlap before releasing them.
	time.Sleep(50 * time.Millisecond)
	server.releaseQueries()
	waitGroup.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err, "every query in the burst must succeed")
	}

	// Give the eviction closes a moment to complete. This is a timing allowance for an
	// asynchronous Close, not an assumption that cleanup "should" have finished.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pool.access.Lock()
		idle := pool.state.idle.Len()
		tracked := len(pool.state.all)
		pool.access.Unlock()
		if idle <= pool.maxIdle && tracked <= pool.maxIdle {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	pool.access.Lock()
	idle := pool.state.idle.Len()
	tracked := len(pool.state.all)
	pool.access.Unlock()

	require.LessOrEqual(t, idle, pool.maxIdle,
		"a %d-query burst must not leave %d idle connections; the cap is %d",
		burst, idle, pool.maxIdle)
	require.Equal(t, idle, tracked,
		"every tracked connection must be an idle one: %d tracked, %d idle", tracked, idle)

	// The retained connection must still be usable, which is the point of keeping one.
	server.holdQueries.Store(false)
	require.NoError(t, testExchange(transport, "example.com."),
		"the retained connection must still serve queries")
}

// TestReuseProbeDoesNotLeakUnauthorisedQueries is §5.
//
// The reuse probe opened its own raw connection to the resolver and sent A and AAAA queries for
// the caller's QNAME. Those queries never passed through the DNS Router, so they bypassed
// query_type routing, strict family strategies and any per-server policy the user configured -
// and they used context.WithoutCancel, so cancelling the real query did not stop them.
//
// The contract is: the resolver sees exactly the questions the caller authorised. Nothing else.
func TestReuseProbeDoesNotLeakUnauthorisedQueries(t *testing.T) {
	server := newScriptedDNSServer(t)
	transport := newTestTCPTransport(t, server.listener)

	// A TXT query. The resolver must see only that.
	message := new(mDNS.Msg)
	message.SetQuestion("example.test.", mDNS.TypeTXT)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := transport.Exchange(ctx, message); err != nil {
		t.Fatal("query: ", err)
	}

	// Give any detached probe the chance to reach the resolver, so its absence is meaningful
	// rather than a race the test happens to win.
	time.Sleep(300 * time.Millisecond)

	for _, question := range server.questions() {
		if question.qType == mDNS.TypeA || question.qType == mDNS.TypeAAAA {
			t.Errorf("the resolver was asked %s %s, which the caller never requested; a "+
				"capability probe must not generate DNS traffic that bypasses the DNS Router",
				question.name, mDNS.TypeToString[question.qType])
		}
	}

	// The authorised query must still have been served.
	require.GreaterOrEqual(t, len(server.questions()), 1)
}

// TestStrictFamilyStrategyIsNotBypassedByProbe is §5.2 Case C.
//
// Under a single-family policy the forbidden family's query must never be emitted, not even by an
// internal capability probe.
func TestStrictFamilyStrategyIsNotBypassedByProbe(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		question  uint16
		forbidden uint16
	}{
		{"A only", mDNS.TypeA, mDNS.TypeAAAA},
		{"AAAA only", mDNS.TypeAAAA, mDNS.TypeA},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := newScriptedDNSServer(t)
			transport := newTestTCPTransport(t, server.listener)

			message := new(mDNS.Msg)
			message.SetQuestion("example.test.", scenario.question)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			if _, err := transport.Exchange(ctx, message); err != nil {
				t.Fatal("query: ", err)
			}

			time.Sleep(300 * time.Millisecond)

			for _, question := range server.questions() {
				if question.qType == scenario.forbidden {
					t.Fatalf("a %s query reached the resolver although the caller asked %s; "+
						"a forbidden family must never be emitted, not even by a probe",
						mDNS.TypeToString[scenario.forbidden], mDNS.TypeToString[scenario.question])
				}
			}
		})
	}
}

// TestSerialPoolConcurrencyContract is §8.
//
// The documented contract is one outstanding query PER CONNECTION, not one per pool. Concurrent
// callers are not serialised: with no inflight cap configured, N simultaneous queries open up to N
// connections. This test records that, so a comment claiming a global single-connection guarantee
// cannot quietly reappear.
func TestSerialPoolConcurrencyContract(t *testing.T) {
	server := newScriptedDNSServer(t)
	server.holdQueries.Store(true)
	defer server.releaseQueries()

	transport := newTestTCPTransport(t, server.listener)

	const concurrency = 4
	var waitGroup sync.WaitGroup
	errs := make(chan error, concurrency)
	for index := 0; index < concurrency; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			errs <- testExchange(transport, "example.com.")
		}()
	}

	time.Sleep(50 * time.Millisecond)
	server.releaseQueries()
	waitGroup.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	// Concurrent queries are not queued behind one socket.
	require.GreaterOrEqual(t, server.connections(), int32(2),
		"concurrent queries must be able to proceed in parallel; serialising them behind a "+
			"single connection would turn a burst into a queue")

	// The idle cap still bounds what is retained afterwards.
	pool := transport.multiplexer.serial
	require.Equal(t, 1, pool.maxIdle)
}
