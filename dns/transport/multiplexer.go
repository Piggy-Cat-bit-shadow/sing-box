package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	mDNS "github.com/miekg/dns"
)

const (
	reuseStateUnknown int32 = iota
	reuseStateProbing
	reuseStateSupported
	reuseStateUnsupported
)

const (
	reuseProbeTimeout       = 5 * time.Second
	reuseProbeRetryInterval = time.Minute
	reuseDemoteFailureLimit = 3

	reuseProbeQueryIdA uint16 = 1
	reuseProbeQueryIdB uint16 = 2
)

type queryMultiplexerOptions struct {
	dial           func(ctx context.Context) (net.Conn, error)
	write          func(conn net.Conn, message *mDNS.Msg, queryId uint16) error
	readNext       func(conn net.Conn) (*mDNS.Msg, error)
	retryReadError bool
	probeReuse     bool
}

type queryMultiplexer struct {
	options    queryMultiplexerOptions
	connection *ConnPool[*multiplexConn]
	// serial is the reuse pool for servers that do NOT support concurrent outstanding
	// queries. See dispatch: "unsupported" means "no pipelining", not "no reuse", and
	// dialing per query was paying a TCP handshake for a server that is happy to answer
	// sequentially on one connection.
	//
	// ConnPoolOrdered gives exactly the required shape: one holder at a time, an idle
	// list, and stale-connection eviction through IsAlive.
	serial *ConnPool[*multiplexConn]

	queryAccess sync.Mutex
	queryId     uint16
	queries     map[uint16]*pendingQuery

	reuseState     atomic.Int32
	demoteFailures atomic.Int32
	keepIdle       atomic.Bool

	probeAccess   sync.Mutex
	probeEpoch    uint32
	lastProbeTime time.Time
}

type multiplexConn struct {
	net.Conn
	readEpoch atomic.Uint64
}

type queryMultiplexerReadError struct {
	cause error
}

func (e *queryMultiplexerReadError) Error() string {
	return e.cause.Error()
}

func (e *queryMultiplexerReadError) Unwrap() error {
	return e.cause
}

type pendingQuery struct {
	conn        *multiplexConn
	message     *mDNS.Msg
	readEpoch   uint64
	callback    func(response *mDNS.Msg, err error)
	stopContext func() bool
	stopConn    func() bool
	retryCtx    context.Context
}

func newQueryMultiplexer(options queryMultiplexerOptions) *queryMultiplexer {
	multiplexer := &queryMultiplexer{
		options: options,
		queries: make(map[uint16]*pendingQuery),
		connection: NewConnPool(ConnPoolOptions[*multiplexConn]{
			Mode: ConnPoolSingle,
			IsAlive: func(conn *multiplexConn) bool {
				return conn != nil
			},
			Close: func(conn *multiplexConn, cause error) {
				conn.Close()
			},
		}),
	}
	multiplexer.serial = NewConnPool(ConnPoolOptions[*multiplexConn]{
		Mode: ConnPoolOrdered,
		IsAlive: func(conn *multiplexConn) bool {
			// Only a nil connection is rejected here.
			//
			// This deliberately does NOT consult readEpoch. That counter is incremented by
			// recvLoop, which only the shared/connection-oriented path runs; the serial path
			// reads inline and never starts one, so readEpoch stays zero for the entire life
			// of a serial connection and a readEpoch check would report every connection as
			// healthy forever. An earlier comment claimed it detected a dead serial socket,
			// which it cannot - it was measuring something the serial path never updates.
			//
			// Detecting a stale serial connection is done where it can actually be observed:
			// the next read or write fails, the connection is invalidated, and the query is
			// retried once on a genuinely fresh socket. That needs no syscall, no polling and
			// no background goroutine, so it costs nothing on a healthy connection and does
			// not burn power probing.
			return conn != nil
		},
		Close: func(conn *multiplexConn, cause error) {
			if conn != nil {
				conn.Close()
			}
		},
	})
	multiplexer.keepIdle.Store(true)
	return multiplexer
}

func (m *queryMultiplexer) SetKeepIdleConnections(keep bool) {
	m.keepIdle.Store(keep)
	m.closeIdleConnection()
}

func (m *queryMultiplexer) CloseIdleConnections() {
	m.connection.CloseIdle()
	// The serial pool holds its own idle connection. Leaving it out here would keep a TCP
	// socket open to the resolver after the caller asked for idle connections to be
	// dropped - which is the whole point of this call on a mobile device.
	m.serial.CloseIdle()
}

func (m *queryMultiplexer) closeIdleConnection() {
	if !m.keepIdle.Load() {
		m.connection.CloseIdle()
		// Same reasoning as CloseIdleConnections: with keep-idle disabled, no pooled
		// connection may outlive the query that created it.
		m.serial.CloseIdle()
	}
}

func (m *queryMultiplexer) Close() error {
	// Both pools must be closed. Missing the serial pool would leave a connection open
	// and, worse, let a query after Close still succeed by dialing through it - Close is
	// supposed to make this transport unusable.
	err := m.connection.Close()
	if serialErr := m.serial.Close(); err == nil {
		err = serialErr
	}
	return err
}

func (m *queryMultiplexer) Reset() {
	if m.options.probeReuse {
		m.probeAccess.Lock()
		m.probeEpoch++
		m.reuseState.Store(reuseStateUnknown)
		m.lastProbeTime = time.Time{}
		m.probeAccess.Unlock()
		m.demoteFailures.Store(0)
	}
	m.connection.Reset()
	// A Reset drops cached connections so the next query re-dials - used when the network
	// has changed. The serial pool must follow, or a query after Reset would keep using a
	// connection established on the old path.
	m.serial.Reset()
}

func (m *queryMultiplexer) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	done := make(chan struct{})
	var (
		response *mDNS.Msg
		err      error
	)
	m.ExchangeAsync(ctx, message, func(callbackResponse *mDNS.Msg, callbackErr error) {
		response = callbackResponse
		err = callbackErr
		close(done)
	})
	<-done
	return response, err
}

func (m *queryMultiplexer) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	m.dispatch(ctx, message, callback, true)
}

func (m *queryMultiplexer) dispatch(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error), retryReadError bool) {
	if m.options.probeReuse && m.reuseState.Load() != reuseStateSupported {
		m.maybeStartProbe(ctx, message)
		go m.exchangeSingle(ctx, message, callback)
		return
	}
	m.exchangeAsync(ctx, message, callback, retryReadError)
}

// exchangeSingle answers one query on a connection that is NOT used concurrently.
//
// # What changed, and why it matters
//
// "The server cannot pipeline" was being treated as "the connection cannot be reused",
// so every query paid a full TCP handshake and teardown. Plenty of resolvers refuse
// concurrent outstanding queries but are perfectly happy to answer sequentially on a
// kept-alive connection - which is the overwhelmingly common case and costs one dial
// rather than one per query.
//
// The connection now comes from the serial pool, and is returned for reuse only when it
// is still healthy. The one-outstanding-query invariant is enforced structurally rather
// than by convention: ConnPoolOrdered holds at most one connection out at a time, so
// two callers cannot both be mid-query on the same socket.
func (m *queryMultiplexer) exchangeSingle(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	conn, created, err := m.serial.Acquire(ctx, m.dialSerialConn)
	if err != nil {
		callback(nil, err)
		return
	}

	// THE POOL OWNS THIS CONNECTION. Every path out of this function must end in exactly one
	// hand-back to the pool - Release(conn, true) for a healthy connection, or an invalidation
	// for one that must not be reused. Calling conn.Close() directly and dropping the local
	// reference, which an earlier version did, leaves the socket dead while the pool still
	// tracks it in state.all: repeated server-side idle closes then accumulate dead objects.
	//
	// settled makes that "exactly one" structural rather than a property of every return path.
	settled := false
	releaseReusable := func() {
		if settled {
			return
		}
		settled = true
		m.serial.Release(conn, true)
	}
	invalidate := func(cause error) {
		if settled {
			return
		}
		settled = true
		m.serial.Invalidate(conn, cause)
	}
	defer func() {
		// Any path that did not explicitly settle leaves the stream in an unknown position,
		// so the connection is invalidated rather than reused.
		invalidate(net.ErrClosed)
	}()

	// Closing on context cancellation is what makes a timeout interrupt a read or write that
	// is already in flight.
	//
	// The callback captures a COPY of the connection pointer. It must not capture a variable
	// the main goroutine can reassign: an earlier version closed over `conn` and then set
	// `conn = nil` on the success path, which is a data race between the cancellation
	// goroutine reading it and this goroutine writing it - and worse, a cancellation landing
	// in that window would close a connection that had just been returned to the idle pool.
	//
	// The callback's ONLY job is to interrupt I/O. Pool bookkeeping stays with this goroutine.
	interruptConn := conn
	stopCancel := context.AfterFunc(ctx, func() {
		interruptConn.Close()
	})

	err = m.options.write(conn, message, message.Id)
	if err != nil {
		interruptStopped := stopCancel()
		if ctxErr := ctx.Err(); ctxErr != nil {
			invalidate(ctxErr)
			callback(nil, ctxErr)
			return
		}
		// A write failure on a REUSED connection is the other half of stale keep-alive
		// handling. A server that closed an idle socket commonly surfaces as EPIPE or
		// ECONNRESET on the NEXT write rather than as a read error, and the earlier
		// implementation only retried the read case - so the write case returned a spurious
		// error to the caller for a connection that was merely stale.
		if !created && interruptStopped {
			invalidate(err)
			m.retrySerialOnce(ctx, message, callback)
			return
		}
		invalidate(err)
		callback(nil, E.Cause(err, "write request"))
		return
	}

	for {
		response, readErr := m.options.readNext(conn)
		if readErr != nil {
			interruptStopped := stopCancel()
			if ctxErr := ctx.Err(); ctxErr != nil {
				invalidate(ctxErr)
				callback(nil, ctxErr)
				return
			}
			if !created && interruptStopped {
				// The server closed an idle connection between queries. That is normal
				// keep-alive behaviour, so retry once on a fresh connection.
				invalidate(readErr)
				m.retrySerialOnce(ctx, message, callback)
				return
			}
			invalidate(readErr)
			callback(nil, E.Cause(readErr, "read response"))
			return
		}
		if response == nil {
			continue
		}

		// The response is complete. Before allowing reuse, cancel the interrupt hook AND
		// confirm it had not already started closing the connection.
		//
		// Checking ctx.Err() alone is not enough: cancellation can arrive at the same instant
		// as the response, and a cancellation callback that has already begun Close() must not
		// have its connection handed to the next query. stopCancel reports whether the
		// callback was prevented from running at all, which is the only condition under which
		// the socket is provably untouched.
		interruptStopped := stopCancel()
		if !interruptStopped {
			invalidate(context.Canceled)
			if ctxErr := ctx.Err(); ctxErr != nil {
				callback(nil, ctxErr)
				return
			}
			callback(nil, E.New("response received but the connection was interrupted"))
			return
		}

		response.Id = message.Id
		releaseReusable()
		callback(response, nil)
		return
	}
}

// retrySerialOnce re-runs a query exactly once, on a connection that is guaranteed FRESH.
//
// # Why the retry must not simply re-enter the pool
//
// A stale idle connection is not the only one in the pool: the server may have closed several.
// Invalidating the failed connection and calling Acquire again could hand back ANOTHER stale
// idle connection, which fails the same way, and the retry would repeat - an unbounded loop
// dressed up as a bounded one, with a dial or two per iteration.
//
// Clearing the pool's idle connections before re-acquiring is what makes "fresh" true rather
// than hopeful. The failed connection is already invalidated by the caller, so this removes any
// OTHER idle connection that might be stale too.
//
// # Boundedness
//
// The retry runs with a flag that forces a NEW connection regardless of what the pool holds.
// Combined with the once-only call sites, a query performs at most one retry, and that retry
// cannot itself be retried: a failure on a fresh connection is a real error and is reported.
func (m *queryMultiplexer) retrySerialOnce(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	if ctx.Err() != nil {
		callback(nil, ctx.Err())
		return
	}

	// Drop every remaining idle serial connection. A server that closed one idle socket has
	// very likely closed the others, and re-acquiring a different stale one would defeat the
	// point of retrying.
	m.serial.CloseIdle()

	go m.exchangeSingleFresh(ctx, message, callback)
}

// exchangeSingleFresh is exchangeSingle with a forced new connection.
//
// It reports created=true semantics for the retry: the connection cannot have come from the
// idle pool, because the pool's idle list was cleared and the acquire below dials directly.
func (m *queryMultiplexer) exchangeSingleFresh(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	conn, err := m.dialSerialConn(ctx)
	if err != nil {
		callback(nil, err)
		return
	}
	m.exchangeOnFreshConn(ctx, message, conn, callback)
}

// exchangeOnFreshConn runs one query on a connection this function owns outright.
//
// The connection is never handed to the pool, so there is no reuse decision to get wrong: it
// is closed exactly once, on every path.
func (m *queryMultiplexer) exchangeOnFreshConn(ctx context.Context, message *mDNS.Msg, conn *multiplexConn, callback func(response *mDNS.Msg, err error)) {
	defer conn.Close()

	interruptConn := conn
	stopCancel := context.AfterFunc(ctx, func() {
		interruptConn.Close()
	})
	defer stopCancel()

	if err := m.options.write(conn, message, message.Id); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			callback(nil, ctxErr)
			return
		}
		// A failure on a genuinely fresh connection is a real error. It is reported, not
		// retried: retrying here is exactly the unbounded loop this path exists to avoid.
		callback(nil, E.Cause(err, "write request"))
		return
	}

	for {
		response, err := m.options.readNext(conn)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				callback(nil, ctxErr)
				return
			}
			callback(nil, E.Cause(err, "read response"))
			return
		}
		if response == nil {
			continue
		}
		response.Id = message.Id
		callback(response, nil)
		return
	}
}

// dialSerialConn dials for the serial pool, wrapping the transport's own dialer so the
// pool caches multiplexConn values like the shared path does.
func (m *queryMultiplexer) dialSerialConn(ctx context.Context) (*multiplexConn, error) {
	conn, err := m.options.dial(ctx)
	if err != nil {
		return nil, err
	}
	return &multiplexConn{Conn: conn}, nil
}

func (m *queryMultiplexer) maybeStartProbe(ctx context.Context, message *mDNS.Msg) {
	if len(message.Question) == 0 {
		return
	}
	m.probeAccess.Lock()
	if m.reuseState.Load() == reuseStateProbing {
		m.probeAccess.Unlock()
		return
	}
	if !m.lastProbeTime.IsZero() && time.Since(m.lastProbeTime) < reuseProbeRetryInterval {
		m.probeAccess.Unlock()
		return
	}
	m.reuseState.Store(reuseStateProbing)
	m.lastProbeTime = time.Now()
	epoch := m.probeEpoch
	m.probeAccess.Unlock()
	go m.runReuseProbe(context.WithoutCancel(ctx), message.Question[0].Name, epoch)
}

func (m *queryMultiplexer) runReuseProbe(ctx context.Context, questionName string, epoch uint32) {
	supported, dialFailed := m.executeReuseProbe(ctx, questionName)
	m.probeAccess.Lock()
	defer m.probeAccess.Unlock()
	if m.probeEpoch != epoch {
		return
	}
	switch {
	case supported:
		m.reuseState.Store(reuseStateSupported)
		m.demoteFailures.Store(0)
	case dialFailed:
		m.reuseState.Store(reuseStateUnknown)
	default:
		m.reuseState.Store(reuseStateUnsupported)
	}
}

func (m *queryMultiplexer) executeReuseProbe(ctx context.Context, questionName string) (supported bool, dialFailed bool) {
	probeCtx, cancel := context.WithTimeout(ctx, reuseProbeTimeout)
	defer cancel()
	conn, err := m.options.dial(probeCtx)
	if err != nil {
		return false, true
	}
	defer conn.Close()
	stop := context.AfterFunc(probeCtx, func() {
		conn.Close()
	})
	defer stop()
	queryA := new(mDNS.Msg)
	queryA.SetQuestion(questionName, mDNS.TypeA)
	queryAAAA := new(mDNS.Msg)
	queryAAAA.SetQuestion(questionName, mDNS.TypeAAAA)
	err = m.options.write(conn, queryA, reuseProbeQueryIdA)
	if err == nil {
		err = m.options.write(conn, queryAAAA, reuseProbeQueryIdB)
	}
	if err != nil {
		return false, false
	}
	var seenA, seenAAAA bool
	for !seenA || !seenAAAA {
		var response *mDNS.Msg
		response, err = m.options.readNext(conn)
		if err != nil {
			return false, false
		}
		if response == nil {
			continue
		}
		switch response.Id {
		case reuseProbeQueryIdA:
			seenA = true
		case reuseProbeQueryIdB:
			seenAAAA = true
		}
	}
	return true, false
}

func (m *queryMultiplexer) recordConnDeath(conn *multiplexConn) {
	if !m.options.probeReuse || m.reuseState.Load() != reuseStateSupported {
		return
	}
	if conn.readEpoch.Load() == 0 {
		return
	}
	m.queryAccess.Lock()
	var pendingOnConn int
	for _, pending := range m.queries {
		if pending.conn == conn {
			pendingOnConn++
		}
	}
	m.queryAccess.Unlock()
	if pendingOnConn == 0 {
		m.demoteFailures.Store(0)
		return
	}
	if m.demoteFailures.Add(1) < reuseDemoteFailureLimit {
		return
	}
	m.probeAccess.Lock()
	if m.reuseState.Load() == reuseStateSupported {
		m.reuseState.Store(reuseStateUnsupported)
		m.lastProbeTime = time.Now()
	}
	m.probeAccess.Unlock()
	m.demoteFailures.Store(0)
}

func (m *queryMultiplexer) exchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error), retryReadError bool) {
	for firstAttempt := true; ; firstAttempt = false {
		conn, connCtx, created, err := m.connection.AcquireShared(ctx, m.dialConn)
		if err != nil {
			callback(nil, err)
			return
		}
		if created {
			go m.recvLoop(conn)
		}
		queryId, err := m.register(ctx, connCtx, conn, message, callback, retryReadError && m.options.retryReadError && !created)
		if err != nil {
			m.connection.Release(conn, true)
			m.closeIdleConnection()
			callback(nil, err)
			return
		}
		writeErr := m.options.write(conn, message, queryId)
		if writeErr == nil {
			return
		}
		pending := m.take(queryId)
		m.connection.Invalidate(conn, writeErr)
		if pending == nil {
			return
		}
		if !created && firstAttempt {
			continue
		}
		callback(nil, E.Cause(writeErr, "write request"))
		return
	}
}

func (m *queryMultiplexer) dialConn(ctx context.Context) (*multiplexConn, error) {
	conn, err := m.options.dial(ctx)
	if err != nil {
		return nil, err
	}
	return &multiplexConn{Conn: conn}, nil
}

func (m *queryMultiplexer) register(ctx context.Context, connCtx context.Context, conn *multiplexConn, message *mDNS.Msg, callback func(response *mDNS.Msg, err error), retryReadError bool) (uint16, error) {
	m.queryAccess.Lock()
	defer m.queryAccess.Unlock()
	start := m.queryId
	for {
		m.queryId++
		if _, exists := m.queries[m.queryId]; !exists {
			break
		}
		if m.queryId == start {
			return 0, E.New("no available query ID")
		}
	}
	queryId := m.queryId
	pending := &pendingQuery{
		conn:      conn,
		message:   message,
		readEpoch: conn.readEpoch.Load(),
		callback:  callback,
	}
	if retryReadError {
		pending.retryCtx = ctx
	}
	m.queries[queryId] = pending
	pending.stopContext = context.AfterFunc(ctx, func() {
		m.completeContextDone(queryId, ctx)
	})
	pending.stopConn = context.AfterFunc(connCtx, func() {
		m.completeConnDone(queryId, connCtx)
	})
	return queryId, nil
}

func (m *queryMultiplexer) completeConnDone(queryId uint16, connCtx context.Context) {
	pending := m.take(queryId)
	if pending == nil {
		return
	}
	connErr := context.Cause(connCtx)
	_, readFailed := connErr.(*queryMultiplexerReadError)
	if pending.retryCtx != nil && readFailed {
		m.dispatch(pending.retryCtx, pending.message, pending.callback, false)
		return
	}
	pending.callback(nil, connErr)
}

func (m *queryMultiplexer) take(queryId uint16) *pendingQuery {
	m.queryAccess.Lock()
	pending, loaded := m.queries[queryId]
	if !loaded {
		m.queryAccess.Unlock()
		return nil
	}
	delete(m.queries, queryId)
	m.queryAccess.Unlock()
	pending.stopContext()
	pending.stopConn()
	return pending
}

func (m *queryMultiplexer) complete(queryId uint16, response *mDNS.Msg, err error, releaseConn bool) {
	pending := m.take(queryId)
	if pending == nil {
		return
	}
	if releaseConn {
		m.connection.Release(pending.conn, true)
	}
	if response != nil {
		response.Id = pending.message.Id
	}
	pending.callback(response, err)
	m.closeIdleConnection()
}

func (m *queryMultiplexer) completeContextDone(queryId uint16, ctx context.Context) {
	pending := m.take(queryId)
	if pending == nil {
		return
	}
	err := ctx.Err()
	if errors.Is(err, context.DeadlineExceeded) && pending.conn.readEpoch.Load() == pending.readEpoch {
		m.connection.Invalidate(pending.conn, err)
	} else {
		m.connection.Release(pending.conn, true)
	}
	pending.callback(nil, err)
	m.closeIdleConnection()
}

func (m *queryMultiplexer) recvLoop(conn *multiplexConn) {
	for {
		message, err := m.options.readNext(conn)
		if err != nil {
			m.recordConnDeath(conn)
			m.connection.Invalidate(conn, &queryMultiplexerReadError{cause: err})
			return
		}
		conn.readEpoch.Add(1)
		if message == nil {
			continue
		}
		m.complete(message.Id, message, nil, true)
	}
}
