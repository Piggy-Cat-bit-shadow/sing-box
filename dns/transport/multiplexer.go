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
			// A connection whose read loop saw death is not reusable, and neither is a
			// nil one. The readEpoch check mirrors the shared path: a non-zero epoch on a
			// connection that is being handed back means it already died once.
			return conn != nil && conn.readEpoch.Load() == 0
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

	// reusable records whether the connection may go back to the idle pool. Any failure
	// after the request is written leaves the stream in an unknown position, so it must
	// be discarded rather than reused - a stale response would otherwise be delivered to
	// the next query.
	reusable := false
	closeConn := func() {
		if conn != nil {
			conn.Close()
			conn = nil
		}
	}
	defer func() {
		if conn != nil {
			m.serial.Release(conn, reusable)
		}
	}()

	// Closing on context cancellation is what makes a timeout actually interrupt a read
	// that is already in flight. It also means the connection must NOT be reused
	// afterwards: the close happened underneath the caller.
	stop := context.AfterFunc(ctx, func() {
		if conn != nil {
			conn.Close()
		}
	})
	defer stop()

	err = m.options.write(conn, message, message.Id)
	if err != nil {
		ctxErr := ctx.Err()
		closeConn()
		if ctxErr != nil {
			callback(nil, ctxErr)
			return
		}
		callback(nil, E.Cause(err, "write request"))
		return
	}
	for {
		var response *mDNS.Msg
		response, err = m.options.readNext(conn)
		if err != nil {
			ctxErr := ctx.Err()
			closeConn()
			if ctxErr != nil {
				callback(nil, ctxErr)
				return
			}
			// A read failure on a REUSED connection usually means the server closed an
			// idle connection between queries, which is normal and must not surface as an
			// error to the caller. Retry once on a fresh connection.
			if !created {
				// Retry once, on a fresh connection, and report whatever that returns.
				// Bounded at one attempt: a server that closes every connection would
				// otherwise be retried forever.
				m.retrySerialOnce(ctx, message, callback)
				return
			}
			callback(nil, E.Cause(err, "read response"))
			return
		}
		if response == nil {
			continue
		}
		response.Id = message.Id
		// Completed cleanly: the stream is exactly at a message boundary, so the
		// connection is safe to hand to the next query.
		reusable = true
		callback(response, nil)
		return
	}
}

// retrySerialOnce re-runs a query exactly once after a REUSED connection failed.
//
// A read failure on a reused connection usually means the server closed an idle
// connection between queries. That is normal keep-alive behaviour and must not surface
// as an error, so the query is retried on a fresh connection. The retry is deliberately
// bounded at one attempt - the retried call comes back through exchangeSingle with
// created=true, and a failure there is reported rather than retried again.
func (m *queryMultiplexer) retrySerialOnce(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	if ctx.Err() != nil {
		callback(nil, ctx.Err())
		return
	}
	go m.exchangeSingle(ctx, message, callback)
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
