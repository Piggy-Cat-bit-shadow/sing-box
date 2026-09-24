//go:build with_quic

package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

func init() {
	NewHTTP3Client = newHTTP3Client
}

// http3PoolSlot owns one complete, independent HTTP/3 stack: its own UDP socket,
// its own QUIC connection and its own http3.ClientConn. Slots share nothing, so
// two slots are two QUIC connections rather than two streams on one.
// http3PoolSlot is defined in client_h3_slot.go together with its state
// machine and health accounting.

// http3ClientImpl is the MASQUE tunnel client.
//
// The pool exists because every CONNECT and CONNECT-UDP tunnel previously shared
// one QUIC connection, putting them all under a single congestion controller. A
// pool of N gives N independent congestion controllers on the wire.
//
// A NEW tunnel picks a slot once, round-robin, and stays on it for its lifetime.
// A tunnel is never migrated to another slot and its payload is never replayed,
// which is the property that matters for CONNECT: a half-written tunnel body
// cannot be rewound, so "do not replay" is about one tunnel, not about pinning
// every tunnel to slot 0.
type http3ClientImpl struct {
	dialer        N.Dialer
	tlsConfig     aTLS.Config
	server        M.Socksaddr
	authority     string
	headers       http.Header
	authorization string
	// baseQUICConfig is cloned per slot, because sing-quic mutates the config it
	// is handed.
	baseQUICConfig *quic.Config

	// logger may be nil; logf guards for that so a client built without one does
	// not panic on a debug path.
	logger logger.ContextLogger
	// onSuccess clears the authority-level HTTP/3 backoff after a confirmed
	// success. See ClientOptions.OnHTTP3Success.
	onSuccess func()

	// slots holds the pool. Its length never exceeds maxSlots: a pool that grew
	// on every failure would turn a flapping server into unbounded UDP sockets.
	slots    []*http3PoolSlot
	maxSlots int
	next     atomic.Uint64

	// beforeOpenStream is a test hook invoked immediately before a tunnel opens
	// its request stream. It is nil in production and exists so the ordering
	// between the handshake gate and the CONNECT header can be asserted directly
	// rather than inferred from timing.
	beforeOpenStream func(slot *http3PoolSlot)
}

func newHTTP3Client(options ClientOptions, authorization string) (http3Client, error) {
	if options.TLSConfig == nil {
		return nil, E.New("HTTP/3 requires TLS")
	}
	dialer := options.RawDialer
	if dialer == nil {
		dialer = N.SystemDialer
	}
	baseQUICConfig := httpclient.NewQUICConfig(options.HTTP3Options)
	baseQUICConfig.EnableDatagrams = true
	headers := options.Headers.Clone()
	authority := options.Server.String()
	if options.Authority != "" {
		authority = options.Authority
	}
	if headers != nil {
		if host := headers.Get("Host"); host != "" {
			authority = host
		}
		headers.Del("Host")
	}
	// A size of 1 is the upstream behaviour: exactly one transport, one lazily
	// established connection.
	poolSize, err := options.HTTP3Options.HTTP3ConnectionPool.Build()
	if err != nil {
		return nil, err
	}
	slots := make([]*http3PoolSlot, 0, poolSize)
	for range poolSize {
		slots = append(slots, &http3PoolSlot{
			transport: &http3.Transport{EnableDatagrams: true, DisableCompression: true},
		})
	}

	return &http3ClientImpl{
		dialer:         dialer,
		tlsConfig:      options.TLSConfig,
		server:         options.Server,
		authority:      authority,
		headers:        headers,
		authorization:  authorization,
		baseQUICConfig: baseQUICConfig,
		logger:         options.Logger,
		onSuccess:      options.OnHTTP3Success,
		slots:          slots,
		maxSlots:       poolSize,
	}, nil
}

// quicConfigForLocked returns a per-slot QUIC config.
//
// sing-quic's DialEarly mutates the config it is given (it assigns
// HandshakeIdleTimeout when unset), so a config shared between slots is a data
// race once two slots dial concurrently. Each slot therefore gets its own copy.
//
// The caller MUST already hold slot.access. This is not stylistic: acquire()
// holds the slot lock for the whole dial, and an earlier version of this helper
// took the same lock again, which self-deadlocked every first dial. The "Locked"
// suffix marks the contract so the mistake is visible at the call site.
func (c *http3ClientImpl) quicConfigForLocked(slot *http3PoolSlot) *quic.Config {
	if slot.quicConfig == nil {
		slot.quicConfig = c.baseQUICConfig.Clone()
	}
	return slot.quicConfig
}

// selectionCooldown is how long a slot that failed to establish (or failed to
// open a stream) is skipped before it becomes eligible again.
//
// It is deliberately short. A failure is usually transient (a NAT rebinding, a
// lost packet, a server restart), and keeping capacity out of rotation for long
// periods would push traffic onto H2 for no reason. Repeated failures are still
// visible through consecutiveFailures.
const selectionCooldown = 5 * time.Second

// pickSlot chooses the slot a NEW tunnel will use.
//
// Strategy: healthy least-active. Among eligible slots the one with the fewest
// live tunnels wins, because that is the slot whose congestion controller has
// the least queued work. Ties are resolved by an atomic round-robin over the
// tied slots alone, so equally idle slots are used evenly.
//
// The tie-break deliberately operates on the collected minimum set rather than
// on "the first eligible slot whose active equals the minimum". The earlier
// form compared against the whole eligible count while scanning for the first
// match, which meant it almost always re-selected the lowest-indexed tied slot:
// rotation was possible only on an exact modulus hit, and even then it landed
// on that same first match. The measured effect was that slot 0 served every
// tunnel whenever the slots were tied, which defeats the purpose of a pool.
//
// This replaced unconditional round-robin, which had two defects: it could hand
// a new tunnel to a connection that had already received GOAWAY, and it ignored
// how loaded each connection was.
//
// It returns nil when no slot is eligible. The caller must then consult the
// authority-level state rather than assuming H3 is unusable: an ineligible slot
// is not evidence about the authority. See establishSlot.
func (c *http3ClientImpl) pickSlot() *http3PoolSlot {
	now := time.Now()
	var (
		bestActive  int
		leastActive []*http3PoolSlot
	)
	// Pass 1: find the minimum active count among eligible slots and collect
	// every slot that shares it.
	for _, slot := range c.slots {
		if !slot.eligible(now) {
			continue
		}
		active := slot.health().Active
		switch {
		case leastActive == nil:
			bestActive = active
			leastActive = append(leastActive, slot)
		case active < bestActive:
			bestActive = active
			leastActive = leastActive[:0]
			leastActive = append(leastActive, slot)
		case active == bestActive:
			leastActive = append(leastActive, slot)
		}
	}
	if len(leastActive) == 0 {
		return nil
	}
	// Pass 2: rotate within the tied set. One atomic increment is enough to
	// spread consecutive selections across the ties.
	if len(leastActive) == 1 {
		return leastActive[0]
	}
	index := c.next.Add(1) - 1
	return leastActive[index%uint64(len(leastActive))]
}

// slotCount reports how many independent QUIC connections this client can hold.
func (c *http3ClientImpl) slotCount() int {
	return len(c.slots)
}

func (c *http3ClientImpl) acquire(slot *http3PoolSlot, ctx context.Context) (*http3.ClientConn, error) {
	slot.access.Lock()
	defer slot.access.Unlock()
	if slot.conn != nil && slot.conn.Context().Err() == nil {
		return slot.conn, nil
	}
	if slot.rawConn != nil {
		slot.rawConn.Close()
		slot.rawConn = nil
	}
	rawConn, err := c.dialer.DialContext(ctx, N.NetworkUDP, c.server)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// A slot-level failure is NOT proof that the authority lacks HTTP/3: this
		// particular pooled connection could not be established (transient UDP
		// loss, a NAT rebinding, a closed socket). Reporting it as
		// ErrHTTP3Unavailable would make the caller mark the whole authority
		// broken and drop to HTTP/2 even though other slots are healthy. The
		// error is therefore returned as a plain failure so the caller retries
		// without poisoning the authority.
		return nil, E.Cause(err, "establish HTTP/3 connection")
	}
	// qtls.DialEarly returns once the connection object exists, but it DOES honor
	// ctx: with a peer that stalls its TLS handshake it returns the context error
	// at the deadline (verified against the pinned sing-quic). No extra timeout
	// wrapper is therefore needed here.
	quicConn, err := qtls.DialEarly(ctx, rawConn, c.tlsConfig, c.quicConfigForLocked(slot))
	if err != nil {
		rawConn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Same reasoning as above, except for a genuine protocol negotiation
		// failure: if the server rejects the h3 ALPN then the authority really
		// does not speak HTTP/3 and falling back is correct.
		if isHTTP3NegotiationFailure(err) {
			return nil, E.Cause1(ErrHTTP3Unavailable, err)
		}
		return nil, E.Cause(err, "establish HTTP/3 connection")
	}
	slot.conn = slot.transport.NewClientConn(quicConn)
	slot.quicConn = quicConn
	slot.rawConn = rawConn
	return slot.conn, nil
}

// awaitHandshake blocks until the QUIC handshake for this slot has completed.
//
// Why this is required: sing-quic's DialEarly returns as soon as the connection
// object exists, and OpenStreamSync only waits for stream limits, not for the
// handshake. Our MASQUE client writes the CONNECT header with
// OpenRequestStream + SendRequestHeader, which bypasses the protection the
// standard http3.ClientConn.roundTrip applies. That method waits for
// HandshakeComplete() for every request except GET_0RTT and HEAD_0RTT, and it is
// what keeps ordinary requests out of 0-RTT.
//
// A proxy tunnel must not be created as 0-RTT application data: 0-RTT data is
// replayable by design, so a captured CONNECT could be replayed by an attacker.
// Session resumption itself is left enabled; only the sending of the CONNECT
// header is gated.
func (c *http3ClientImpl) awaitHandshake(slot *http3PoolSlot, ctx context.Context) error {
	slot.access.Lock()
	quicConn := slot.quicConn
	slot.access.Unlock()
	if quicConn == nil {
		return nil
	}
	select {
	case <-quicConn.HandshakeComplete():
		return nil
	case <-quicConn.Context().Done():
		return context.Cause(quicConn.Context())
	case <-ctx.Done():
		return ctx.Err()
	}
}

// openStream opens a CONNECT request stream on a healthy slot, with bounded
// pre-write slot failover.
//
// REPLAY SAFETY is the governing rule here, and it is structural rather than
// advisory:
//
//   - The slot is chosen, and any slot-level retry happens, strictly BEFORE
//     SendRequestHeader is called. At that point no CONNECT byte has been sent
//     and the server has not seen this tunnel, so trying another slot cannot
//     duplicate anything.
//   - Once SendRequestHeader has been called the attempt is marked
//     non-replayable and NO further slot is tried, whatever the failure. The
//     header may be partially on the wire; re-sending it on another connection
//     would make the authority observe the same tunnel twice.
//
// The two are different concepts and are deliberately not merged: pre-write
// failover is not protocol fallback replay.
func (c *http3ClientImpl) openStream(ctx context.Context, request *http.Request) (*http3ActiveStream, *http3.ClientConn, error) {
	// Bounded so a pool of N slots costs at most N + 1 attempts (the extra one
	// allowing a single fresh connection), never an unbounded loop.
	maxAttempts := len(c.slots) + 1
	var lastErr error
	// transportFailures counts attempts that failed while ESTABLISHING transport
	// (dial, QUIC handshake, stream open) as opposed to failing after the CONNECT
	// header was written. Only this class may be promoted to "authority is
	// temporarily unavailable", and only once every attempt has been consumed.
	transportFailures := 0
	attempts := 0
	for range maxAttempts {
		attempts++
		slot, err := c.establishSlot(ctx)
		if err != nil {
			if lastErr != nil {
				return nil, nil, c.promoteExhaustedTransportFailure(lastErr, transportFailures, attempts, maxAttempts)
			}
			return nil, nil, err
		}
		clientConn, err := c.acquire(slot, ctx)
		if err != nil {
			lastErr = err
			if isHTTP3TransportEstablishmentFailure(err) {
				transportFailures++
			}
			c.noteSlotFailure(slot, err)
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			continue
		}
		// Never send a CONNECT before the handshake completes; otherwise it could
		// be transmitted as replayable 0-RTT data.
		if err = c.awaitHandshake(slot, ctx); err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			lastErr = E.Cause(err, "await HTTP/3 handshake")
			if isHTTP3TransportEstablishmentFailure(err) {
				transportFailures++
			}
			c.noteSlotFailure(slot, err)
			continue
		}
		if c.beforeOpenStream != nil {
			c.beforeOpenStream(slot)
		}
		stream, err := clientConn.OpenRequestStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			// GOAWAY is the one open failure with a specific meaning: the
			// connection still works, but it will never accept a new request
			// stream. The slot must stop receiving tunnels immediately, while
			// its existing tunnels keep running.
			if isGoAwayError(err) {
				if slot.markDraining(err) {
					c.logPoolEvent("H3_SLOT_DRAINING", slot, err)
				}
				lastErr = E.Cause(err, "open HTTP/3 stream")
				// Pre-write, so moving to another healthy slot is safe. It is NOT
				// evidence about the authority.
				continue
			}
			// Any other open failure is a slot-level problem. It does not poison
			// the authority, because other slots may be perfectly healthy.
			if isHTTP3TransportEstablishmentFailure(err) {
				transportFailures++
			}
			c.noteSlotFailure(slot, err)
			lastErr = E.Cause(err, "open HTTP/3 stream")
			continue
		}

		// From here on the CONNECT is in flight: this tunnel is non-replayable.
		// No code below may retry on another slot.
		//
		// The active count is taken only now, so a failed open above can never
		// leak a count, and it is released exactly once by the returned release
		// function.
		slot.acquireActive()
		releaseActive := c.activeReleaser(slot)

		stop := context.AfterFunc(ctx, func() {
			stream.CancelRead(0)
			stream.CancelWrite(0)
		})
		var response *http.Response
		err = stream.SendRequestHeader(request)
		if err == nil {
			response, err = stream.ReadResponse()
		}
		if err == nil {
			select {
			case <-clientConn.ReceivedSettings():
			case <-clientConn.Context().Done():
				err = context.Cause(clientConn.Context())
			case <-ctx.Done():
				err = ctx.Err()
			}
		}
		if !stop() {
			err = ctx.Err()
		}
		if err != nil {
			stream.CancelRead(0)
			stream.Close()
			releaseActive()
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			// The CONNECT was already sent, so this must NOT be retried on
			// another slot even though the failure is reported here.
			if isGoAwayError(err) {
				slot.markDraining(err)
			}
			return nil, nil, E.Cause(err, "HTTP/3 CONNECT")
		}
		if response.StatusCode != http.StatusOK {
			stream.CancelRead(0)
			stream.Close()
			releaseActive()
			return nil, nil, statusError(response)
		}
		slot.markHealthy()
		if c.onSuccess != nil {
			// A confirmed HTTP/3 tunnel clears the AUTHORITY-level backoff, which
			// is a different decision from the slot's own health above.
			c.onSuccess()
		}
		return &http3ActiveStream{RequestStream: stream, release: releaseActive}, clientConn, nil
	}
	if lastErr == nil {
		lastErr = E.New("no HTTP/3 pool slot could open a stream")
	}
	// Every attempt was consumed without a single tunnel being established. If
	// ALL of those attempts failed while establishing transport, the authority is
	// treated as temporarily unavailable so the caller can fall back to HTTP/2.
	return nil, nil, c.promoteExhaustedTransportFailure(lastErr, transportFailures, attempts, maxAttempts)
}

// promoteExhaustedTransportFailure upgrades an exhausted pool to an
// authority-level "HTTP/3 unavailable" signal, but ONLY when every attempt
// failed for a transport-establishment reason.
//
// Why this is needed: a silent UDP blackhole is the common mobile-network
// failure, and it produces a handshake TIMEOUT rather than a protocol error.
// Without this promotion the user would simply see a timeout, even though the
// authority serves HTTP/2 perfectly well. That is exactly the case fallback
// exists for.
//
// Why it is restricted: only transport establishment counts. A certificate
// failure, a wrong TLS server name, an auth failure, a 407, a non-200 CONNECT
// response or any post-write error must NOT be laundered into "the server does
// not speak HTTP/3", because retrying those over HTTP/2 would either fail
// identically or mask a real configuration error. Those paths never reach here:
// they return directly above.
//
// Every attempt must have failed this way. A single non-transport failure means
// the pool was not uniformly unable to connect, so the authority is not
// condemned.
func (c *http3ClientImpl) promoteExhaustedTransportFailure(lastErr error, transportFailures, attempts, maxAttempts int) error {
	if lastErr == nil || transportFailures == 0 {
		return lastErr
	}
	// Guard against condemning the authority from a single unlucky attempt: the
	// pool must have been genuinely exhausted.
	if attempts < maxAttempts {
		return lastErr
	}
	if transportFailures != attempts {
		return lastErr
	}
	if errors.Is(lastErr, ErrHTTP3Unavailable) {
		// Already classified; nothing to promote.
		return lastErr
	}
	return E.Cause1(ErrHTTP3Unavailable, lastErr)
}

// isHTTP3TransportEstablishmentFailure reports whether err is a failure to
// ESTABLISH transport, as opposed to a failure of an established tunnel or of
// the protocol negotiation itself.
//
// Negotiation failure is deliberately excluded: isHTTP3NegotiationFailure
// already classifies it precisely (the server answered and rejected h3), and it
// is reported as ErrHTTP3Unavailable at its own call site.
func isHTTP3TransportEstablishmentFailure(err error) bool {
	if err == nil {
		return false
	}
	if isHTTP3NegotiationFailure(err) {
		// Precise classification already exists for this case.
		return false
	}
	// A caller-side cancellation or deadline is NOT evidence about the server.
	// It means we stopped waiting, so it must never condemn the authority.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// A QUIC handshake timeout is the silent-UDP-blackhole signature: the
	// handshake never completed, and nothing on the wire ever came back.
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return true
	}
	// A concrete transport error means the transport layer answered and refused,
	// which is also a transport-establishment failure.
	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		return true
	}
	return false
}

// http3ActiveStream wraps a RequestStream so closing it releases the slot's
// active-tunnel count exactly once.
type http3ActiveStream struct {
	*http3.RequestStream
	release func()
}

func (s *http3ActiveStream) Close() error {
	s.release()
	return s.RequestStream.Close()
}

// activeReleaser returns a function that decrements the slot's active count at
// most once, so a double Close cannot corrupt the count.
func (c *http3ClientImpl) activeReleaser(slot *http3PoolSlot) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			slot.releaseActive()
		})
	}
}

// establishSlot returns a slot that may take a new tunnel, creating a fresh
// connection if every existing slot is unavailable.
//
// This is the layer that keeps SLOT health separate from AUTHORITY health. A
// slot being dead, draining or cooling down says nothing about whether the
// authority speaks HTTP/3, so this never marks the authority broken. Only the
// caller's H3-unavailable signal does that.
func (c *http3ClientImpl) establishSlot(ctx context.Context) (*http3PoolSlot, error) {
	slot := c.pickSlot()
	if slot != nil {
		return slot, nil
	}
	// No slot is currently eligible. Before concluding anything about the
	// authority, try to replace unusable slots with a fresh connection.
	c.replaceClosedSlots()
	slot = c.pickSlot()
	if slot != nil {
		return slot, nil
	}
	// Every slot is draining or dead. Recycle an unusable slot IN PLACE rather
	// than appending, so the pool cannot grow past maxSlots.
	return c.recycleSlot(ctx)
}

// noteSlotFailure records a slot-level failure and retires the slot if it has
// become unusable.
func (c *http3ClientImpl) noteSlotFailure(slot *http3PoolSlot, err error) {
	slot.markFailure(time.Now(), selectionCooldown)
	health := slot.health()
	if health.Connected {
		// The connection object still exists, so the slot keeps its place in the
		// pool and returns after its cooldown.
		c.logPoolEvent("H3_SLOT_COOLDOWN", slot, err)
		return
	}
	slot.markDead()
	c.logPoolEvent("H3_SLOT_DEAD", slot, err)
}

// replaceClosedSlots drops closed slots and refills the pool up to its size with
// fresh connections, so a retired slot does not permanently reduce capacity.
func (c *http3ClientImpl) replaceClosedSlots() {
	now := time.Now()
	for _, slot := range c.slots {
		if !slot.shouldClose() {
			continue
		}
		slot.access.Lock()
		if slot.conn != nil {
			slot.conn.CloseWithError(0, "")
			slot.conn = nil
		}
		slot.quicConn = nil
		if slot.rawConn != nil {
			slot.rawConn.Close()
			slot.rawConn = nil
		}
		slot.state = http3SlotHealthy
		slot.consecutiveFailures = 0
		slot.cooldownUntil = time.Time{}
		slot.drainingSince = time.Time{}
		slot.created = now
		slot.access.Unlock()
	}
}

// recycleSlot re-dials the least useful unusable slot, in place.
//
// It never appends: the pool size is a hard cap, and growing it on failure would
// let a misbehaving server multiply the client's UDP sockets and goroutines. A
// replacement reuses the existing transport so no orphan transport is leaked.
func (c *http3ClientImpl) recycleSlot(ctx context.Context) (*http3PoolSlot, error) {
	if len(c.slots) == 0 {
		return nil, E.New("the HTTP/3 pool is empty")
	}
	// Prefer a dead slot, then a draining one with no active tunnels, then the
	// least-active slot overall. Re-dialing a slot that still carries traffic
	// would cut live tunnels, so it is the last resort.
	var target *http3PoolSlot
	for _, slot := range c.slots {
		health := slot.health()
		switch health.State {
		case http3SlotDead:
			target = slot
		case http3SlotDraining:
			if health.Active == 0 && target == nil {
				target = slot
			}
		}
		if target != nil {
			break
		}
	}
	if target == nil {
		// Nothing is safely recyclable: every slot is either healthy, cooling
		// down, or draining with live tunnels. Report that instead of forcing a
		// connection out from under live traffic.
		return nil, E.New("no HTTP/3 pool slot can be recycled")
	}
	slot := &http3PoolSlot{
		transport: target.transport,
		created:   time.Now(),
	}
	_, err := c.acquire(slot, ctx)
	if err != nil {
		return nil, err
	}
	// Swap the contents in place so the pool length is unchanged.
	target.access.Lock()
	target.conn = slot.conn
	target.quicConn = slot.quicConn
	target.rawConn = slot.rawConn
	target.quicConfig = slot.quicConfig
	target.state = http3SlotHealthy
	target.consecutiveFailures = 0
	target.cooldownUntil = time.Time{}
	target.drainingSince = time.Time{}
	target.created = time.Now()
	target.access.Unlock()
	return target, nil
}

func (c *http3ClientImpl) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	stream, _, err := c.openStream(ctx, &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: destination.String()},
		Host:   destination.String(),
		Header: buildRequestHeader(c.headers, c.authorization, false),
	})
	if err != nil {
		return nil, err
	}
	return &http3StreamConn{stream: stream, remoteAddr: destination}, nil
}

func (c *http3ClientImpl) OpenTunnel(ctx context.Context, request tunnelRequest) (DatagramStream, error) {
	requestURL := *request.url
	requestURL.Scheme = "https"
	requestURL.Host = c.authority
	header := buildRequestHeader(c.headers, c.authorization, request.originAuthorization)
	header.Set("Capsule-Protocol", "?1")
	stream, clientConn, err := c.openStream(ctx, &http.Request{
		Method: http.MethodConnect,
		Proto:  request.protocol,
		URL:    &requestURL,
		Host:   c.authority,
		Header: header,
	})
	if err != nil {
		return nil, err
	}
	return &http3RequestDatagramStream{stream: stream, datagramsEnabled: clientConn.Settings().EnableDatagrams}, nil
}

// ResetConnection tears down every pooled connection so later tunnels dial
// fresh. All slots are reset because a shared authority failure affects them all.
func (c *http3ClientImpl) ResetConnection() {
	for _, slot := range c.slots {
		slot.access.Lock()
		if slot.conn != nil {
			slot.conn.CloseWithError(0, "")
			slot.conn = nil
		}
		slot.quicConn = nil
		if slot.rawConn != nil {
			slot.rawConn.Close()
			slot.rawConn = nil
		}
		slot.access.Unlock()
	}
}

// Close releases every slot's connection, UDP socket and transport. A failure on
// one slot does not prevent the others from being closed.
func (c *http3ClientImpl) Close() error {
	var closeErr error
	for _, slot := range c.slots {
		slot.access.Lock()
		if slot.conn != nil {
			slot.conn.CloseWithError(0, "")
			slot.conn = nil
		}
		slot.quicConn = nil
		if slot.rawConn != nil {
			slot.rawConn.Close()
			slot.rawConn = nil
		}
		slot.access.Unlock()
		closeErr = E.Append(closeErr, slot.transport.Close(), func(err error) error {
			return E.Cause(err, "close http3 transport")
		})
	}
	return closeErr
}

type http3StreamConn struct {
	// stream is the active-stream wrapper, so closing this connection releases
	// the pool slot's active-tunnel count exactly once.
	stream      *http3ActiveStream
	remoteAddr  net.Addr
	writeAccess sync.Mutex
	closed      atomic.Bool
}

func (c *http3StreamConn) Read(p []byte) (int, error) {
	n, err := c.stream.Read(p)
	return n, c.wrapError(err)
}

func (c *http3StreamConn) Write(p []byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	n, err := c.stream.Write(p)
	return n, c.wrapError(err)
}

func (c *http3StreamConn) wrapError(err error) error {
	if err == nil {
		return nil
	}
	if c.closed.Load() {
		return net.ErrClosed
	}
	return qtls.WrapError(err)
}

func (c *http3StreamConn) CloseWrite() error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	return c.stream.Close()
}

func (c *http3StreamConn) Close() error {
	c.closed.Store(true)
	c.stream.SetWriteDeadline(time.Now())
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	c.stream.CancelRead(0)
	return c.stream.Close()
}

func (c *http3StreamConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *http3StreamConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http3StreamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *http3StreamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *http3StreamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func (c *http3StreamConn) NeedAdditionalReadDeadline() bool {
	return true
}

type http3RequestDatagramStream struct {
	// stream is the active-stream wrapper; see http3StreamConn.
	stream           *http3ActiveStream
	datagramsEnabled bool
}

func (s *http3RequestDatagramStream) Read(p []byte) (int, error) {
	return s.stream.Read(p)
}

func (s *http3RequestDatagramStream) Write(p []byte) (int, error) {
	return s.stream.Write(p)
}

func (s *http3RequestDatagramStream) Close() error {
	s.stream.SetWriteDeadline(time.Now())
	s.stream.CancelRead(0)
	return s.stream.Close()
}

func (s *http3RequestDatagramStream) SendDatagram(payload []byte) error {
	if !s.datagramsEnabled {
		return ErrDatagramUnsupported
	}
	err := s.stream.SendDatagram(payload)
	if err == nil {
		return nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return &DatagramTooLargeError{MaxPayloadSize: int(tooLarge.MaxDatagramPayloadSize) - VarintLen(uint64(s.stream.StreamID()/4))}
	}
	return err
}

func (s *http3RequestDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.stream.ReceiveDatagram(ctx)
}

var (
	_ net.Conn       = (*http3StreamConn)(nil)
	_ N.WriteCloser  = (*http3StreamConn)(nil)
	_ DatagramStream = (*http3RequestDatagramStream)(nil)
)

// isHTTP3NegotiationFailure reports whether a QUIC handshake failed because the
// peer does not speak HTTP/3.
//
// This is the only handshake outcome that justifies an authority-level fallback:
// it means the server itself declined the h3 protocol. A timeout, an unreachable
// address or a closed socket says nothing about the authority and must not
// disable HTTP/3 for it, because other pooled connections may still be healthy.
func isHTTP3NegotiationFailure(err error) bool {
	if err == nil {
		return false
	}
	// A TLS alert about ALPN surfaces as a CRYPTO_ERROR carrying
	// "no application protocol"; quic-go wraps it in a TransportError with a
	// crypto error code (0x100 + alert). Code 0x178 is alert 120,
	// no_application_protocol.
	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		const noApplicationProtocol = 0x100 + 120
		if uint64(transportErr.ErrorCode) == noApplicationProtocol {
			return true
		}
	}
	return false
}
