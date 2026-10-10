package wireguard

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/wireguard-go/device"
)

// Recovery constants.
//
// The give-up window is the peer's own retry cycle: the device publishes PeerSessionExpired or
// PeerSessionNone when its handshake attempts are exhausted, which is roughly 90 seconds of retries
// under demand. The early window is this fork's addition: the same evidence, taken as soon as it is
// conclusive instead of waiting for the cycle, because a user measuring a node 15 seconds after
// waking the device cannot tell "not yet recovered" from "dead".
const (
	earlyRebindDelay = 15 * time.Second
	recoveryPoll     = 5 * time.Second
)

var (
	// errRebindNotPossible is returned when a rebind was requested but the endpoint is not in a
	// state where it may act: closing, suspended, not started, or already inside a recovery window.
	// It is a local lifecycle outcome, not a path failure, and callers must not record it as one.
	errRebindNotPossible = E.New("wireguard rebind not possible in the current state")
)

// peerSession is what the session-state callback records per peer.
//
// The callback runs under the peer's session-state lock and must be cheap and must not call back
// into Device, so it stores primitives and signals a channel. Everything else - the stale
// predicate, the timers, the rebind - happens on the recovery worker.
type peerSession struct {
	state         device.PeerSessionState
	establishedAt time.Time
	handshakeAt   time.Time
	// stale is set when the session is provably dead (give-up, or a handshake that never
	// completes). A successful handshake clears it.
	stale bool
}

// recoveryState is everything the WireGuard recovery needs, kept next to the endpoint's other
// runtime state so a reader has one place to look.
type recoveryState struct {
	access sync.Mutex
	peers  map[device.NoisePublicKey]*peerSession
	wake   chan struct{}
	worker bool
	closed bool
	// settle overrides earlyRebindDelay in tests.
	settle time.Duration
	// poll overrides recoveryPoll in tests.
	poll time.Duration
	// rebindHook, when set, replaces the device UAPI rebind. Tests use it to observe the decision
	// path without a live device; production leaves it nil.
	rebindHook func(ctx context.Context) error
}

// RuntimeResourceLabel names this endpoint in coordinator logs.
func (e *Endpoint) RuntimeResourceLabel() string {
	return "wireguard/" + e.options.Tag
}

// sessionStateChanged is the Device.SetSessionStateFunc callback.
//
// Contract from wireguard-go: calls are serialized per peer, delivered in transition order, and the
// callback must be cheap and must not call back into Device. It is also delivered while the peer's
// session-state lock is held, so nothing here may block on another lock that could in turn take
// that one. It records a few primitives and nudges a channel with a non-blocking send.
func (e *Endpoint) sessionStateChanged(peer device.NoisePublicKey, state device.PeerSessionState) {
	now := time.Now()
	recovery := &e.recovery
	recovery.access.Lock()
	session, loaded := recovery.peers[peer]
	if !loaded {
		session = &peerSession{}
		recovery.peers[peer] = session
	}
	switch state {
	case device.PeerSessionEstablished:
		// A live session is not stale, whatever happened before it. This is what stops the early
		// trigger from firing while a rekey is in progress on a healthy tunnel.
		session.stale = false
		session.establishedAt = now
	case device.PeerSessionHandshake:
		// Only the FIRST handshake of a series arms the early window; a retry is the same series.
		if session.state != device.PeerSessionHandshake {
			session.handshakeAt = now
		}
	case device.PeerSessionExpired, device.PeerSessionNone:
		// The retry cycle gave up. The session is provably dead: no usable key material, or the
		// handshake older than the reject window. This is the give-up trigger.
		session.stale = true
	}
	session.state = state
	// The worker is needed for BOTH triggers, not only the give-up one.
	//
	// A handshake entering its series is NOT stale - it becomes stale only when the settle window
	// expires, and the code that makes that decision (`anyStale`) lives inside the worker. Starting
	// the worker only on `stale` therefore made the early trigger unreachable: nobody was left to
	// notice that the handshake was still running at the window, so it could fire only as a side
	// effect of some OTHER peer having given up first and started the worker. The symptom is the one
	// the trigger exists to remove - a node wakes, retries into the dead 5-tuple, and the user waits
	// for the full give-up cycle.
	//
	// Starting it here does not make it resident: the loop returns as soon as nothing is stale AND
	// nothing is handshaking, so a handshake that completes before the window costs one goroutine
	// for its duration and nothing afterwards.
	needWorker := session.stale || session.state == device.PeerSessionHandshake
	recovery.access.Unlock()

	if needWorker {
		e.pokeRecovery()
	}
}

// pokeRecovery starts the recovery worker if it is not running.
//
// It is called from the session-state callback, so it costs one lock and a non-blocking receive on
// the common path. The worker is created lazily: a healthy, idle or closed endpoint has no
// goroutine, no timer and no traffic.
func (e *Endpoint) pokeRecovery() {
	recovery := &e.recovery
	recovery.access.Lock()
	if recovery.closed || recovery.worker {
		recovery.access.Unlock()
		return
	}
	recovery.worker = true
	recovery.access.Unlock()
	go e.recoveryLoop()
}

// recoveryLoop watches stale sessions until they are resolved.
//
// It exists only while a session is stale. Its two jobs:
//
//   - poll the peers: a handshake that never completes becomes stale after the early window, which
//     is the early trigger, and one that completes clears the flag and ends the loop;
//   - run a rebind when one is earned, through the coordinator's window so that a burst of
//     triggers, a wake and a network change produce one rebind rather than four.
func (e *Endpoint) recoveryLoop() {
	recovery := &e.recovery
	defer func() {
		recovery.access.Lock()
		recovery.worker = false
		recovery.access.Unlock()
	}()

	settle, poll := e.recoveryWindow()

	for {
		select {
		case <-recovery.wake:
		case <-time.After(poll):
		case <-e.options.Context.Done():
			return
		}

		// A closed or torn-down endpoint ends the loop. Close sets this under the same lock the
		// loop reads, so a rebind can never resurrect a closed device.
		recovery.access.Lock()
		closed := recovery.closed
		recovery.access.Unlock()
		if closed {
			return
		}
		if e.stateAccess.TryLock() {
			closing := e.closing
			e.stateAccess.Unlock()
			if closing {
				return
			}
		}

		if !e.anyStale(settle) {
			if !e.anyHandshaking() {
				return
			}
			continue
		}

		reason := adapter.RebindSessionExpired
		if e.staleFromGiveUp() {
			reason = adapter.RebindHandshakeGiveUp
		}
		lease, granted := e.registration.BeginRebind(reason)
		if !granted {
			// Coalesced: a rebind for this generation already ran or is in flight.
			return
		}
		// The rebind runs under the LEASE's context, derived from the lease's deadline, so a generation
		// change or a close is observed by a rebind that has not yet STARTED its socket work. Running
		// under the endpoint's own context would only observe the core shutting down, which is a
		// different and much later event.
		//
		// Its reach stops at RebindStale's entry, and that is stated there rather than implied here: the
		// socket reopen below takes no context, so a revocation arriving during it is a bounded latency
		// rather than a cancellation. See RebindStale's own note for the measurement.
		rebindCtx, cancel := context.WithTimeout(lease.Context(), e.rebindTimeout())
		err := e.RebindStale(rebindCtx, reason)
		cancel()
		lease.Complete()
		if err != nil && !E.IsClosedOrCanceled(err) && !errors.Is(err, errRebindNotPossible) {
			e.options.Logger.Warn("wireguard[", e.options.Tag, "] rebind failed: ", err)
		}
		// One rebind per series: the next one requires a new proven failure.
		return
	}
}

// anyStale reports whether any peer needs a rebind.
//
// A session is stale when the device said so (give-up), or when a handshake has been in progress for
// longer than the settle window without completing: the early trigger. A session that is
// Established is never stale here, which is what keeps a healthy rekey from being treated as a
// failure.
func (e *Endpoint) anyStale(settle time.Duration) bool {
	now := time.Now()
	recovery := &e.recovery
	recovery.access.Lock()
	defer recovery.access.Unlock()
	for _, session := range recovery.peers {
		if session.stale {
			return true
		}
		if session.state == device.PeerSessionHandshake && !session.handshakeAt.IsZero() &&
			now.Sub(session.handshakeAt) >= settle {
			session.stale = true
			return true
		}
	}
	return false
}

// anyHandshaking reports whether a handshake is still in progress, so the worker keeps waiting for
// it to succeed or time out.
func (e *Endpoint) anyHandshaking() bool {
	recovery := &e.recovery
	recovery.access.Lock()
	defer recovery.access.Unlock()
	for _, session := range recovery.peers {
		if session.state == device.PeerSessionHandshake {
			return true
		}
	}
	return false
}

// staleFromGiveUp reports whether the staleness came from the device's own give-up rather than from
// this fork's early window.
func (e *Endpoint) staleFromGiveUp() bool {
	recovery := &e.recovery
	recovery.access.Lock()
	defer recovery.access.Unlock()
	for _, session := range recovery.peers {
		if session.stale && (session.state == device.PeerSessionExpired || session.state == device.PeerSessionNone) {
			return true
		}
	}
	return false
}

func (e *Endpoint) recoveryWindow() (time.Duration, time.Duration) {
	recovery := &e.recovery
	recovery.access.Lock()
	defer recovery.access.Unlock()
	settle := recovery.settle
	if settle == 0 {
		settle = earlyRebindDelay
	}
	poll := recovery.poll
	if poll == 0 {
		poll = recoveryPoll
	}
	return settle, poll
}

func (e *Endpoint) rebindTimeout() time.Duration {
	return 30 * time.Second
}

// RebindStale reopens the endpoint's UDP socket and lets the device retry its handshake on the new
// 5-tuple.
//
// # Why reopening the socket is the fix
//
// After a device sleep or a handover the per-flow state on the path - the NAT mapping, or a DPI
// classification - is gone, while the peer keeps retrying handshakes into the same 5-tuple. Nothing
// on our side can revive that flow. Reopening the bind gives the retry a new source port, which is
// what a manual reconnect does and what heals it in the field.
//
// # listen_port
//
// A configured listen_port pins the local port, so a rebind cannot change the 5-tuple. It is still
// performed - the socket is reopened and the handshake retried - but the operator is told that
// recovery was limited, because silently changing a configured port would be a configuration
// change, not a recovery.
//
// It is safe to call from the coordinator or directly: it never runs while the endpoint is suspended or
// closed, and the rebind itself is a device UAPI operation that holds the device's own lock rather
// than ours.
//
// # What ctx actually reaches, and what it cannot
//
// ctx is observed ONCE, at entry. That is the whole of its reach, and it is a limitation of the
// interface below rather than an oversight here: the socket is reopened by `BindUpdate`, which lands in
// the dialer's listener control - `func(network, address string, conn syscall.RawConn) error`, with no
// context parameter - so a revocation that arrives while that operation is running cannot be delivered
// to it. MEASURED, with a rebind held inside a real socket open and the network generation advanced
// under it: the lease is expired, its context is cancelled, and the rebind completes anyway, moving the
// endpoint (port 61179 -> 61180 in that measurement).
//
// The consequence is a bounded REVOCATION LATENCY, not a leak and not a hang: the superseded generation
// gets one socket reopen it would otherwise have asked for again, the endpoint still holds exactly one
// socket, and Close still releases everything. The alternative available inside this repository - a
// second ctx check between the two UAPI calls below - would narrow the window without closing it, and a
// guard that does not do what its name says is worse than a measured and stated bound.
//
// Note that `closeRecovery` is NOT limited this way: a Close marks the endpoint closed, which
// `BindUpdate`'s own path observes, which is why Close is correct even while a rebind is in flight.
func (e *Endpoint) RebindStale(ctx context.Context, reason adapter.RebindReason) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Closing and suspended are both terminal for a rebind: closing means the endpoint is going
	// away, and suspended means the device is deliberately down (BindUpdate is a no-op then, and
	// waking it here would resurrect a resource the idle policy released).
	if e.suspended.Load() {
		return errRebindNotPossible
	}
	e.stateAccess.Lock()
	closing := e.closing
	wgDevice := e.device.Load()
	e.stateAccess.Unlock()
	if closing {
		return errRebindNotPossible
	}

	// Test seam. It runs the decision path without a live device, which is what makes the recovery
	// policy testable deterministically; production never sets it.
	e.recovery.access.Lock()
	rebindHook := e.recovery.rebindHook
	e.recovery.access.Unlock()
	if rebindHook != nil {
		if err := rebindHook(ctx); err != nil {
			return err
		}
		e.options.Logger.Info("wireguard[", e.options.Tag, "] rebound after ", reason)
		return nil
	}
	if wgDevice == nil {
		return errRebindNotPossible
	}

	oldPort := e.currentListenPort(wgDevice)
	if e.options.ListenPort == 0 {
		// Release the ephemeral port so the reopen picks a fresh one: this IS the new 5-tuple.
		if err := wgDevice.IpcSet("listen_port=0\n"); err != nil {
			return E.Cause(err, "release listen port")
		}
	} else if err := wgDevice.BindUpdate(); err != nil {
		// A pinned port cannot move; reopening on it is all that is available.
		return E.Cause(err, "rebind socket")
	}
	newPort := e.currentListenPort(wgDevice)
	e.options.Logger.Info("wireguard[", e.options.Tag, "] rebound after ", reason,
		": port ", oldPort, " -> ", newPort, e.pinnedPortNote())
	return nil
}

// pinnedPortNote explains a recovery that could not change the 5-tuple.
func (e *Endpoint) pinnedPortNote() string {
	if e.options.ListenPort == 0 {
		return ""
	}
	return " (listen_port is pinned, so the local port is unchanged and recovery is limited)"
}

// currentListenPort reads the device's current local port, for the log line. A failure to parse the
// running configuration is not worth failing a rebind over.
func (e *Endpoint) currentListenPort(wgDevice *device.Device) uint16 {
	running, err := wgDevice.IpcGet()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(running, "\n") {
		if !strings.HasPrefix(line, "listen_port=") {
			continue
		}
		port, parseErr := strconv.ParseUint(strings.TrimPrefix(line, "listen_port="), 10, 16)
		if parseErr != nil {
			return 0
		}
		return uint16(port)
	}
	return 0
}

// rebindOnWake applies the wake nudge (trigger 3).
//
// The stale predicate is the point: a wake with a healthy session must cost nothing. It is also
// skipped entirely for a suspended or not-started endpoint, which is what keeps a device wake from
// spinning up tunnels the idle policy had released.
func (e *Endpoint) rebindOnWake() {
	if e.suspended.Load() {
		return
	}
	e.stateAccess.Lock()
	closing := e.closing
	wgDevice := e.device.Load()
	e.stateAccess.Unlock()
	if closing || wgDevice == nil {
		return
	}
	if !e.hasStaleSession() {
		return
	}
	if !e.registration.WakeAllowsRebind() {
		return
	}
	lease, granted := e.registration.BeginRebind(adapter.RebindDeviceWake)
	if !granted {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(lease.Context(), e.rebindTimeout())
		defer cancel()
		err := e.RebindStale(ctx, adapter.RebindDeviceWake)
		lease.Complete()
		if err != nil && !errors.Is(err, errRebindNotPossible) && !E.IsClosedOrCanceled(err) {
			e.options.Logger.Debug("wireguard[", e.options.Tag, "] wake rebind skipped: ", err)
		}
	}()
}

// hasStaleSession reports whether any peer's session is provably dead.
func (e *Endpoint) hasStaleSession() bool {
	recovery := &e.recovery
	recovery.access.Lock()
	defer recovery.access.Unlock()
	for _, session := range recovery.peers {
		if session.stale {
			return true
		}
	}
	return false
}

// closeRecovery stops the recovery worker and marks the endpoint closed for it.
//
// The flag is set under the same lock the worker reads, so a rebind already in flight observes it
// and a later one cannot start. The channel is not closed: the worker may be selecting on it, and a
// send racing a close is a panic. A pending worker notices the flag on its next wake, which
// includes the context cancellation every endpoint already has.
func (e *Endpoint) closeRecovery() {
	recovery := &e.recovery
	recovery.access.Lock()
	alreadyClosed := recovery.closed
	recovery.closed = true
	recovery.access.Unlock()
	if alreadyClosed || recovery.wake == nil {
		return
	}
	select {
	case recovery.wake <- struct{}{}:
	default:
	}
}

// initRecovery prepares the recovery state. It is called once, before the device exists.
func (e *Endpoint) initRecovery() {
	e.recovery.peers = make(map[device.NoisePublicKey]*peerSession)
	e.recovery.wake = make(chan struct{}, 1)
}
