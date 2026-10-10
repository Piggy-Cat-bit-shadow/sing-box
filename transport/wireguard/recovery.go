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

	// errRevokedRebind is returned by RebindStale when its lease was revoked - by a newer network
	// generation, by Close, or by the registration being invalidated - while the socket work was in
	// flight. It is not a failure of the rebind: the socket was reopened and the endpoint still holds
	// exactly one. What it withholds is the CLAIM. "The socket was reopened" and "this generation
	// recovered" are different facts, and a caller that conflated them would record a superseded
	// generation as healthy. See RebindStale's own note for why this cannot be an abort instead.
	errRevokedRebind = E.New("rebind lease was revoked while the socket was being reopened")
)

// revokedRebindError carries BOTH facts a revoked rebind has to report: that the rebind was revoked, and
// the cancellation reason of the lease it ran under.
//
// # Why both, and why not one wrapped in the other
//
// They are needed by different readers, and each one is useless to the other's:
//
//   - `errors.Is(err, errRevokedRebind)` is what a caller uses to withhold a recovery claim, and it is the
//     only signal that distinguishes "I reopened the socket for a generation that had been superseded" from
//     "I reopened the socket".
//   - `errors.Is(err, context.Canceled)` is what the existing cancellation filters in this file use
//     (`E.IsClosedOrCanceled`), and a revoked rebind must keep being filtered out of the warning path -
//     reporting a superseded generation as a rebind FAILURE would be a second, noisier wrong answer.
//
// Wrapping either inside the other loses the other: `E.Cause(errRevokedRebind, reason)` gives a chain whose
// only leaf is the sentinel, so `errors.Is(err, context.Canceled)` is false and the rebuttal goes to the
// warning path. This type therefore reports both, and the joining implementation is explicit so the
// behaviour does not depend on which error wrapper a dependency happens to provide.
type revokedRebindError struct {
	reason error
}

func (e *revokedRebindError) Error() string {
	return errRevokedRebind.Error() + ": " + e.reason.Error()
}

func (e *revokedRebindError) Unwrap() []error {
	return []error{errRevokedRebind, e.reason}
}

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
	//
	// It is run SYNCHRONOUSLY on the recovery goroutine, from RebindStale. That makes it the seam a test
	// uses to hold a recovery worker resident inside `recoveryLoop` - the goroutine census's sensitivity
	// control is built on it, so no second seam is needed for that.
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

// WorkerResident reports whether a recovery worker is running for this endpoint.
//
// It is a diagnostic, and it exists because the residency flag has exactly one owner (`recoveryLoop`, under
// `recovery.access`) and two readers that must not read it raw: anything deciding whether to start another
// worker, and anything observing from outside. Reading the field directly from another goroutine is a data
// race - `-race` caught precisely that in a test that did it - so the flag is read through the same lock it is
// written under. The recovery comment that explains what a finished worker leaves behind depends on this
// being readable.
func (e *Endpoint) WorkerResident() bool {
	recovery := &e.recovery
	recovery.access.Lock()
	defer recovery.access.Unlock()
	return recovery.worker
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
		// The rebind runs under the LEASE's context, derived from the lease's deadline. A generation change
		// or a close revokes that lease, and the revocation is observed at the points RebindStale
		// documents: at entry, and again before the socket is reopened. Its reach stops at the socket
		// operation itself, which takes no context, so a revocation arriving during the reopen is reported
		// rather than acted on. See RebindStale's own note.
		rebindCtx, cancel := context.WithTimeout(lease.Context(), e.rebindTimeout())
		err := e.RebindStale(rebindCtx, reason)
		cancel()
		lease.Complete()
		switch {
		case rebindWasRevoked(err):
			// The generation moved while the socket was being reopened. The reopen could not be interrupted
			// (see RebindStale), and it is deliberately not claimed as a recovery for the generation that
			// revoked it: this loop reports what it may claim, and stops here.
			//
			// # What recovers the NEW generation, and when
			//
			// Nothing here retries, and the loop does not continue: it returns at the bottom of this case
			// because it performs one rebind per series by design. What makes the NEXT rebind possible is
			// the deferred `recovery.worker = false` at the top of this function - it runs as this loop
			// returns, and `pokeRecovery` refuses to start a worker while that flag is set. So once this
			// returns, the flag is clear and the next trigger can start a worker.
			//
			// The next trigger is a fresh fact, and there are two, both live:
			//
			//   - a session-state transition from the device. The peer is still retrying - that is what
			//     made it stale - so `sessionStateChanged` runs again and calls `pokeRecovery`;
			//   - a device wake, through `rebindOnWake`, which takes its own lease.
			//
			// The registration's window does not stand in the way: `observeEpoch` clears `lastRebind` when
			// the generation advances, which is the same event that revoked this rebind.
			e.options.Logger.Info("wireguard[", e.options.Tag, "] rebind after ", reason,
				" was revoked by a newer network generation; the reopen completed but is not "+
					"recorded as a recovery for it")
		case err != nil && !E.IsClosedOrCanceled(err) && !errors.Is(err, errRebindNotPossible):
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
// # Where ctx is observed, and the one thing it cannot reach
//
// ctx is observed at every point where this layer still has a CHOICE: at entry, and again immediately
// before the UAPI call that reopens the socket. Those are the only two places, and the reason is
// structural rather than a matter of adding more checks.
//
// It is NOT observed inside the socket operation, and no arrangement of checks here can make it so: the
// socket is reopened by `BindUpdate`, which lands in the dialer's listener control -
// `func(network, address string, conn syscall.RawConn) error`, which has no context parameter - and
// which `wireguard-go`'s conn/bind_std.go reaches through `net.ListenConfig.Control` from a
// `ListenPacket(context.Background(), ...)` call. Nothing in this repository can hand a context to that
// operation, so the reach of a revocation stops at the boundary of this method.
//
// MEASURED, and the measurement is the point: with a rebind held inside a real socket open and the
// network generation advanced underneath it, the lease IS expired and its context IS cancelled, and the
// operation that is already running completes anyway, because it is attached to a socket that is already
// gone. `TestCtxCannotReachASocketOperationAlreadyRunning` pins that as the stated bound rather than
// leaving it to be re-derived.
//
// What the check before the reopen does buy:
//
//   - A revocation that arrives while the rebind is still deciding - after `BeginRebind`, before the
//     first UAPI call - now stops the socket from being reopened AT ALL. Without it, that rebind
//     committed the endpoint to a new socket on behalf of a generation that had been superseded.
//   - A revocation that arrives after the socket operation has STARTED cannot stop it, and the outcome
//     is therefore reported as REVOKED rather than as a success, so no caller can record a superseded
//     generation as recovered. The operation is deliberately not abandoned mid-flight: by then the old
//     socket is already closed, and walking away would leave the endpoint with no socket at all -
//     strictly worse than the one a superseded generation asked for.
//
// In one line: this method can refuse to START a reopen on a revoked lease, and can refuse to CLAIM a
// reopen it performed; it cannot INTERRUPT one. A guard whose name promised the third would be worse
// than no guard.
//
// Note that `closeRecovery` is not limited this way: a Close marks the endpoint closed, which
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
		// The guard is the LAST instant at which this rebind can still be abandoned: the call it guards
		// reopens the socket itself (device/uapi.go's listen_port handler calls BindUpdate).
		if err := ctx.Err(); err != nil {
			return err
		}
		// Release the ephemeral port so the reopen picks a fresh one: this IS the new 5-tuple.
		if err := wgDevice.IpcSet("listen_port=0\n"); err != nil {
			return rebindOutcome(ctx, E.Cause(err, "release listen port"))
		}
	} else {
		// A pinned port cannot move; reopening on it is all that is available. The guard is the same
		// last instant: `BindUpdate` is the call that reopens.
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := wgDevice.BindUpdate(); err != nil {
			return rebindOutcome(ctx, E.Cause(err, "rebind socket"))
		}
	}
	// The socket work is done, so the question is no longer whether to act but what may be claimed. A
	// revocation that arrived while the operation ran is reported instead of being absorbed, and the
	// port is read only after that: an operation performed for a generation that no longer exists is not
	// evidence about this one, so there is nothing here worth logging as a success.
	if err := ctx.Err(); err != nil {
		return rebindOutcome(ctx, err)
	}
	newPort := e.currentListenPort(wgDevice)
	e.options.Logger.Info("wireguard[", e.options.Tag, "] rebound after ", reason,
		": port ", oldPort, " -> ", newPort, e.pinnedPortNote())
	return nil
}

// rebindOutcome decides what a rebind that has finished its socket work may CLAIM.
//
// The lease's context is the authority on whether the recovery still belongs to a current generation: a
// generation change, a coordinator close, a registration invalidation and this endpoint's own Close all
// cancel it, and the lease is the only thing that can. A cancelled context therefore means the work
// belongs to a generation that no longer exists, and the caller must not treat it as a recovery - even
// when the work itself succeeded. The cancel reason is carried as the cause, so `errors.Is` still finds
// context.Canceled or context.DeadlineExceeded, which is also what keeps a revoked rebind out of the
// "rebind failed" warning path.
func rebindOutcome(ctx context.Context, rebindErr error) error {
	if err := ctx.Err(); err != nil {
		return &revokedRebindError{reason: err}
	}
	return rebindErr
}

// rebindWasRevoked reports whether a rebind finished without being able to claim its generation.
func rebindWasRevoked(err error) bool {
	return errors.Is(err, errRevokedRebind)
}

// revokedRebindCause reports WHY a revoked rebind was revoked, or nil when the error is not one.
//
// It exists so a caller can tell the two causes apart without parsing the message. They arrive through the
// same cancellation: a generation advance, a coordinator close, a registration invalidation and this
// endpoint's own Close all cancel the LEASE, which surfaces as context.Canceled, while the rebind's own
// `rebindTimeout` surfaces as context.DeadlineExceeded. The first is a revocation by the runtime and the
// second is this layer's own bound expiring, and a caller that needed to report them differently can.
func revokedRebindCause(err error) error {
	var revoked *revokedRebindError
	if errors.As(err, &revoked) {
		return revoked.reason
	}
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
		// A revoked rebind is not a failure and not something to report as one: it is the same
		// generation change the loop above handles, observed from the wake path.
		if err != nil && !rebindWasRevoked(err) && !errors.Is(err, errRebindNotPossible) && !E.IsClosedOrCanceled(err) {
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
