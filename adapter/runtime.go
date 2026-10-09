package adapter

import (
	"context"
	"net"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// ErrResourceSuspended is returned by a resource that is intentionally suspended when the call came
// from background work.
//
// # Why this is not a health signal
//
// An on-demand endpoint is suspended when nothing references it, or while the device is paused. A
// periodic health check that then dials it must NOT wake the tunnel engine: that would be the
// health check spinning up the very machinery it exists to avoid, and would also mean the device
// never stays idle.
//
// So the probe fails, and it fails with this sentinel rather than a network error, so the caller can
// tell the two apart. The health layer treats it as "not measured" and leaves the member's existing
// evidence alone; a real dial failure is still recorded as one.
//
// Real device traffic never sees this error: it does not arrive through a background probe, and the
// demand path wakes the resource normally.
var ErrResourceSuspended = E.New("resource is suspended and this caller may not wake it")

// IsResourceSuspended reports whether an error means "the resource is idle and background work is
// not allowed to wake it".
func IsResourceSuspended(err error) bool {
	return E.IsMulti(err, ErrResourceSuspended)
}

// IsCallerCancellation reports whether an error means the CALLER withdrew.
//
// # Why this is a named fact and not an inline errors.Is
//
// Several subsystems need it and each one needs it for a different decision - the failover retry
// refuses to spend the flow's alternate on it, the load-balance ledger refuses to blame a member for
// it, a measurement refuses to record it as a result, the family scheduler refuses to call a broken
// address family for it - and every one of those decisions has to agree about the fact or they
// contradict each other. The decision stays with the caller; only the fact is here.
//
// It is deliberately NOT the same fact as IsOwnTeardown, even though several callers currently treat
// the two the same way. A caller can stop waiting for a flow that the process did not touch, and the
// process can tear down a flow nobody withdrew. route/dialSetupGate is the case that proves they come
// apart: it cancels an in-flight dial because the NETWORK GENERATION moved, which reports the same
// context.Canceled a caller cancellation does, and the failover path needs to tell them apart to
// satisfy both "no retry after caller cancellation" and "the new generation's demand continues".
// Merging them into one predicate would make that impossible to express later. See
// docs/fork/v0.1.6-architecture-closure.md, known limitations.
func IsCallerCancellation(err error) bool {
	return E.IsMulti(err, context.Canceled)
}

// IsOwnTeardown reports whether an error means THIS PROCESS ended the operation rather than the far
// end failing it.
//
// net.ErrClosed is defined as "an operation on a closed network connection", so it is a statement
// about this side by construction: a remote close arrives as io.EOF or ECONNRESET. The transports
// that could carry a spurious one have already normalised it away - see
// transport/http/stream_error.go, where a quic-go fault is deliberately kept from unwrapping to
// net.ErrClosed so a protocol violation is not reported as an ordinary teardown - so what reaches
// here is an orderly close, a network transition closing a transport, or a group being torn down.
//
// On a network transition this is the fact that matters: the transition closes the members'
// transports, so every in-flight probe fails with net.ErrClosed, and reading that as a node failure
// deletes the health evidence of a member that was never given a chance to answer.
func IsOwnTeardown(err error) bool {
	return E.IsMulti(err, net.ErrClosed)
}

type backgroundProbeKey struct{}

// ContextWithBackgroundProbe marks a context as belonging to periodic background work rather than
// to a flow the user or the device asked for.
//
// # Why a context marker and not a global or a metadata field
//
// The distinction already exists structurally for traffic accounting: real flows arrive at
// Router.RouteConnectionEx and are observed there, while a URLTest probe dials its outbound
// directly. The one place that discrimination is not visible is a resource deciding whether to
// WAKE, because a probe and a demand dial both arrive as DialContext.
//
// The marker travels with the operation that owns the decision, so it cannot leak across requests,
// needs no configuration, and a transport that does not care never reads it. It is set by the
// periodic health path only; a user-initiated test deliberately does not set it, because that test
// is demand in the product sense.
func ContextWithBackgroundProbe(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundProbeKey{}, true)
}

// IsBackgroundProbe reports whether a context belongs to periodic background work.
func IsBackgroundProbe(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	background, _ := ctx.Value(backgroundProbeKey{}).(bool)
	return background
}

// RebindReason says why a network-bound resource is being asked to rebuild.
//
// It is passed through so the resource can decide policy (a new network generation resets the
// recovery window; a repeated same-generation failure does not) and so the log line can name the
// trigger.
type RebindReason uint8

const (
	// RebindHandshakeGiveUp is the safety net: the handshake retry cycle was exhausted.
	RebindHandshakeGiveUp RebindReason = iota
	// RebindSessionExpired is an early trigger, taken when the session is provably dead rather than
	// waiting for the retry cycle to exhaust.
	RebindSessionExpired
	// RebindDeviceWake is the consumer's nudge after the device woke.
	RebindDeviceWake
	// RebindNetworkChanged is a network generation change.
	RebindNetworkChanged
	// RebindManual is an operator or API request.
	RebindManual
)

func (r RebindReason) String() string {
	switch r {
	case RebindHandshakeGiveUp:
		return "handshake-give-up"
	case RebindSessionExpired:
		return "session-expired"
	case RebindDeviceWake:
		return "device-wake"
	case RebindNetworkChanged:
		return "network-changed"
	case RebindManual:
		return "manual"
	default:
		return "unknown"
	}
}

// Rebindable is implemented by a resource whose network binding can be reopened after the path it
// was using died. WireGuard is the first implementation; it is optional so that an outbound without
// a long-lived binding never has to implement it.
//
// RebindStale must be idempotent, must observe ctx, and must return an error rather than retrying
// without bound. It is called with the coordinator's lock released.
type Rebindable interface {
	RebindStale(ctx context.Context, reason RebindReason) error
}

// RecoveryWindow is how long a resource must wait between two rebinds. It matches the handshake
// retry cycle: within one window a burst of triggers is one logical rebind.
const RecoveryWindow = 90 * time.Second
