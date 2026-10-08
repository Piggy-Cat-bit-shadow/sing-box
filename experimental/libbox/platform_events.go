package libbox

import (
	"context"
	"sync/atomic"

	"github.com/sagernet/sing-box/common/runtimecoord"
	"github.com/sagernet/sing-box/daemon"
)

// # Android platform events: the ABI rule this file is written under
//
// Every exported method of a bound type is reachable from Kotlin through a generated cgo //export
// wrapper whose C result frame is packed, and a `string`/`[]byte` result puts a Go pointer in that
// frame. On go1.25 that is the unaligned-write hazard the tripwire in gomobile_surface_test.go
// documents. This API therefore returns NOTHING: the platform reports a fact inward, it does not ask
// for a value back. `NewPlatformEvents` returns a bound object, which is a refnum and not a pointer.
//
// # What this file is, and what it deliberately is not
//
// It is a transport. It carries the platform's own numbers and booleans to the shared policy in
// common/runtimecoord and then to the core operations that already exist - NetworkManager.TrimMemory
// and ReleaseMemory, and the pause manager's device axis. It contains no policy: no threshold, no
// level comparison, no decision about what a fact means. If a decision were made here, Android would
// have a second copy of the memory and lifecycle policy that Apple and the desktop do not share, and
// the two would drift - which is the failure mode runtimecoord was created to end for network
// transitions.

// PlatformEvents is the sink a platform reports lifecycle and memory FACTS to.
//
// # One per CommandServer, and why that is the identity that matters
//
// It holds the *StartedService it was created for, not a lookup of "the currently running Box". A
// stale callback that arrives after a new Box started must not reach the new Box, and the only thing
// that can guarantee that is an identity captured at creation: a global "current instance" would
// deliver the old platform's late callback straight into the new core, which is a resurrection.
//
// A fact that arrives after Close - the sink's, or the service's - is a counted no-op. Both floors
// exist because they cover different lifecycles: the sink's Close covers an embedder that tore the
// sink down, and the nil-instance check covers a service that was stopped without the embedder
// telling the sink.
//
// # Locking and Close ordering
//
// There is no lock here. All state is in runtimecoord.PlatformEvents, which owns the coalescing
// state, the closed flag and the in-flight barrier. Close here is that Close, so it waits for a
// target call already in flight and makes every later fact a no-op.
type PlatformEvents struct {
	service *daemon.StartedService
	policy  *runtimecoord.PlatformEvents
	// closed makes Close idempotent without reaching into the policy twice.
	closed atomic.Bool
}

// boxPlatformTarget applies the policy's decisions to the live Box.
//
// # Why it resolves the instance per call instead of capturing it
//
// A reload replaces the Box inside the same StartedService. Capturing the Box would mean the sink
// silently stopped working after a profile reload; capturing the service means the sink follows the
// reload, and a service that has been stopped reports no instance, which is what makes a late fact a
// no-op rather than a call into a torn-down core.
//
// # Why nothing here blocks
//
// Every call is a short, non-blocking operation on the core's own object: closing pools that have no
// active user, or setting the pause manager's flags. It is called from the platform's callback
// thread, so it must not wait on a dial, a reset or a file. ReleaseMemory is the one expensive call
// and it is reached only by the level the platform documents as process-ending.
type boxPlatformTarget struct {
	service *daemon.StartedService
}

// live resolves the running Box instance, or nil when there is none to act on.
func (t *boxPlatformTarget) live() *daemon.Instance {
	if t == nil || t.service == nil {
		return nil
	}
	return t.service.Instance()
}

func (t *boxPlatformTarget) TrimMemory(level runtimecoord.TrimLevel) {
	instance := t.live()
	if instance == nil {
		return
	}
	box := instance.Box()
	if box == nil {
		return
	}
	network := box.Network()
	if network == nil {
		return
	}
	// This is the progressive pass. It closes pools with no active user traffic and drops cached
	// state; it cannot dial, and the level that reaches it was classified by the policy, not here.
	network.TrimMemory(context.Background())
}

func (t *boxPlatformTarget) ReleaseMemory(level runtimecoord.TrimLevel) {
	instance := t.live()
	if instance == nil {
		return
	}
	box := instance.Box()
	if box == nil {
		return
	}
	network := box.Network()
	if network == nil {
		return
	}
	network.ReleaseMemory(context.Background())
}

func (t *boxPlatformTarget) DevicePause() {
	instance := t.live()
	if instance == nil {
		return
	}
	manager := instance.PauseManager()
	if manager == nil {
		return
	}
	// Stops speculative maintenance and makes idle on-demand resources eligible for suspension. It
	// does not stop forwarding and it never terminates a flow that is carrying traffic.
	manager.DevicePause()
}

func (t *boxPlatformTarget) DeviceWake() {
	instance := t.live()
	if instance == nil {
		return
	}
	manager := instance.PauseManager()
	if manager == nil {
		return
	}
	// Marks resources eligible and is the nudge a stale session hears. It dials nothing: the
	// WireGuard endpoint applies its own stale predicate and skips a suspended engine.
	manager.DeviceWake()
}

// NewPlatformEvents returns the sink for one CommandServer.
//
// Create one and hold it for the life of the service, exactly as the CommandServer itself is held.
// The returned object is safe for concurrent use: the policy underneath serialises the facts and
// coalesces the repeats.
func NewPlatformEvents(server *CommandServer) *PlatformEvents {
	events := &PlatformEvents{policy: runtimecoord.NewPlatformEvents(nil)}
	if server != nil {
		events.service = server.StartedService
		events.policy = runtimecoord.NewPlatformEvents(&boxPlatformTarget{service: events.service})
	}
	return events
}

// MemoryTrim reports a memory-trim fact at the platform's own level.
//
// The number is passed through unchanged - Android's ComponentCallbacks2 value - and the shared
// policy decides what it means. That is deliberate: a mapping in Java would have to be repeated in
// Kotlin, Swift and any future client, and the first one to go stale would silently change the
// memory behaviour of that platform alone.
//
// This is the callback Android delivers to a registered ComponentCallbacks2. If the platform never
// calls it, the core's own configured memory policy still runs; this is a supplementary signal, not
// a replacement, and the app must not invent a level for a callback it did not receive.
//
// # Call it off the main thread
//
// The progressive level closes pools and may run the Go collector; the reset-shaped level runs a
// network reset. onTrimMemory is delivered on the main thread, and doing that work there is an ANR
// waiting for a slow teardown. Report the fact from the platform's own background executor, which is
// also where the app already drives the pause/wake commands from.
//
// # Do not map TRIM_MEMORY_UI_HIDDEN to a lifecycle fact here
//
// Level 20 is ignored by the shared policy on purpose. If the app wants the transition it should
// report SetAppForeground / SetScreenOn from the lifecycle and display callbacks that own that fact,
// not derive it from a memory callback whose delivery is not guaranteed.
func (e *PlatformEvents) MemoryTrim(level int32) {
	e.policy.MemoryTrim(runtimecoord.TrimLevel(level))
}

// SetAppForeground reports whether this app is in the foreground.
//
// It is a separate axis from SetScreenOn on purpose. A VPN's normal state is "screen on, our app in
// the background", and a single boolean cannot represent it. This fact never stops the tunnel
// carrying traffic for whatever is in front; its effect is on when the wake nudge may run.
func (e *PlatformEvents) SetAppForeground(foreground bool) {
	e.policy.SetAppForeground(foreground)
}

// SetScreenOn reports whether the device's screen is interactive.
//
// Screen-off is the platform's own "nobody is using this device" statement, and it is what pauses
// the device axis. It is not the same fact as the app going to the background, and the app must
// report both rather than deriving one from the other.
//
// # One driver for the device axis
//
// The shared policy mirrors the last device-axis value it published so that a repeated screen-off is
// not a repeated pause. That mirror assumes it is the only writer. Android currently also drives
// CommandServer.Pause/Wake from ACTION_DEVICE_IDLE_MODE_CHANGED, and mixing the two would let a Doze
// wake lift a pause the screen fact still asserts, with neither path knowing. Report the screen fact
// here and retire the Doze-driven pause/wake on the Android client in the same change, or leave the
// device axis entirely to the old path and report only the app and memory facts here.
func (e *PlatformEvents) SetScreenOn(on bool) {
	e.policy.SetScreenOn(on)
}

// ReportDeviceWake reports an explicit device-wake fact, such as an unlock or user-present event.
//
// It is the strongest of the lifecycle facts: the device just became usable, which is the event the
// WireGuard wake nudge exists for.
func (e *PlatformEvents) ReportDeviceWake() {
	e.policy.DeviceWake()
}

// Close makes every later fact a no-op and waits for a target call already in flight.
//
// Call it when the CommandServer is closed. It is idempotent, and calling it is not the only
// protection: a fact that arrives after the service stopped finds no instance and is ignored too.
func (e *PlatformEvents) Close() {
	if e == nil || !e.closed.CompareAndSwap(false, true) {
		return
	}
	e.policy.Close()
}
