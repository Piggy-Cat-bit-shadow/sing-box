package runtimecoord

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// PlatformEvents is the shared policy that turns platform FACTS into core ACTIONS.
//
// # Why the policy lives here and not in the platform adapter
//
// The Apple extension reports device sleep/wake through the command server, Android reports
// ComponentCallbacks2 memory trims and lifecycle transitions, and a desktop build reports nothing at
// all. If each platform translated its own signals into TrimMemory/ReleaseMemory/pause calls, the
// memory policy would exist three times and disagree with itself - which is exactly the shape this
// fork removed for network transitions when it introduced Coordinator. The platform reports what it
// observed; this file decides what that means.
//
// # What this file does NOT own
//
// It does not own resources. It never closes a pool, never dials and never resets the network
// itself: TrimMemory and ReleaseMemory are NetworkManager's, the pause/wake vocabulary is pause's,
// and the background-probe marker is adapter's. This object is only the mapping and the coalescing
// between the two vocabularies, so it can be driven end to end in a unit test with no device.
//
// # Locking
//
// One mutex guards the recorded facts, the "already published" mirrors and the statistics. It is
// NEVER held across a target call: a target takes the pause manager's lock, the network manager's
// reset lock and the WireGuard endpoint's state lock, and holding this one across them would put an
// arbitrary event goroutine inside those lock orders - the shape of the ABBA deadlock this fork has
// already paid for. Every entry point therefore decides under the lock and acts after releasing it,
// and Close waits for those in-flight calls with the same barrier adaptiveTimer.stop uses.
type PlatformEvents struct {
	access sync.Mutex
	closed bool
	target PlatformTarget

	// inFlight counts target calls that have passed the closed check and not yet returned. Close
	// waits on it. The ordering is the same one documented at length in oomkiller's notifyPressure:
	// the Add happens under access and only after the check, and Close sets closed under access
	// before it Waits, so a call that started before Close is always counted and one that arrives
	// after sees closed and never Adds.
	inFlight sync.WaitGroup

	// screenKnown distinguishes "the platform told us the screen is off" from "the platform never
	// reported the screen". A build that reports nothing must not be treated as a device with the
	// screen off, or every desktop build would run its idle policy permanently.
	screenKnown bool
	screenOn    bool
	// appForeground is the SECOND axis. It is deliberately not folded into screenOn: "the screen is
	// off" and "the app is not in front" are different facts with different consequences, and the
	// combination that matters most - screen on, app in the background - is the NORMAL state of a
	// VPN, which exists to carry traffic for whatever app is in front.
	appForeground bool

	// paused mirrors the last device-axis value published to the target, so a repeated fact is not a
	// repeated call. pause.Manager is itself idempotent, but the mirror is what makes "coalesced when
	// identical events repeat" observable and testable instead of a claim about another package.
	paused bool
	// wakePending is a wake the device axis earned while the app was not in front. It is released by
	// AppForeground, never by a timer: a timer here would be the global polling this policy is
	// explicitly not allowed to introduce.
	wakePending bool

	lastTrimLevel TrimLevel
	lastTrimAt    time.Time
	lastReleaseAt time.Time

	stats PlatformEventStats
}

// PlatformTarget is the runtime half of the mapping: the core operations a platform fact may earn.
//
// It is an interface rather than a set of function fields so a reader sees the complete vocabulary in
// one place, and so adding an action to the policy forces every target to answer for it instead of
// silently doing nothing.
type PlatformTarget interface {
	// TrimMemory is the progressive pass. It must only make the process smaller: it must not dial,
	// must not wake a suspended resource and must not kill a flow that is carrying traffic.
	TrimMemory(level TrimLevel)
	// ReleaseMemory is the reset-shaped pass. It retires every transport and every ownership epoch,
	// so it is only earned by pressure that is about to end the process.
	ReleaseMemory(level TrimLevel)
	// DevicePause records that the device is not being used. It stops speculative maintenance; it
	// does not stop forwarding, and it never terminates an active flow.
	DevicePause()
	// DeviceWake lifts that suppression and is the nudge a stale session hears. It is the "mark
	// resources eligible" action: it does not dial, and it does not rebuild anything by itself.
	DeviceWake()
}

// PlatformEventStats is what the policy actually did. It exists for the harness in the tests, and so
// a field report can answer "did the core see the trim at all" without a debugger.
type PlatformEventStats struct {
	Trims        uint64
	Releases     uint64
	Pauses       uint64
	Wakes        uint64
	Coalesced    uint64
	IgnoredTrims uint64
	AfterClose   uint64
}

// NewPlatformEvents builds the policy for one owner (one Box).
//
// A nil target is legal and makes every action a counted no-op, which keeps a test double and a
// platform with no runtime simple.
func NewPlatformEvents(target PlatformTarget) *PlatformEvents {
	return &PlatformEvents{target: target}
}

// TrimLevel is a memory-trim severity exactly as the platform reported it.
//
// # Why the platform's numbering is carried through unchanged
//
// These are Android's ComponentCallbacks2 values, not a re-numbering invented here. An unrecognised
// level therefore stays visibly unrecognised instead of quietly landing on a neighbour's action, and
// a future platform level can be classified by adding one row to the table below without either the
// Java side or the ABI changing.
//
// # Why ReleaseMemory is earned by exactly one of them
//
// Android's onTrimMemory levels are documented as the SYSTEM's memory state, not this process's
// budget: TRIM_MEMORY_RUNNING_MODERATE/LOW describe the system running low while this process
// happens to be visible, and TRIM_MEMORY_BACKGROUND/MODERATE/COMPLETE describe this process's
// position in the system's LRU list. Treating any of them as "this process is near its own ceiling"
// would be inventing a budget, and this fork deliberately does not do that - see the block comment on
// DefaultAppleNetworkExtensionMemoryLimit for why a number observed on one device is not a
// specification.
//
// The one level that is about THIS process is TRIM_MEMORY_RUNNING_CRITICAL: the documented meaning is
// that a currently-running process will be killed if more memory is not released. That is the only
// Android fact that justifies the reset-shaped pass, because the alternative to one round of
// handshakes is losing the tunnel entirely.
type TrimLevel int32

const (
	// TrimLevelUnspecified is the zero value: no trim was reported. It is not Android's level 0.
	TrimLevelUnspecified TrimLevel = 0

	// Android: the system is running low; this process is visible and is not a kill candidate yet.
	TrimRunningModerate TrimLevel = 5
	// Android: lower still, and this process should release what it is not using.
	TrimRunningLow TrimLevel = 10
	// Android: critically low, and a currently-running process will be killed if memory is not
	// released. The only level severe enough to earn the reset-shaped pass.
	TrimRunningCritical TrimLevel = 15
	// Android: the app's UI was hidden. This is a LIFECYCLE fact, not a memory reading, and it is
	// deliberately NOT mapped to a trim. The old advice to treat UI_HIDDEN as "memory is tight" is
	// wrong on modern Android, where onStop()/ProcessLifecycleOwner report the same transition and
	// the trim callback is not a reliable delivery channel for it. The app reports foreground and
	// screen state as their own facts; see SetAppForeground and SetScreenOn.
	TrimUIHidden TrimLevel = 20
	// Android: this process is in the background LRU list and the system is low.
	TrimBackground TrimLevel = 40
	// Android: the middle of the background LRU list.
	TrimModerate TrimLevel = 60
	// Android: the end of the background LRU list; the process will be killed as soon as possible. A
	// reset here would shed the transports of a process that is already going away, so it is a
	// progressive trim and nothing more.
	TrimComplete TrimLevel = 80
)

// TrimAction is what the shared memory policy does about one trim level.
type TrimAction uint8

const (
	// TrimIgnore is "the platform told us something, and it is not memory pressure we can act on".
	TrimIgnore TrimAction = iota
	// TrimProgressive releases reusable pools and drops caches. It cannot dial or reset.
	TrimProgressive
	// TrimRelease is the reset-shaped pass. Only genuine, process-ending pressure earns it.
	TrimRelease
)

// Action classifies a raw platform level.
//
// # Why an unknown level is ignored rather than trimmed
//
// Trimming is not free: it drops a DNS or HTTP pool the next request then has to rebuild, so a trim
// issued for a level whose meaning we do not know is a cost paid for a guess. Ignoring it is the safe
// direction - the consequence is only that a genuinely tight process keeps its pools until the next
// level we do understand, while the alternative would make every future platform level a silent
// behavioural change.
func (l TrimLevel) Action() TrimAction {
	switch l {
	case TrimRunningLow,
		TrimBackground,
		TrimModerate,
		TrimComplete:
		return TrimProgressive
	case TrimRunningCritical:
		return TrimRelease
	default:
		// Includes TrimRunningModerate (advisory: the system is low, this process is not a
		// candidate), TrimUIHidden (a lifecycle fact, not a memory reading) and every unknown value.
		return TrimIgnore
	}
}

// trimCoalesceWindow bounds how often the same progressive trim is repeated.
//
// It is the same problem oomkiller's defaultReleaseInterval solves: identical repeated events are one
// logical event, and running the release again immediately would drop the pool the previous release's
// next request had just rebuilt. A DIFFERENT level is acted on at once - an escalation is a new fact.
const trimCoalesceWindow = time.Second

// releaseCoalesceWindow bounds the reset-shaped pass.
//
// It is deliberately the same order as adapter.RecoveryWindow: a network reset is the most expensive
// thing this policy can do, and RUNNING_CRITICAL is a state the system stays in for a while, not a
// single instant. Without a window, every repeated callback would advance the network generation and
// reconnect every transport - a reconnect storm wearing a memory-management name.
const releaseCoalesceWindow = adapter.RecoveryWindow

// MemoryTrim records a memory-trim fact from the platform.
//
// The level is the platform's own number; the mapping to a core action is this file's job, and the
// caller must not pre-classify it. Nothing here can dial: the progressive action is
// NetworkManager.TrimMemory, which closes pools with no active user traffic, and the release action
// is only reached by a level the platform documents as process-ending.
func (p *PlatformEvents) MemoryTrim(level TrimLevel) {
	now := time.Now()
	p.access.Lock()
	if p.closed {
		p.stats.AfterClose++
		p.access.Unlock()
		return
	}
	action := level.Action()
	switch action {
	case TrimIgnore:
		p.stats.IgnoredTrims++
		p.access.Unlock()
		return
	case TrimProgressive:
		if level == p.lastTrimLevel && now.Sub(p.lastTrimAt) < trimCoalesceWindow {
			p.stats.Coalesced++
			p.access.Unlock()
			return
		}
		p.lastTrimLevel = level
		p.lastTrimAt = now
		p.stats.Trims++
	case TrimRelease:
		if !p.lastReleaseAt.IsZero() && now.Sub(p.lastReleaseAt) < releaseCoalesceWindow {
			p.stats.Coalesced++
			p.access.Unlock()
			return
		}
		p.lastReleaseAt = now
		p.stats.Releases++
	}
	p.inFlight.Add(1)
	p.access.Unlock()
	defer p.inFlight.Done()
	if p.target == nil {
		return
	}
	switch action {
	case TrimProgressive:
		p.target.TrimMemory(level)
	case TrimRelease:
		p.target.ReleaseMemory(level)
	}
}

// SetScreenOn records whether the device's screen is interactive.
//
// # Why this is the device axis
//
// The screen being off is the platform's own statement that nobody is using the device - it is the
// Android analogue of the NetworkExtension sleep the Apple client reports through the command server.
// It pauses the DEVICE axis: speculative maintenance stops and idle reusable resources become
// eligible for release. It never terminates an active flow and it never resets the network, and real
// traffic still wakes whatever it needs.
//
// # Why it does not resume the app axis
//
// Turning the screen on makes the device usable; it does not put this app in front. The wake nudge is
// deferred to SetAppForeground, which is the fact that says a person is looking at this app - see
// there for why an immediate nudge on screen-on would be a rebind storm on behalf of nobody.
func (p *PlatformEvents) SetScreenOn(on bool) {
	p.access.Lock()
	if p.closed {
		p.stats.AfterClose++
		p.access.Unlock()
		return
	}
	p.screenKnown = true
	p.screenOn = on
	action := p.recomputeDeviceLocked()
	p.inFlight.Add(1)
	p.access.Unlock()
	defer p.inFlight.Done()
	p.applyDeviceAction(action)
}

// SetAppForeground records whether this app is in the foreground.
//
// # Why this is a second axis and not a synonym for the screen
//
// A VPN's normal state is "screen on, our app in the background": the user is in another app and the
// tunnel is carrying that app's traffic. Folding the two facts into one boolean makes that state
// indistinguishable from "screen off", and the first thing a single boolean gets wrong is pausing
// the device for a user who is actively using the phone.
//
// Its one consequence is the wake nudge. The nudge exists so that a session a sleep destroyed is
// re-opened when somebody is waiting on it; with no user in front of this app there is nobody to
// wait, so the nudge is deferred rather than run. It is released - once - the moment the app comes
// forward, and a real flow never waits for it: demand wakes a suspended resource directly.
//
// It deliberately does NOT pause anything on the way to the background: backgrounding the app must
// not stop the tunnel carrying traffic for whatever is now in front.
func (p *PlatformEvents) SetAppForeground(foreground bool) {
	p.access.Lock()
	if p.closed {
		p.stats.AfterClose++
		p.access.Unlock()
		return
	}
	p.appForeground = foreground
	action := p.recomputeDeviceLocked()
	p.inFlight.Add(1)
	p.access.Unlock()
	defer p.inFlight.Done()
	p.applyDeviceAction(action)
}

// DeviceWake records an explicit device-wake fact (a user present / unlock event).
//
// It is authoritative in a way the screen flag is not: the platform is saying the device just became
// usable, which is exactly the event the WireGuard wake nudge was written for (LX 041 - the device
// wakes and the handshake is still retrying into a flow the sleep destroyed). It therefore forces the
// nudge even if the app axis has not caught up yet.
func (p *PlatformEvents) DeviceWake() {
	p.access.Lock()
	if p.closed {
		p.stats.AfterClose++
		p.access.Unlock()
		return
	}
	if p.screenKnown && p.screenOn && !p.paused && !p.wakePending {
		// Already awake and already nudged. A platform may deliver the same user-present fact more
		// than once (a receiver re-registration replays it); a second nudge would be a second rebind
		// opportunity for no new event.
		p.stats.Coalesced++
		p.access.Unlock()
		return
	}
	p.screenKnown = true
	p.screenOn = true
	p.paused = false
	p.wakePending = false
	p.stats.Wakes++
	p.inFlight.Add(1)
	p.access.Unlock()
	defer p.inFlight.Done()
	if p.target != nil {
		p.target.DeviceWake()
	}
}

// deviceAction is one decision the device axis reached, taken under the lock and applied after it.
type deviceAction uint8

const (
	deviceActionNone deviceAction = iota
	deviceActionPause
	deviceActionWake
)

// recomputeDeviceLocked decides what the device axis owes after a fact changed. Caller holds access.
//
//	paused   = screen known to be off
//	wake     = the device became usable AND a user is in front of this app
//	deferred = the device became usable with nobody in front of this app
func (p *PlatformEvents) recomputeDeviceLocked() deviceAction {
	wantPaused := p.screenKnown && !p.screenOn
	if wantPaused {
		if p.paused {
			return deviceActionNone
		}
		p.paused = true
		p.wakePending = false
		p.stats.Pauses++
		return deviceActionPause
	}
	if !p.paused && !p.wakePending {
		return deviceActionNone
	}
	p.paused = false
	if !p.appForeground {
		// The screen came back with the app in the background. The resources stay eligible; the nudge
		// waits for the user rather than running for an app nobody is looking at.
		p.wakePending = true
		return deviceActionNone
	}
	p.wakePending = false
	p.stats.Wakes++
	return deviceActionWake
}

func (p *PlatformEvents) applyDeviceAction(action deviceAction) {
	if p.target == nil {
		return
	}
	switch action {
	case deviceActionPause:
		p.target.DevicePause()
	case deviceActionWake:
		p.target.DeviceWake()
	}
}

// Close makes every later fact a no-op and waits for the target calls already in flight.
//
// # Why it waits
//
// Returning immediately left the same hole adaptiveTimer.stop documents: a call that had passed the
// closed check was still going to run its target operation - a trim that closes pools, or a wake that
// nudges a rebind - against a core that is being torn down. Callers treat Close as "nothing further
// will touch this", and the barrier is what makes that true rather than likely.
//
// It is idempotent, and a fact that arrives after it is counted in AfterClose rather than acted on,
// because "an event after Close" is a platform dropping a callback on us, not a resurrection.
func (p *PlatformEvents) Close() {
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		return
	}
	p.closed = true
	p.access.Unlock()
	p.inFlight.Wait()
}

// Stats returns a snapshot of what the policy did.
func (p *PlatformEvents) Stats() PlatformEventStats {
	p.access.Lock()
	defer p.access.Unlock()
	return p.stats
}

// ScreenOn reports the last screen fact, and whether one was ever reported.
func (p *PlatformEvents) ScreenOn() (on bool, known bool) {
	p.access.Lock()
	defer p.access.Unlock()
	return p.screenOn, p.screenKnown
}

// AppForeground reports whether the app is currently in front.
func (p *PlatformEvents) AppForeground() bool {
	p.access.Lock()
	defer p.access.Unlock()
	return p.appForeground
}
