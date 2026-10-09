package box

import (
	"github.com/sagernet/sing-box/common/power"
)

// This file is CORE, not platform glue, and it exists because the Apple lifecycle is the one place
// where the platform's vocabulary and the core's two axes are easy to get wrong.
//
// # The four facts an Apple packet tunnel actually reports, and what each one means
//
// The client is a NEPacketTunnelProvider. Every fact below is a public NetworkExtension override or
// a platform notification the client delivers through the command server; none of them is inferred
// here, and none of them is invented.
//
//	sleep()          the device is going to sleep.  -> the sleep EDGE and the device LEVEL pause
//	wake()           the extension ran again.        -> the resume EDGE only
//	displayStatus    the display is on / off.        -> off: the sleep EDGE and the level pause
//	                                                    on:  the resume EDGE only
//	lockstate        the device is locked / unlocked. -> locked:   the sleep EDGE and the level pause
//	                                                    unlocked: the resume EDGE and the LEVEL WAKE
//
// The asymmetry between the last two lines of displayStatus and lockstate is the whole point of this
// file, so it is stated rather than left to be re-derived:
//
// A DISPLAY TURNING ON IS NOT AN UNLOCK. On iOS a push notification lights the lock screen; so does
// raise-to-wake; so does a notification the user glanced at and dismissed. Treating any of those as
// "the device is usable" releases health checks, URLTests and provider refreshes for a phone in a
// pocket, which is the wake storm the power policy exists to prevent (docs/fork/power-governor.md).
// What a display turning on DOES prove is that time passed and that this process ran again: the
// sleep is over, so reusable state established before it has not been verified since. That is the
// reuse epoch, and it is the only thing a display-on publishes.
//
// AN UNLOCK IS an unlock. `lockstate == 0` is the platform's own statement that a person presented
// a credential and is now using the device. It is the only fact that releases the level, it arrives
// at most once per unlock, and the release that follows it is staggered by the governor.
//
// # Why the level needs a publisher at all, and why it is not a timer
//
// Before this file, the Apple level had no lift at all: the pause manager's device axis is a level,
// `Wake()` never moved it on iOS (correctly, because a resume is not a wake), and the shipped client
// never called the one method that did. So the level was entered on the first sleep and held for the
// life of the process: speculation never resumed, and the DEEP_IDLE pool release re-fired on every
// traffic gap. See docs/fork/post-wake-reuse.md.
//
// The tempting fix - expire the pause after some duration - is wrong and is not what this does. A
// timer cannot tell a locked phone from an unlocked one, so it would release speculation for the
// locked phone (the power regression) or fail to release it for the unlocked one (the latch). The
// only thing that can answer "is somebody using this device" is a platform fact that says so, and
// the unlock fact says exactly that. A platform that reports no such fact keeps the latch, and that
// is stated as a limitation rather than papered over with a guess: see the client patch in
// docs/fork/apple-screen-state-observer.md.
//
// # Dedup: the same sleep must not be measured twice, and one sleep must not produce two boundaries
//
// Every fact above goes through the same two calls, and the coalescing is the GOVERNOR's, not this
// file's: `SleepStarted` ignores a repeated sleep while one is being measured, `Resumed` publishes
// at most one boundary per sleep, and the level calls are idempotent levels. So a client that
// reports sleep() AND the display AND the lock for one screen-off produces one measurement and one
// boundary, and a client that reports only one of them produces the same one. The alternative -
// disambiguating here with a "have I already seen this sleep" flag - would mean this file owned a
// second copy of the coalescing rule and the two could disagree.

// deviceAxis is the level side of the device lifecycle: the object that publishes "the device is
// paused" and "the device is usable" to everything that cares. In the core it is the pause manager.
//
// It is an interface here so the mapping in this file can be tested without building a Box, which
// needs a full service context and a dozen managers: the mapping is the part with the ordering and
// dedup argument in it, and it is the part that must be provable without a device.
type deviceAxis interface {
	DevicePause()
	DeviceWake()
}

// lifecycle is the Apple lifecycle's vocabulary mapped onto the governor's two axes.
//
// Both fields are optional and both are checked per call: a Box built without a governor, or with a
// caller-supplied pause manager that is nil, must still be drivable by a platform fact rather than
// panicking on it. That is not defensive decoration - `NewBox` registers the governor before it can
// fail, and the libbox path supplies an existing pause manager, so the partial wiring is real.
type lifecycle struct {
	governor *power.Governor
	device   deviceAxis
}

// slept records a sleep: the EDGE first, then the LEVEL.
//
// The order is the same one applyPauseEvent documents for the pause manager's own events, and for
// the same reason: the sleep must be being measured before anything reacts to the pause, so the
// resume that ends it has a start instant to measure from. A level that arrived first would leave a
// window in which the device is paused with no measurement running, and a resume in that window is
// not a boundary - which is precisely the "first flow after the unlock is handed a socket that the
// sleep killed" failure this whole stream exists to remove.
func (l lifecycle) slept() {
	if l.governor != nil {
		l.governor.SleepStarted()
	}
	if l.device != nil {
		l.device.DevicePause()
	}
}

// resumed records that this process ran again after a sleep: the EDGE, and nothing else.
//
// It is deliberately NOT a device wake. See the file comment: the platform resumes the extension for
// every push and background task, and releasing speculative work for those is the wake storm. What a
// resume does carry is time, which is all the reuse epoch needs.
func (l lifecycle) resumed() {
	if l.governor != nil {
		l.governor.Resumed()
	}
}

// woke records that the device became usable: the reuse EDGE first, then the LEVEL wake.
//
// The verdict is published before the level moves, and that order is load-bearing. Releasing the
// level is what lets a health check, a probe and a provider refresh run; the work they do dials, and
// it must dial a path that is known to be new rather than one that merely looks alive. Publishing
// the boundary first closes that race by construction instead of by timing.
//
// The edge is published HERE as well as by the pause manager's own callback, which fires
// EventDeviceWake and reaches applyPauseEvent -> Governor.Resumed. That double publication is
// deliberate and is a no-op: `Resumed` is idempotent for one sleep, so the explicit call is what
// makes the ordering a property of this function rather than a property of the pause manager's
// callback list, and the callback's is what keeps a wake driven from anywhere else - an Android
// Doze exit, a future embedder - on the same path.
func (l lifecycle) woke() {
	if l.governor != nil {
		l.governor.Resumed()
	}
	if l.device != nil {
		l.device.DeviceWake()
	}
}

// screenState applies the display fact.
//
// Off is a sleep: nobody is looking at a screen that is off, and the level pause plus a measurement
// is exactly what the sleep fact does.
//
// On is a RESUME and not a wake. The reasoning is in the file comment and it is the difference
// between a working device axis and a phone in a pocket running URLTests: a display lights up for a
// push notification, for raise-to-wake, and for a notification dismissed without unlocking.
func (l lifecycle) screenState(on bool) {
	if on {
		l.resumed()
		return
	}
	l.slept()
}

// lockState applies the lock fact.
//
// Locked is a sleep, and it is the more reliable of the two "nobody is using this" facts: it does
// not depend on whether a notification lit the screen. Both reach the same two calls, and the
// governor coalesces them into one measurement, so reporting both costs nothing and reporting only
// one still produces a correct axis.
//
// Unlocked is the ONE fact in this file that releases the level, because it is the only one that
// means a person is using the device. It is bounded in every direction that matters: it fires at
// most once per unlock, the governor coalesces repeats, and the release that follows is staggered
// (health check 5s, statistics 10s, provider refresh 15s), so an unlock is a ramp rather than a
// burst.
func (l lifecycle) lockState(locked bool) {
	if locked {
		l.slept()
		return
	}
	l.woke()
}

// lifecycleFor resolves the bridge for this Box. It is a value, so it captures the governor and the
// manager once and cannot observe a later replacement of either.
func (s *Box) lifecycle() lifecycle {
	return lifecycle{
		governor: s.powerGovernor,
		device:   s.pauseManager,
	}
}
