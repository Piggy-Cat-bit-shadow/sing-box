# The power governor

What this fork does about wakeups while an Apple device is asleep, and the one thing it deliberately
does not do.

## What it is

`common/power` is the single authority. It answers one question - "how much background work is
permitted right now" - and nothing else. It closes nothing, clears nothing, resets nothing;
transitions change what is ALLOWED, and the owner of a connection or a cache decides what to do about
that. ACTIVE is the zero configuration and allows everything, so a build where nothing ever pauses
behaves exactly as it did before this existed.

```
ACTIVE ──pause──▶ QUIESCENT ──no traffic for DeepIdleAfter──▶ DEEP_IDLE
   ▲                   │                                          │
   └──── wake ──── WAKING ◀──────────── real traffic ─────────────┘
```

It is driven from the platform's own lifecycle through the bridge in `box_lifecycle.go`, which maps
each Apple fact onto the governor's two axes:

```
NEPacketTunnelProvider.sleep() -> commandServer.pause() -> Box.DeviceSlept()
     edge: Governor.SleepStarted()      level: PauseManager.DevicePause()
displayStatus off / lockstate locked     the same two calls
NEPacketTunnelProvider.wake()  -> commandServer.wake() -> Box.DeviceResumed()
     edge only: a resume is not a wake, and a push lights the lock screen
displayStatus on                          the edge only, for the same reason
lockstate unlocked            -> commandServer.recordLockState(false) -> Box.DeviceWoke()
     edge, then level: the one platform fact that means a person is using the device
                                     ↓ PauseManager events → applyPauseEvent
                                  Governor
```

The level and the edge are separate facts and the table is the whole policy: a resume and a display
turning on publish the reuse verdict and move nothing else, and only an unlock releases speculative
work. `docs/fork/apple-screen-state-observer.md` is the client half.

## The decisions worth knowing

**QUIESCENT suppresses speculation and keeps liveness.** Provider refresh and UI statistics stop; a
health check and a probe continue. A tunnel whose liveness nobody checks fails silently the moment
the user picks the phone up.

**Traffic does not return the governor to ACTIVE.** A push notification arriving while the phone is
in a pocket forwards one request; returning the whole governor to ACTIVE for it would re-enable
every speculative subsystem at once. Traffic gets its link, the DEEP_IDLE deadline is RESET to now +
`DeepIdleAfter`, and DEEP_IDLE lifts back to QUIESCENT. This is the brief's "wake storm" requirement.

Note what this does and does not claim, because an earlier version of this document overstated it.
Activity is observed **per flow**, not per byte, so a single long-lived transfer does not keep
resetting the deadline while it runs and the governor CAN reach DEEP_IDLE during one. That is
intended, and it is safe, because DEEP_IDLE does not terminate an active flow: it suppresses
speculative maintenance and releases genuinely idle reusable pools, and every keeper only touches
resources with no active user traffic (see the audit below). The accurate statement is:

    new real-flow activity postpones DEEP_IDLE;
    DEEP_IDLE itself does not terminate active business flows.

Not "a device carrying traffic is never treated as idle" - per-flow observation cannot establish
that, and it is not what the code does.

**The discrimination between real and generated traffic is structural, not a heuristic.**
`RouteConnectionEx` / `RoutePacketConnectionEx` are reached by a flow the DEVICE asked for; a URLTest
probe and a DNS query dial their outbound or their transport directly and never arrive there. No
traffic-class guess, no port list. Getting this wrong would be a loop - the governor woken by the
very maintenance it gates.

**A wake is staggered.** WAKING releases the business path immediately and the speculative categories
on their own delays (health check 5s, statistics 10s, provider refresh 15s, probe 5s), measured from
the moment the device is USABLE - a wake with no path waits for the path.

**The pool is released at DEEP_IDLE, not at pause.** `CommandServer.Pause` used to call
`CloseIdleConnections()` the moment the screen went off, which turns every unlock into a pile of DNS,
TLS and QUIC handshakes at exactly the moment the user wants a request answered.

**Observers are notified with the lock released.** An observer's real job - releasing reusable
connections - takes locks of its own, so calling one under the governor's lock makes it a
lock-ordering hazard for every subsystem that observes it.

## The one thing it does not do

**It does not change keepalives.** The brief asks for this in DEEP_IDLE, and it is not implemented.
The reason is not effort - it is that there is no live keepalive anywhere in the tree except
WireGuard, and even there the consequence cannot be verified from this repository. See
`power-keepalive.md` for the full audit.

Status: **accepted as device-validation work.** A bounded WireGuard lengthening is the shape that
would remove the need for a measurement, and choosing that bound requires knowing a carrier's NAT
mapping lifetime. Until somebody measures it on a real network, shipping a guess would risk the
failure this work stream is least allowed to produce: a tunnel that is up, reports healthy, and is
silently unreachable.

## What is covered, and the audit behind it

`power-timer-audit.md` classifies every periodic timer in the core - gated, already pause-aware,
deliberately not gated with reasons, and the one-shot correctness timers that must not be touched.
Two real gaps were found and fixed (the ssm-api save and the remote rule-set refresh); several items
an earlier pass had assumed were handled turned out not to be.
