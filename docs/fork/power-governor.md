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

It is driven from the platform's own lifecycle, already present before this work:

```
NEPacketTunnelProvider.sleep() -> commandServer.pause() -> PauseManager.DevicePause()
NEPacketTunnelProvider.wake()  -> commandServer.wake()  -> PauseManager.DeviceWake()
                                     ↓ applyPauseEvent
                                  Governor
```

## The decisions worth knowing

**QUIESCENT suppresses speculation and keeps liveness.** Provider refresh and UI statistics stop; a
health check and a probe continue. A tunnel whose liveness nobody checks fails silently the moment
the user picks the phone up.

**Traffic does not return the governor to ACTIVE.** A push notification arriving while the phone is
in a pocket forwards one request; returning the whole governor to ACTIVE for it would re-enable
every speculative subsystem at once. Traffic gets its link, the countdown to DEEP_IDLE is disarmed,
and DEEP_IDLE lifts back to QUIESCENT. This is the brief's "wake storm" requirement.

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
