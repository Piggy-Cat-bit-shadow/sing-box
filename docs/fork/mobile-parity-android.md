# Mobile parity — Android

Auditing which iOS/tvOS/NetworkExtension optimisations are *mobile* optimisations rather than
*Apple* ones, and porting the invariant rather than the API. The engineering record, including what
was not decided and why, is `mobile-parity-android-report.md`.

## 1. The dividing line

The useful question is not "does Android have this API". It is: **is the policy in core, and is only
the signal platform-specific?**

Almost everything turned out to be already on the right side of that line. The memory policy, the
network generation, the trim chain, the background-probe marker and the idle-resource rules all live
in core and are platform-neutral, so Android was already receiving them. What was Apple-specific was
the **signal source** — Darwin's memory-pressure dispatch source — and one **compile-time geometry**
tag, which Android now ships on measured evidence.

The four things Android actually gained: the platform event API, the trim-level mapping, the
lifecycle axes, and the low-memory geometry. Everything else was already shared or already
equivalent.

## 2. Build-tag layering

The Android libbox builder composed its tags from `applebuildtags`. An Apple-named package was the
source of truth for Android.

| Layer | Owner | Content |
| --- | --- | --- |
| A · shared mobile | `cmd/internal/mobilebuildtags` | the 25 feature tags both platforms ship |
| B · Darwin-only | *empty* | nothing is genuinely Darwin-only today |
| C · Android-only | *empty* | gVisor was retired; no empty shell was created |
| D · mobile geometry | `cmd/internal/mobilebuildtags` | `with_low_memory` |

`applebuildtags` keeps the genuinely Apple material (platform table, deployment tag sets, the
gomobile `-tags-not-macos` mechanism) and depends on `mobilebuildtags`, never the reverse, so no
Android composition path can reach an Apple-named package.

Two mislabelled tags moved to the shared layer: `with_dhcp` gates `include/dhcp.go` and `grpcnotrace`
is grpc-go's trace switch. Neither is Darwin-meaningful, and Android already compiled both because the
Apple common set *was* the Android set — so the values did not change, only the label.

**No functional change**, proven rather than asserted: every variant's resolved tag set was frozen
before the refactor, order included, and is asserted byte-identical after.

## 3. Signals, not policy

Android reports facts; core decides.

```
Android OS / app lifecycle          Apple: Darwin memory pressure,
      ↓                                    NetworkExtension lifecycle,
libbox scalar void API                     Apple screen/network state
      ↓                                          ↓
core classification ─────────────────────────────┘
      ↓
TrimMemory  ·  ReleaseMemory  ·  network generation  ·  no-background-wake
```

The libbox API is **scalar and void** — `MemoryTrim(level)`, `SetAppForeground`, `SetScreenOn`,
`ReportDeviceWake`, `Close` — so it adds nothing to the gomobile result-frame risk that the ABI
tripwire already watches. It captures the started service rather than a global "current box", so a
stale callback from an old box resolves to nothing; `Close` is a wait barrier, so it cannot return
while a target call is in flight.

## 4. Trim mapping (provisional)

Derived from documented `ComponentCallbacks2` semantics, **not** device-observed, and labelled that
way until it is.

| Level | Action |
| --- | --- |
| 5 RUNNING_MODERATE | ignore |
| 10 RUNNING_LOW | progressive `TrimMemory` |
| 15 RUNNING_CRITICAL | `ReleaseMemory` (reset-shaped, window-coalesced) |
| 20 UI_HIDDEN | **ignore** — a lifecycle fact, not a memory reading |
| 40 / 60 / 80 background levels | progressive `TrimMemory` |
| unknown | ignore |

`UI_HIDDEN` being ignored is the deliberate one: treating it as pressure is the common advice this
does not follow. `RUNNING_CRITICAL` is the only level documented as "this running process will be
killed", so it is the only one that earns a reset.

No Apple 50 MiB budget is copied and **no process ceiling is invented**. `onTrimMemory` reports the
*system's* state, not this process's budget.

Invariants, enforced by design and test: `TrimMemory` may only make the process smaller; it must not
dial, wake, or kill an active flow; it must never call `ResetNetwork`; repeated identical events
coalesce; events after `Close` are ignored.

## 5. Lifecycle: two axes, not one bool

`screenOn` and `appForeground` are independent facts.

- **Screen off** → device-pause axis (the same signal Apple's NetworkExtension sleep drives). Active
  flows preserved; idle expensive resources eligible; a background health round cannot wake a
  suspended endpoint; WireGuard does not run a recovery storm.
- **Screen on** → nudges **only if the app is in front**; otherwise the nudge is *deferred* and
  released once when it is. Mark eligible, rebuild lazily on demand — screen-on never reconnects
  every endpoint.
- **App background alone never pauses.** A VPN must keep carrying other apps' traffic.
- **Real traffic always wakes.**

## 6. Handover

No new debounce was needed, which is the useful finding: eight identical `ConnectivityManager`
callbacks already produce **exactly one** transition delivery, and a burst during an in-flight reset
advances the generation **exactly once** while a genuine change afterwards advances it exactly once
more. Monotonicity holds inside the burst.

The offline edge is deliberately **not** deduped, because coalescing there would swallow the
restoration.

## 7. Expensive / constrained networks

Android sources confirmed and already wired: `Expensive` from metered / default-expensive,
`Constrained` from restricted / Data-Saver. They are consumed **only** by operator-written rule items
and are not part of the environment fingerprint, so a metering change cannot claim a generation and
**metered never moves the user's foreground traffic**.

## 8. Trim targets

The full inventory lives in the report. The shape:

- **Already shared, so Android gets them free**: the DNS pools, DoH2, XHTTP XMUX, the QUIC/gRPC/sing-mux
  pools, the reference-manager chain, and (after this round) `ManagedTransport`.
- **Correctly *not* trimmable**: URLTest history, FakeIP and rule-set caches. Clearing any of them
  forces a re-probe, a reload fetch, or breaks an active flow's routing — "no trim path" is the right
  answer there, not a gap.
- **Real gaps, reported**: DoQ and DoH3 implement only `Reset` — no idle-only trim — on *either*
  platform. That is a core gap, so fixing it benefits both.
- **A different architecture**: TUN is trimmed by a *pull* pressure gauge
  (`oomKiller.MemoryPressure` → sing-tun's slab pool), not by the `TrimMemory` call.
- **Cronet/Naive: DEFER.** One engine per naive outbound, and `engineCount = insecure_concurrency`
  (1 on iOS). Cross-outbound sharing is unsafe (per-client auth, authority, ECH, QUIC policy). The
  in-outbound collapse already exists as `insecure_concurrency_single_engine`, and its default flip is
  recorded in the repo as awaiting a measured A/B with a real server.

## 9. What is not ported

Darwin `dispatch_source` · `os_proc_available_memory` semantics · NetworkExtension's 50 MiB budget ·
Apple entitlements · Apple screen APIs · Apple signing and build behaviour.

What *is* ported: the invariant, the policy, resource ownership, the low-memory geometry, and the
event semantics.
