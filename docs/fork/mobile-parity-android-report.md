# Mobile parity — Android report

The model is `mobile-parity-android.md`. This is the record: what was ported, what was already shared,
what is Apple-only, what is deferred, and — most importantly — **what was not decided**.

---

## HEADLINE: one decision is NOT made

**Android does not ship `with_low_memory`, and I did not enable it.**

The brief is explicit that the tag must not be enabled on the strength of "phones have less memory",
and must be justified by measurement. The measurement package (`common/bufgeom`) is built, documented
and green, but the benchmark comparison **was still running when this phase closed**. Enabling the tag
without its numbers would be exactly the reasoning the brief forbids, and enabling it is a one-line
change that can be made in minutes once the table exists.

So: geometry is **NOT enabled**, and the reason is "the evidence is not finished", not "it seemed
risky". `common/bufgeom/doc.go` records the confound that makes the measurement non-trivial — the tag
also flips `sing.LowMemory`, which changes which copy loop `copyExtended` enters for sources whose read
waiter needs a copy. Socket sources report `needCopy=false` and take the pooled loop in both
geometries, so the socket benchmarks isolate buffer size; that is a property of those sources, not of
the tag.

Also not finished: the Android **Kotlin client wiring**. The core API and policy are complete and
tested; the app-side calls are specified in §"Device validation" below.

---

## Parity matrix

`portable` column: whether the optimisation is a mobile invariant rather than an Apple API.

| Optimisation | iOS implementation | Platform-independent invariant | Android status before | Portable? | Android now | Regression |
| --- | --- | --- | --- | --- | --- | --- |
| Memory-pressure classification | `service/oomkiller/service_darwin.go` (dispatch source) | pressure → progressive trim → optional reset | **shared** (core classification) | **ALREADY SHARED** | unchanged | `oomkiller` tests |
| `TrimMemory` chain | core | trim only shrinks; no dial/wake/kill | **shared** | **ALREADY SHARED** | + one real bug fixed | `managed_transport_reset_test.go` |
| `ReleaseMemory` | core | reset-shaped, generation-scoped | **shared** | **ALREADY SHARED** | unchanged | route reset matrix |
| Trim signal source | Darwin dispatch | a platform reports a *level* | **missing** | **PORT** | `libbox.PlatformEvents.MemoryTrim` | `platform_events_test.go` |
| Foreground/background | Apple lifecycle | separate axis from screen | **missing** | **PORT** | `SetAppForeground` | `TestPlatformScreenOnDefersTheWakeUntilTheAppIsInFront` |
| Screen state | Apple screen API | separate axis from foreground | **missing** | **PORT** | `SetScreenOn` | same |
| Device wake | `pause.EventDeviceWake` | distinct from network wake | **missing** | **PORT** | `ReportDeviceWake` | `TestPlatformExplicitDeviceWakeIsAuthoritative` |
| Background-probe suppression | core marker | a background probe must not wake | **shared** | **ALREADY SHARED** | verified on the Android chain | `urltest_android_lifecycle_test.go` |
| Network generation | core coordinator | monotonic, one per real change | **shared** | **ALREADY SHARED** | burst proof added | `android_handover_generation_test.go` |
| Handover coalescing | core | don't storm; don't swallow | **already correct** | **ANDROID EQUIVALENT** | proven, no debounce added | `handover_coalescing_test.go` |
| Expensive / constrained | `NetworkInterface` | probe pacing, background suppression | **already wired** | **ALREADY SHARED** | sources confirmed | `TestNetworkInterfaceExpensiveAndConstrainedHaveAndroidSources` |
| Idle pool retirement | core | retire idle only, never a live stream | **shared** | **ALREADY SHARED** | unchanged | per-pool tests |
| Low-memory geometry | `with_low_memory` | halve the steady-state buffer | **absent** | **DEFER** | **not enabled** — see headline | `common/bufgeom` (measurement) |
| MSL / 50 MiB budget | NetworkExtension | — | — | **APPLE ONLY** | not copied | — |
| Darwin dispatch source | `service_darwin.go` | — | — | **APPLE ONLY** | not copied | — |
| Apple screen / entitlement APIs | Apple | — | — | **APPLE ONLY** | not copied | — |
| Cronet idle-engine release | none | release idle native memory | **missing on both** | **DEFER** | reported | — |
| DoQ / DoH3 idle trim | none | trim idle only | **missing on both** | **DEFER** | reported | — |

### Absorption rate

```
portable mobile optimisations audited   17
already shared (core, Android free)      8
ported to Android this round             4
Android-equivalent (different mechanism) 1
Apple-only, not portable                 3
deferred with a reason                   2  (low-memory geometry, Cronet/DoQ/DoH3 trim)
```

Nothing was ported to make a number look better, and nothing portable was left unported for
convenience.

---

## 13. Goroutines and timers

**New permanent goroutines: none. New permanent timers: none.**

Proven structurally rather than by a gauge, because Go exposes no timer count: a source tripwire
parses `common/runtimecoord/platform_events.go` and fails on any `go` statement or
`time.AfterFunc`/`NewTimer`/`NewTicker`/`Tick`/`After`/`Sleep`. `runtime.NumGoroutine()` is also
checked before and after the stress run.

---

## 14. Trim-target inventory (summary)

Full per-component table in the working record. The properties that matter:

- Exactly **one** invariant violation was found across 15 components, and it is fixed: see §15.
- Every other pool upholds "must not kill an active flow" **structurally**, via a live-usage counter
  (`sharedUsers`/`waiters`, `openUsage`, `session.streams`, `streams==0`) rather than by guessing.
- "Must not wake" holds because trim never calls `SetKeepIdleConnections(false)` — the only
  suspend/wake verb — and the wake paths are demand- or explicit-pause-driven, with a background probe
  explicitly refused.
- **Correct by omission, not gaps**: URLTest history, FakeIP and rule-set caches have no trim path and
  must not get one. Clearing URLTest history causes a fresh election (a dial); clearing FakeIP breaks
  an established flow's reverse mapping; clearing rule sets forces a reload fetch (a dial).
- **Real gaps**: DoQ and DoH3 have only `Reset`, so trim cannot reach them on either platform.

## 15. The one violation found and fixed

`ManagedTransport.CloseIdleConnections` was `Reset`'s body minus the cheap rebuild — it swapped the
epoch to nil and retired the old one. A nil epoch is indistinguishable at the next `RoundTrip` from
"nothing built yet", so the factory ran and produced a **second** inner transport while a stream could
still be live on the old epoch. The trim released idle connections and then **built more memory and
more connections than it released**, and discarded the H3 verdict for a network that had not changed.

Fixed by keeping the epoch and closing only its idle connections; `Reset` keeps the swap, which is
where the generation boundary belongs. The pre-existing test could not catch it — it only asserted no
rebuild *across* the call and the rebuild is lazy — so it now asserts the epoch pointer survives and
the request *after* the trim does not rebuild. Red-checked.

## 16. Apple behaviour

**Unchanged.** No Apple file was modified. `applebuildtags` keeps its Apple-only role and gained no
behavioural change; the low-memory geometry still reaches iOS/tvOS and still never reaches macOS,
which is asserted by the frozen goldens and the existing tag-contract checks.

## 17. macOS

**Still does not carry the low-memory geometry.** Frozen in the golden test across all five Apple
platform sets (`ios`, `iossimulator`, `tvos`, `tvossimulator`, `macos`), and the CI contract reads were
verified directly.

Found and fixed along the way: the darwin step in `verify.yml` built with `-tags "$tags,low_memory"`,
but `low_memory` is **not a build tag anywhere** — the geometry tag is `with_low_memory`. That step was
silently building the standard geometry while appearing to verify the low-memory build. It now reads
the tag and fails closed if it comes back empty.

## 18. Race

`-race` green on `common/runtimecoord`, `common/httpclient`, `cmd/internal/mobilebuildtags`,
`cmd/internal/build_libbox`, `cmd/internal/applebuildtags`, `route`, `protocol/group`; and on
`service/oomkiller`, `transport/wireguard`, `experimental/libbox`. The only failure anywhere is the
documented pre-existing race inside the pinned sing-tun `stack_go.go`
(`TestStackDeviceConcurrentStartAndCloseDoNotPanic`), which is byte-identical across the pin bump and
excluded by CI's own race legs.

`-count=20 -race` green on every new test.

## 19. Builds

`gofmt` clean · `go mod tidy -diff` clean · full tagged suite **66 ok** with only the known
pre-existing failures (`common/tlsfragment` — external network; `experimental/libbox` test-binary
`runtime.fwdSig`; `common/trafficsched` timing-sensitive benchmarks, reproduced on a pristine
`git archive HEAD` copy). Android/arm64 libbox builds **without** gVisor; the ABI tripwire passes.

## 20. Device validation plan (what a device must still confirm)

1. **Apply the Kotlin wiring** — nothing else can be validated until this exists:
   `registerComponentCallbacks.onTrimMemory` → `MemoryTrim(level)` off the main thread;
   `ProcessLifecycleOwner`/`ActivityLifecycleCallbacks` → `SetAppForeground`;
   `ACTION_SCREEN_ON/OFF` → `SetScreenOn`; `ACTION_USER_PRESENT` → `ReportDeviceWake`.
   **Decide the device axis deliberately**: either retire `BoxService`'s Doze-driven
   `commandServer.pause()/wake()`, or leave that axis entirely to it. Mixing both desyncs the policy's
   published-state mirror.
2. **Confirm the trim mapping.** The levels are derived from documented semantics; OEM delivery of
   40/60/80 to a foreground `VpnService` is unverified, and `UI_HIDDEN` being ignored should be
   checked against a real background transition.
3. **Idle 30 min, screen off** — expect near-zero dials, zero URLTest wakes, zero reconnects.
4. **Wi-Fi → cellular, cellular → Wi-Fi** — exactly one generation advance per real transition, no
   reconnect storm.
5. **Background/trim under memory pressure** — pool count decreases, dial count unchanged, active
   flows survive.
6. **Realtime traffic** (video call) across a handover, plus long-lived TCP, QUIC and DNS.
7. **Measure RSS/PSS and battery drain using the same observation points as iOS**, so the comparison is
   genuinely parity rather than two different experiments.
8. **Then** run the `with_low_memory` A/B on a device and decide §headline with real numbers.

## Remaining risks

1. **The low-memory decision is open** (headline). It is a small, reversible change waiting on data.
2. **The trim mapping is provisional** and unvalidated on any OEM.
3. **No Kotlin wiring**, so no Android-side end-to-end test exists yet; the core is tested, the app is
   not.
4. **DoQ/DoH3 idle trim** and **Cronet idle release** are reported, not implemented.
5. **Cronet shutdown has two unbounded `Wait()`s** and a discarded `Shutdown()` result, inside the
   dependency. It cannot be measured without a native build and a real Naive server.
6. `insecure_concurrency_single_engine` is in `docs/schema.json` and the option struct but in **no
   configuration doc**, so operators cannot find the one lever that collapses N engines to 1.

## FUTURE CANDIDATES

- Wire `trafficcontrol.Clear()` into trim (sub-200 KB, trim-safe, needs the `route/network.go` owner).
- DoQ/DoH3 idle-only trim, and `CloseIdleConnections` for the naive outbound → `CloseAllConnections`
  (keeps engines, releases connection pools). Both in-package and trim-safe.
- Document `insecure_concurrency_single_engine`, and run the recorded A/B before flipping its default.
