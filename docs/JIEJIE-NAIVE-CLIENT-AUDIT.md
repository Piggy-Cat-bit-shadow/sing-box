# Naive client audit

Analysis, changes and measurements for the Naive outbound on macOS. Anything that
requires a live Naive server is labelled **NOT TESTED** with the reason and the
harness needed to close it, rather than estimated.

Environment for measurements: `Apple M1`, `darwin/arm64`, `go1.25.5`,
`github.com/sagernet/cronet-go v0.0.0-20260926101438-c3902ec13951`.

---

## 1. The server-only HTTP/3 linkage was removed

### What was there

`include/quic_client_macos.go` imported `protocol/naive/quic`:

```go
_ "github.com/sagernet/sing-box/protocol/naive/quic"
```

That package does exactly two things, both in `init()`:

```go
naive.ConfigureHTTP3ListenerFunc = func(...) {   // qtls.ListenEarly + http3.Server
    ...
}
naive.WrapError = qtls.WrapError
```

Both are **server-side**:

- `ConfigureHTTP3ListenerFunc` is called only from `protocol/naive/inbound.go`.
- `WrapError` is used only from `protocol/naive/inbound_conn.go`.

The macOS client is outbound-only. It registers no `naive` inbound (the registry
audit asserts this), and its Naive outbound goes through
`cronet.NewNaiveClient`. So the import linked a complete HTTP/3 **server listener
stack** into a binary that could never call it.

### Measured effect

darwin/arm64, macOS Lite tag set, `-trimpath -buildvcs=false`:

```text
naive/quic linked symbols            15  →  0
naive.ConfigureHTTP3ListenerFunc   present → absent
naive.WrapError                    present → absent
sing-quic.WrapError                present → absent
total symbols                    69,365 → 69,348
binary size        58,433,746 B → 58,432,354 B   (-1,392 B, -0.002%)
```

**The size delta is small, and that is the honest result.** The HTTP/3 listener
stack itself stays in the binary because MASQUE's own `transport/http` H3 server
needs it. What the removal eliminates is the Naive server's `init()` side effects
and its `congestion_meta1`/`congestion_meta2` wiring — 19 symbols, not a dependency
tree.

The value is **correctness**, not bytes: a client profile no longer links a server
it cannot run, and can no longer be re-imported by accident.

### Nothing that matters was lost

| capability | path | status |
|---|---|---|
| Naive outbound over HTTP/2 | `protocol/naive/outbound.go`, `with_naive_outbound` | intact |
| Naive outbound over QUIC/HTTP3 | same outbound, `"quic": true` → Cronet QUIC | intact |
| Cronet | `cronet-go.NewNaiveClient` | intact, 753 symbols |

Verified behaviourally, not by reading source:

```text
lite binary  + type:naive → FATAL: naive outbound is not included in this build,
                            rebuild with -tags with_naive_outbound
naive binary + type:naive → accepted
```

### A build-constraint consequence that had to be fixed

`test/jiejie/jiejie_naive_h3_linked_test.go` defined
`naiveHTTP3Included = true` under `with_quic && !jiejie_server_minimal`. The macOS
client matches both of those, so after this change it would have claimed HTTP/3 was
linked while the package was gone — and the Naive ALPN tests that branch on that
constant would have asserted against a listener that does not exist, failing or
passing vacuously.

The constraint now also excludes `jiejie_client_macos`, and the absent-variant file
mirrors it.

### The audit now asserts this

`scripts/ci/audit-macos-client-registry.sh` checks that
`naive.ConfigureHTTP3ListenerFunc`, `naive.WrapError` and the
`protocol/naive/quic` package are all absent, while the Naive outbound still
resolves. Its symbol greps use `-F`, because Go symbol names contain `(`, `)` and
`*`, which are regex metacharacters — `masque.(*ClientEndpoint)` silently matched
nothing until that was fixed.

---

## 2. Cronet engine strategy: analysis, switch, and an unmeasured A/B

### The mechanism

`cronet-go/naive_client.go`:

```go
singleEngine: config.TestForceSingleEngine || runtime.GOOS == "ios",
...
engineCount := 1
if c.concurrency > 1 && !c.singleEngine {
    engineCount = c.concurrency
}
```

So on macOS, `"insecure_concurrency": 4` starts **four** Cronet engines. Each is a
full Chromium network stack with its own thread pool, socket pools, caches and DNS
layer.

The single-engine path already exists and is what iOS uses — it gets N independent
HTTP/2 sessions through a per-pool header instead:

```go
streamEngine := c.streamEngines[0]
if c.concurrency > 1 {
    concurrencyIndex := int(c.counter.Add(1) % uint64(c.concurrency))
    if len(c.streamEngines) > 1 {
        streamEngine = c.streamEngines[concurrencyIndex]
    } else {
        headers["-network-isolation-key"] = "https://pool-<i>:443"
    }
}
```

### What was changed

sing-box exposed no way to reach that shape: `TestForceSingleEngine` was never
passed. Added `insecure_concurrency_single_engine` (default **false**), forwarded to
`cronet.NaiveClientOptions.TestForceSingleEngine`.

The default is **unchanged** on purpose. Single-engine moves traffic to a different
Chromium code path, so it is a behaviour change rather than a pure resource change,
and the task was to measure before considering a flip. The switch is what makes the
measurement possible.

The switch is independent of `insecure_concurrency` rather than derived from it: a
plausible mistake would be to treat `concurrency > 1` as "use one engine", which
would make the concurrency setting meaningless. `concurrency` sets how many isolated
pools exist; the switch sets how many engines back them.

### NOT TESTED: the A/B itself

The comparison cannot be made here. It needs a live Naive server on a real network,
which this environment does not have.

**Required measurements, none of which were taken:**

| metric | variant A (N engines) | variant B (1 engine + N keys) |
|---|---|---|
| RSS | NOT TESTED | NOT TESTED |
| private memory (`footprint`) | NOT TESTED | NOT TESTED |
| peak memory | NOT TESTED | NOT TESTED |
| thread count | NOT TESTED | NOT TESTED |
| FD count | NOT TESTED | NOT TESTED |
| startup latency | NOT TESTED | NOT TESTED |
| first request latency (end-to-end, NOT CONNECT alone) | NOT TESTED | NOT TESTED |
| 1 / 4 / 8 / 16 stream throughput (single batch) | NOT TESTED | NOT TESTED |
| per-batch transfer failures | NOT TESTED | NOT TESTED |
| Cronet engine / H2 session / pool count | NOT DIRECTLY VERIFIED | NOT DIRECTLY VERIFIED |
| long-running stability | NOT TESTED | NOT TESTED |
| reconnect after network change | NOT TESTED | NOT TESTED |
| CPU % | NOT TESTED | NOT TESTED |

A loopback or stub server would produce numbers for every row and they would be
meaningless: no RTT, no loss and no BDP, which is exactly what the two shapes differ
on.

**The harness is committed so the measurement is reproducible when a server is
available:**

```bash
./scripts/ci/bench-naive-cronet-engine.sh <naive_server_host> [port]
```

It builds both variants from identical tags (only the config value differs, so any
difference is attributable to the engine layout), then reports the table above. Run
without a server it prints **NOT TESTED** and exits 0 — it does not fabricate
figures.

**Decision rule, recorded in advance so it cannot be fitted to the result:** adopt
single-engine as the macOS default only if throughput and first-request latency show
no meaningful regression **and** the session count still reaches
`insecure_concurrency`. Resource savings alone are not sufficient, because the point
of `insecure_concurrency` is connection isolation.

> ### Session/pool isolation: NOT DIRECTLY VERIFIED
>
> The harness does **not** observe the Cronet engine count, the HTTP/2 session count,
> the network isolation keys, or the connection pool count. There is no API available
> to it that reports those, so the second half of the decision rule above is
> **unverified by measurement**.
>
> What the harness does report is the *inputs* the isolation depends on: the
> `insecure_concurrency` and `insecure_concurrency_single_engine` values actually
> passed to the build, and the `-network-isolation-key` construction at
> `cronet-go/naive_client.go` (section above). That is a code-path claim, not an
> observation.
>
> **Do not read a favourable throughput row as evidence that session isolation holds.**
> Adopting single-engine requires either an observable session signal or a separate
> verification; the decision rule cannot be satisfied by this harness alone.

---

## 3. HTTP/2 receive window: the default is 128 MiB

`cronet-go/naive_client.go`:

```go
receiveWindow := c.receiveWindow
if receiveWindow == 0 {
    if runtime.GOOS == "ios" {
        receiveWindow = 4 * 1024 * 1024
    } else {
        receiveWindow = 128 * 1024 * 1024
    }
}
paramsError = params.SetHTTP2Options(receiveWindow, receiveWindow/2)
```

So the macOS default stream receive window is **128 MiB**, and the connection window
is half of it.

This is a **ceiling, not an allocation**: Chromium's flow control grows the window
as the bandwidth-delay product requires and does not reserve it up front. That is
why the large default is not automatically a memory problem — and also why "smaller
must be better" is not automatically true.

`stream_receive_window` was already configurable, so the sweep needed no code
change.

### NOT TESTED: the sweep

Comparing 4 MiB against 128 MiB is only meaningful when the path's BDP is large
enough that a small window would actually bind. On a loopback or a short-RTT LAN
every value looks identical and the sweep proves nothing.

**Required, none taken:**

```text
size      single-stream   multi-stream   RSS   latency   stalls   flow-control
 4 MiB      NOT TESTED     NOT TESTED     ...   ...       ...      ...
 8 MiB      NOT TESTED     NOT TESTED
16 MiB      NOT TESTED     NOT TESTED
32 MiB      NOT TESTED     NOT TESTED
64 MiB      NOT TESTED     NOT TESTED
128 MiB     NOT TESTED     NOT TESTED     (current default)
```

Harness:

```bash
BENCH_URL=https://<server>/large-object \
  ./scripts/ci/bench-naive-receive-window.sh <naive_server_host> [port]
```

Decision rule: if throughput is flat from 32 or 64 MiB upward, 128 MiB buys nothing
and a lower default would bound per-connection memory at no cost. If 128 MiB is
measurably ahead on a high-BDP path, it stays. Run without a server it reports
**NOT TESTED**.

**No default was changed.**

---

## 3b. SERVER-side HTTP/2 windows (Native Naive inbound): ceilings, not allocations

The production fixture `release/jiejie-production-topology.json` sets the Native Naive
inbound (`inbounds[3]`, tag `naive-in`) to:

| Option | Value |
|---|---|
| `connection_receive_window` | `33554432` (32 MiB) |
| `stream_receive_window` | `8388608` (8 MiB) |

These are applied in `protocol/naive/inbound.go` `http2Server()` and validated by
`validateHTTP2Options`.

### Both windows are flow-control CEILINGS

Setting 32 MiB does **not** allocate 32 MiB. The authoritative evidence is in
`golang.org/x/net v0.57.0`:

- `http2/flow.go` — `inflow` is `struct { avail, unsent int32 }`. Two integers; there is
  no backing buffer anywhere in the type.
- `http2/server.go` — the connection starts at `initialWindowSize`, not at the
  configured value, and the difference is granted as additional *tokens*:

  ```go
  sc.flow.add(initialWindowSize)
  sc.inflow.init(initialWindowSize)
  // Each connection starts with initialWindowSize inflow tokens.
  // If a higher value is configured, we add more tokens.
  if diff := conf.MaxUploadBufferPerConnection - initialWindowSize; diff > 0 {
      sc.sendWindowUpdate(nil, int(diff))
  }
  ```

- Body bytes are buffered only as DATA actually arrives and only if
  `takeInflows(&sc.inflow, &st.inflow, f.Length)` succeeds; the buffer is a `dataBuffer`
  of pooled chunks whose largest size class is 16 KiB, growing on demand. Exceeding the
  window is a protocol error, not an overrun.

**Correction to a previous claim:** an earlier note in this audit described the large
window as a per-connection allocation. That was wrong, and the browser-side section
above already states the opposite for Chromium. Both sides are ceilings.

### What is genuinely worth attention

The exposure is real but it is the **connection** window, not the stream window, and it
is the opposite of the naive intuition:

1. **Per-connection buffered body can reach the connection window (32 MiB).** Once DATA
   arrives and the handler (the tunnel) stalls, real `dataBuffer` bytes can accumulate up
   to `connection_receive_window` — and the connection ceiling, not the 8 MiB stream
   ceiling, is the binding term. Lowering `connection_receive_window` is therefore the
   single highest-leverage dial for the 1 GiB memory target. **NOT MEASURED:** no
   benchmark or soak has established the actual steady-state figure on the production
   path.
2. **Stream concurrency IS bounded.** `max_concurrent_streams` is unset, so x/net applies
   `defaultMaxStreams = 250` (`http2/server.go`). A client cannot open unlimited streams.
3. **No connection-count ceiling on this inbound.** The `unauthenticated_limits`
   (`max_concurrent_per_ip = 8`) in the fixture apply to `inbounds[0]`/`[1]`, **not** to
   the naive inbound, which has none. Connection count is bounded only by OS file
   descriptors.
4. **`IdleTimeout` is unset**, so the http2 layer never reaps idle connections.
5. **`ReadIdleTimeout` is unset**, so no health-check ping is sent and dead peers are not
   reaped by ping.
6. **`WriteByteTimeout` is unset**, so a peer that stops reading can block the write path
   indefinitely. Control-frame flooding is still bounded by x/net's
   `maxQueuedControlFrames = 10000`.

Items 3-6 are **observations, not changes**: none of them is touched by this work, and
changing any of them would alter production behaviour and therefore needs its own
measurement and its own decision.

## 4. Naive QUIC windows and congestion control

`quic_congestion_control` for the **Cronet** Naive outbound already existed and
accepts `bbr`, `bbr2`, `cubic`, `reno` (resolved in `protocol/naive/outbound.go` to
the `cronet.QUICCongestionControl*` values). QUIC windows are exposed as
`stream_receive_window` and `quic_session_receive_window`.

Defaults (from cronet-go, `SetQUICOptions`):

```text
stream  receive window   6 MiB
session receive window  15 MiB
```

### NOT TESTED

Comparing `default` / `bbr` / `bbr2` / `cubic` / `reno`, and the QUIC windows, across
the four path classes that matter:

```text
path class        congestion control   stream window   session window
stable clean           NOT TESTED        NOT TESTED      NOT TESTED
high RTT               NOT TESTED        NOT TESTED      NOT TESTED
small loss             NOT TESTED        NOT TESTED      NOT TESTED
burst loss             NOT TESTED        NOT TESTED      NOT TESTED
```

No default was changed. The protocol default stays whatever Cronet selects, which is
the upstream behaviour.

---

## 5. Preserved client optimizations

These predate this work and were **not** dropped during the consolidation. They are
listed so a future change does not silently regress them:

- **early copy-buffer growth** in the Naive inbound connection path
- **HTTP/2 production receive-window tuning**
- **padding and framing correctness** (`audit_padding_test.go`,
  `padding_segmentation_test.go`, `padding_zero_frame_test.go`)
- **flush contract tests** (`audit_flush_contract_test.go`,
  `audit_write_contract_test.go`)
- **H3 guard** (`audit_h3_guard_test.go`) — the nil-constructor decision, asserted in
  both directions
- **ALPN isolation** (`audit_alpn_isolation_test.go`, `jiejie_http_alpn_isolation_test.go`)
- **Cronet version audit** (`audit_cronet_version_test.go`)
- **fuzz tests** (`fuzz_authority_test.go`, `fuzz_padding_test.go`)
- **benchmark infrastructure** (`bench_test.go`, `bench_h2_test.go`)
- **server-side resource bounds** (capsule bounds, stream limits, unauth limiter)

Note that the H3 guard and server-side bounds are server-side concerns that still
matter after consolidation: they live in shared source, and the server profile
depends on them.

---

## Summary

| item | outcome |
|---|---|
| server-only Naive H3 linkage | **removed**, 19 symbols, −1,392 B; correctness win |
| build-constraint consequence | **fixed** in the `naiveHTTP3Included` constant |
| Cronet single-engine switch | **added**, opt-in, default unchanged |
| Cronet single vs multi engine A/B | **NOT TESTED** — harness committed |
| HTTP/2 receive window sweep | **NOT TESTED** — harness committed, default unchanged |
| Naive QUIC CC and window sweep | **NOT TESTED** — default unchanged |
| preserved optimizations | **verified present** |
