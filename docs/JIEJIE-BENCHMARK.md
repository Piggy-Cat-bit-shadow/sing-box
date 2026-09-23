# Jiejie benchmark plan

This document describes how to A/B the Jiejie Server Edition options on the real
VPS. It exists because CI runner numbers and loopback numbers do **not** predict
throughput on a real path across the public internet.

**Nothing in this fork claims a measured speed-up.** The options are hypotheses
to be tested; the test plan below is how you test them.

## Rules

1. Change **one** variable at a time between runs.
2. Keep the client, the network and the time of day as similar as possible.
3. Run each configuration at least 3 times and compare medians, not single runs.
4. Record raw numbers. Do not round-trip through "it feels faster".
5. Treat any result inside run-to-run noise as "no measurable difference".

## What CI measures (and what it does not)

CI runs `BenchmarkHTTP3Pool1`, `BenchmarkHTTP3Pool2` and pool-selection
microbenchmarks. These are **regression references only**: they run on a shared
runner against a loopback HTTP/3 server. They can detect a gross regression in
the pool code path. They cannot tell you what will happen on your VPS.

## Metrics to record for every run

| Metric | How |
| --- | --- |
| TCP throughput | `iperf3 -c HOST` (and reverse, `-R`) |
| UDP / CONNECT-UDP throughput | `iperf3 -c HOST -u -b 0 -t 30` through the proxy |
| CPU | `pidstat -p $(pidof sing-box) 1 60` or `top -b -d 1` |
| RSS | `ps -o rss= -p $(pidof sing-box)` sampled every second, record peak |
| Goroutines | `curl -s 127.0.0.1:PORT/debug/pprof/goroutine?debug=1 \| head -1` |
| File descriptors | `ls /proc/$(pidof sing-box)/fd \| wc -l`, record peak |
| Packet loss | `mtr -rwzc 100 HOST` |
| RTT | median from `mtr` |
| QUIC connections | count distinct client source ports: `ss -u -a -n \| grep :443 \| wc -l` |
| Latency under load | `ping` while a throughput test runs |

Always sample RSS and FD **during** the load, not only before and after.

## A/B 1 — HTTP/3 connection pool, `size: 1` vs `size: 2`

The primary experiment.

**Baseline client config**

```json
"http3_connection_pool": { "size": 1, "strategy": "round_robin" }
```

**Candidate client config**

```json
"http3_connection_pool": { "size": 2, "strategy": "round_robin" }
```

Procedure:

1. Run a single-stream throughput test (`iperf3 -c HOST`) for both.
2. Run a multi-stream test (`iperf3 -c HOST -P 8`) for both.
3. Run a CONNECT-UDP throughput test for both.
4. Record the server-side QUIC connection count for each.

Interpretation:

* If single-stream throughput is unchanged and multi-stream improves, the pool
  is doing what it is designed to do.
* If nothing changes, keep `size: 1` — it is the simpler, upstream-shaped
  configuration.
* If RSS rises noticeably with no throughput gain, keep `size: 1`.

Do not assume `size: 2` is faster. Two QUIC connections mean two congestion
controllers and more connection state on both ends.

## A/B 2 — fallback backoff, upstream vs Jiejie

The goal is recovery behaviour, not throughput.

**Upstream behaviour**: omit `http3_fallback` (5m, x2, 48h cap).

**Jiejie recommendation**:

```json
"http3_fallback": {
  "initial_backoff": "5s",
  "max_backoff": "5m",
  "multiplier": 2,
  "reset_on_success": true
}
```

Procedure:

1. Establish working HTTP/3.
2. Simulate UDP loss (client-side firewall rule or a temporarily blocked
   UDP/443) for ~30 seconds.
3. Restore UDP.
4. Measure **time until traffic returns to HTTP/3**.

With the upstream schedule the client can stay on HTTP/2 for up to 48 hours.
With the Jiejie schedule it should return within about 5 minutes worst case, and
immediately once a successful HTTP/3 round trip occurs
(`reset_on_success: true`).

Expected result: a large reduction in recovery time. This is a correctness /
UX improvement, not a throughput one.

## A/B 3 — server profile, unset vs `jiejie-balanced-1g`

Measure resource behaviour under load, not speed.

**Baseline**: no `server_profile`.
**Candidate**: `"server_profile": "jiejie-balanced-1g"`.

Procedure:

1. Put the server under sustained HTTP/3 load for 10 minutes.
2. Record peak RSS, peak FD count and goroutine count for both.
3. Also record whether throughput or latency changed.

Interpretation:

* The profile is intended to reduce worst-case resource growth on a 1 GiB VPS.
* If throughput drops materially, the windows are too tight for your path —
  raise `stream_receive_window` / `connection_receive_window` explicitly (an
  explicit value always overrides the profile).
* Watch for `H3_EXCESSIVE_LOAD` appearing in logs; if it does, raise
  `max_concurrent_streams`.

## A/B 4 — full build vs Jiejie build vs Jiejie minimal build

**Baseline**: `sing-box-linux-amd64-full`.
**Candidates**: `sing-box-linux-amd64-jiejie` and
`sing-box-linux-amd64-jiejie-minimal`.

The minimal build registers far fewer protocols, so a useful additional check is
that it still serves the whole production topology. Before any load test, confirm
on the exact binary you intend to deploy:

```sh
sing-box check -c /etc/sing-box/config.json
```

and exercise MASQUE H2/H3 CONNECT and CONNECT-UDP, AnyTLS plus its fallback,
ShadowTLS v3, SS2022, the residential SOCKS outbound and local-AGH resolution.
CI already runs these against `release/jiejie-production-topology.json`, but
verify against your real config before switching production over.

A removed protocol is expected to be *rejected* by the minimal build at config
load; that is the trim working, not a fault. The full and jiejie artifacts remain
available unchanged for rollback.

Procedure:

1. Run the same throughput and latency tests against both.
2. Compare binary size, RSS and CPU.
3. Confirm the production config still passes `sing-box check` on the Jiejie
   build (it is checked in CI against a secret-free fixture).

Interpretation:

* The Jiejie build is roughly half the size. Expect **no throughput difference**;
  the removed components are unregistered optional features, not hot-path code.
* A throughput difference would indicate something unexpected — investigate
  before adopting.
* Keep the full build available as the fallback.

## A/B 5 — `GOAMD64` default vs `v3`

**Baseline**: `sing-box-linux-amd64-jiejie` (GOAMD64 default/`v1`).
**Candidate**: `sing-box-linux-amd64-jiejie-v3`.

First check the host actually supports it:

```sh
lscpu | grep -o -E 'avx2|bmi2|fma|movbe|abm' | sort -u
```

Go's amd64 `v3` requires AVX2 (and the associated feature set). If the output
does not include `avx2`, the `v3` artifact will crash with an illegal
instruction — do not deploy it.

Procedure:

1. Run identical load against both binaries.
2. Compare throughput, CPU and RSS.
3. Note the CPU model, because results are host-specific.

Interpretation:

* Encryption-heavy paths may benefit from AVX2 in Go's assembly.
* If there is no clear, repeatable benefit, **keep the generic build**. The VPS
  host CPU can change under you on migration, and the generic build always runs.

## A/B 6 — `CGO_ENABLED=1` vs `CGO_ENABLED=0`

**Baseline**: `sing-box-linux-amd64-jiejie` (CGO enabled).
**Candidate**: `sing-box-linux-amd64-jiejie-static`.

Procedure:

1. Verify the static artifact was produced and passes `sing-box check`.
2. Run identical load against both.
3. Compare throughput, CPU and RSS.

Interpretation:

* Expect little or no difference for this workload.
* The main benefit is portability (no dynamic loader dependency).
* Keep CGO enabled for production unless the static build shows a clear win or
  you specifically need a static binary.

## Reporting template

```
date:
host / CPU:
kernel:
sing-box version:
config delta:

[throughput]  tcp down:      tcp up:      udp:
[cpu]         mean:          peak:
[rss]         idle:          peak under load:
[fd]          idle:          peak:
[goroutines]  idle:          peak:
[loss]        %:             [rtt] median:
[quic conns]  peak:
verdict:      keep default / adopt candidate / inconclusive
notes:
```

## Decision policy

* Adopt a change only when it is a **repeatable** improvement or a clear
  reliability gain.
* Prefer the default (upstream-shaped) configuration when results are
  inconclusive.
* Re-measure after any upstream rebase, kernel upgrade or VPS migration.
