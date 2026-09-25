# Jiejie VPS benchmark plan

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

CI builds the production binary, runs the server integration suite on loopback,
and enforces a binary size guard. Those are regression signals only. They cannot
tell you what will happen on your VPS, which is why every number below has to be
measured on the real host.

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

## A/B 1 — server profile, unset vs `jiejie-balanced-1g`

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

## A/B 2 — Jiejie minimal build vs a plain upstream build

**Baseline**: `sing-box` built from upstream with `release/DEFAULT_BUILD_TAGS`.
**Candidate**: `sing-box-linux-amd64` from this fork, built with
`release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL`.

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
load; that is the trim working, not a fault.

Procedure:

1. Run the same throughput and latency tests against both.
2. Compare binary size, RSS and CPU.
3. Confirm the production config still passes `sing-box check` on both.

Interpretation:

* The minimal build is roughly half the size. Expect **no throughput difference**;
  the removed components are unregistered optional features, not hot-path code.
* A throughput difference would indicate something unexpected — investigate
  before adopting.
* Keep the previous binary available for rollback.

## A/B 3 — `GOAMD64` default vs `v3`

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

## A/B 4 — `CGO_ENABLED=1` vs `CGO_ENABLED=0`

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

## In-process codec benchmarks: what they measure

`protocol/naive/bench_test.go` contains deterministic micro-benchmarks for the
Padding codec and the headroom helpers. They exist to pin the cost of the codec
itself, not to predict tunnel throughput.

**Read the byte basis, not just ns/op.** A previous version of
`BenchmarkPaddingReadFramed` processed 4096 payloads per iteration while
reporting `SetBytes` for a single payload. The two read benchmarks therefore
had similar ns/op but MB/s differing by roughly 4096x, and the natural
conclusion - "framing is nearly free" - was an artefact of the accounting
rather than a result. The byte basis is now the full stream for both, so they
are directly comparable:

```
BenchmarkPaddingReadFramed-8   200  132415 ns/op  43306.13 MB/s  1408 B/op  1 allocs/op
BenchmarkPaddingReadRaw-8      200  135215 ns/op  42409.51 MB/s  1408 B/op  1 allocs/op
```

Reading the framed path costs about 2% more per byte than the raw path, which is
what one would expect: it parses a 3-byte header and copies the padding window.
The framed benchmark additionally carries 3 header bytes per payload on the wire,
so equal wall time would not imply equal goodput.

Compare these numbers **only against each other on the same machine**. They are
not a throughput claim and they say nothing about a real network path.

## Measured resource cost on Linux (loopback)

Measured on Linux 6.8 (arm64 VM), production tag set
(`with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0`), driving the
Naive inbound in-process. These are **test-process** figures: the test binary
also holds the test framework and the echo servers, so they are a budget check on
the data path, not a measurement of the shipped server.

| Phase | RSS | goroutines | fds | UDP sockets |
| --- | --- | --- | --- | --- |
| idle | 23.3 MiB | 12 | 12 | 1 |
| after 500 churn sessions | 23.8 MiB | 12 | 12 | 1 |
| 8 concurrent TCP tunnels | 24.3 MiB | 12 | 20 | 1 |
| after sustained UDP | 23.2 MiB | 12 | 20 | 1 |
| settled after close | 23.2 MiB | 12 | 12 | 1 |

Over **1000** short-lived sessions: RSS delta -248 KiB, goroutines +0, fds +0,
UDP sockets +0. Descriptors, sockets and goroutines all return to the idle
baseline, so the session path does not leak them.

This is a regression bound, not a capacity plan. `TestJiejieNaiveLinuxResourceBudget`
and `TestJiejieNaiveLinuxSocketAndGoroutineReclaim` enforce it; they SKIP on
non-Linux because they read `/proc`.

## Not measured

- Native Naive versus Caddy throughput on the same host. No fair A/B was run:
  it requires a reproducible Caddy Naive deployment and a client path that both
  can serve identically. **Do not quote a speed-up figure; none was measured.**
- Production RSS of the shipped binary under real client load.
- Peak RSS during a sustained saturating transfer.
