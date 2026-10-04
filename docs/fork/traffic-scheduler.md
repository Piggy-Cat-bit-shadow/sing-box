# Upload traffic scheduler

**Fork extension.** Neither `traffic_scheduler` nor `traffic_class` exists in official sing-box. A
configuration that uses either is not loadable by the official client. Both are omitted when unset,
so a configuration that does not use them stays interchangeable in both directions.

## What it is

A shaper for the upload flows sing-box carries in userspace. It is not machine-wide QoS, it is not a
download limit, and it does not see traffic that never enters sing-box.

```json
{
  "route": {
    "traffic_scheduler": {
      "upload_rate": "8 MiB/s"
    }
  }
}
```

## `upload_rate`

The rate the managed upload path is shaped to, applied exactly as written. There is **no hidden
safety factor**: a configured `8 MiB/s` admits `8 MiB/s` of managed upload.

It is **not** the ISP's nominal bandwidth and **not** a ceiling that only applies while interactive
traffic is present. When a rate is configured the shaper runs continuously, for as long as the
process does. That is deliberate: the queue it exists to prevent fills up during idle periods too,
and a pacer that only starts when interactive traffic arrives protects the second request rather
than the first.

Absent, `0`, or an empty `traffic_scheduler` section leaves the scheduler inert: it observes every
managed byte and admits all of them immediately, with no queue, no lock and no timer. A
configuration that does not ask for shaping does not get it.

### Accepted spellings

| Value | Meaning |
| --- | --- |
| `8388608` | bytes per second |
| `"8388608"` | bytes per second |
| `"8 MiB/s"`, `"8MiB"` | binary size unit; the `/s` is decorative, the field is always a rate |
| `"20 MB/s"` | decimal size unit |
| `"20 Mbps"`, `"16000kbps"` | bit unit, converted at 8 bits to the byte |

A negative value, an unknown unit, a fractional value, or a conversion that would overflow `int64`
fails the configuration rather than being accepted and ignored. For a rate limit, a silently ignored
value means the configuration claims a policy the process does not apply.

### What to configure

The rate the path **actually sustains** for uploads, measured rather than quoted. A connection
advertised at 200 Mbit/s uploads considerably less, and a rate above what the path carries keeps the
queue built and buys nothing at all.

Slightly below the measured rate is the intended use, and it is not a safety margin — it is the
mechanism. On the engineering rig, against a link whose capacity was 2.00 MB/s:

| fixed rate | first-request p95 | bulk throughput |
| --- | --- | --- |
| 85% of capacity | **8 ms** | 1.69 MB/s |
| 100% of capacity | 42 ms | 1.99 MB/s |

## What it does to a flow

Only flows whose copy loop is in sing-box are shaped. A flow whose two ends are both
syscall-capable is served by the kernel splice path, and the gate is not installed on it: it could
not delay such a flow, and installing the gate would only remove the fast path.

High-priority traffic (`traffic_class: interactive` / `realtime`, or an automatically recognised AI
tag) is preferred *within* the shaped budget, with a guaranteed floor for everything else. It is not
exempt from the budget — that is deliberate, because a high-priority flow doing bulk work would
otherwise create exactly the queue the shaper exists to remove.

Upload accounting is unaffected: the traffic tracker counts on the inbound read side, where the
scheduler is not, and a destination-side counter is carried across the gate rather than hidden by
it.

## Measuring it

`common/trafficsched/harness` is a manual engineering tool: it runs the production path against a
real link and reports the receiver-visible round trip of a probe alongside aggregate bulk
throughput.

```
# on a host with capacity
go run ./common/trafficsched/harness -listen :9000

# on the machine under test
go run ./common/trafficsched/harness \
    -server HOST:9000 \
    -rate 8MiB/s \
    -bulk 4 \
    -bulk-class normal \
    -idle-gap 5s \
    -duration 20s
```

`-bulk-class high` reproduces the case aggregate shaping exists for: two classes of interactive
traffic competing, which shaping only the NORMAL lane does not cover.

## What was measured, and what is not shipped

The reproducible experiments, with numbers, are in the package documentation at
[`common/trafficsched`](../../common/trafficsched/doc.go). In summary:

- Models that only change **when** a write starts — admission ordering, service slots — move the
  receiver-visible p99 by nothing at all. The bytes delaying an interactive message are already
  inside the sender's kernel buffer, out of userspace's reach.
- Shaping the managed rate does work, and it must cover the high-priority lane as well.
- A write larger than the shaping bucket is charged rather than exempted.
- A **learned** rate is researched and not shipped. The obvious observable — how long a write
  blocked — measures the wait produced by contention, not the rate of the path: on one 2.00 MB/s
  link it reports 1.29 MB/s with one flow and 0.35 MB/s with four, tightly, both times. A prototype
  controller built on it settles at exactly the capacity, where the queue is built. The code is in
  [`adaptive_research_test.go`](../../common/trafficsched/adaptive_research_test.go), is not part of
  the build, and a test fails if it ever becomes reachable.
