# Every periodic timer in the core, and what the power governor does about it

The brief asks for this classification explicitly, and it is worth having in one place rather than
in the head of whoever did it. It is also a correction: an earlier pass put several of these in an
"already handled" column without checking, and one of them - the remote rule-set refresh - turned out
to have a stored-but-unused pause manager and no gating at all.

The sweep is every `time.NewTicker`, `time.NewTimer` and `time.AfterFunc` in the tree, excluding
`clients/` and the benchmark harnesses.

## Gated by the governor

| Where | Why it is deferrable |
| --- | --- |
| `service/ssmapi/server.go` | Writes traffic totals on a 1-minute ticker. The totals change slowly and the scope saves on close, so a pause costs at most the minutes since it. |
| `route/rule/rule_set_updater.go` | Remote rule-set refresh. Periodic and deferrable: the rules are stale by at most one pause. The FIRST pass is deliberately not deferred - routing needs the rules before the tunnel is usable. |

## Already pause-aware, or already event-driven

| Where | Why no change is needed |
| --- | --- |
| `protocol/group/urltest.go` | Uses `pause.RegisterTicker`, which stops on device or network pause and resets on wake. |
| `experimental/clashapi/*` | The tickers live INSIDE request handlers - traffic, memory and connection streams. They end with the connection, and a backgrounded app has already ended it. |
| `service/api/web_bridge_websocket.go` | Same shape: the ping runs for as long as its WebSocket does. |
| `service/ccm`, `service/ocm` usage saves | Event-driven, not periodic. `scheduleSave` is called when usage changes and debounces to at most one save a minute; with no activity nothing is scheduled, so a sleeping device is not woken. An earlier note of mine called this a 1-minute ticker, which was wrong. |
| `common/networkquality`, `protocol/tailscale/ping.go`, `daemon/started_service.go` streams | User-triggered or client-scoped. They run because somebody asked. |
| `internal/memmetrics` | A benchmark instrument. Its 1ms `DefaultSampleInterval` looks alarming in a naive grep and nothing in production starts it. |

## Deliberately NOT gated, with reasons

| Where | Why |
| --- | --- |
| `service/oomkiller/timer.go` | A 100ms self-rescheduling poll, and the most tempting target in the list. It is a memory-pressure WATCHDOG, not speculation: if it stops, nothing closes the connections that are driving the process toward the limit, and the thing that eventually acts is iOS killing the tunnel outright. Deferring a safety mechanism to save wakeups is a trade this brief does not permit, and the honest fix if it is wanted is a slower cadence or an event-driven trigger from the allocator - not suppression by sleep state. |
| `experimental/cachefile/dns_cache.go` | Hourly (`optimisticTimeout/2`, else 1h). Skipping it risks never cleaning the cache at all, and the saving is one wakeup an hour. |
| `protocol/*`, `common/dialer/*`, `transport/*` timers | One-shot correctness timers: handshake timeouts, fallback delays, retransmission, dual-stack grace. The brief names these as must-not-pause. |
| `common/trafficsched/scheduler.go` | Pacing for an active flow. It only runs while there is traffic to pace, which is the opposite of idle. |

## What this leaves

Nothing in this list is both periodic, long-lived and speculative, apart from the two now gated. The
remaining coverage gap is not a timer: it is the keepalive, which has its own note - see
`power-keepalive.md`.
