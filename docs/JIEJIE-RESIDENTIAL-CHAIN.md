# Residential SOCKS chain

How the residential chain is built, what may not be changed about it, and the two
optional optimizations this repository adds for it.

## Current production architecture

```text
residential client
  -> AnyTLS            (Residential-AnyTLS: UDP rejected)
  -> US VPS sing-box
       -> resolve ipv4_only          DNS happens HERE, on the VPS
       -> residential-socks          SOCKS5 to the residential provider
  -> residential exit
  -> IPv4 target
```

A second path exists for VLESS:

```text
Residential-VLESS-Reality -> Xray -> residential-socks
```

That one is Xray's data plane and is outside this repository's scope. Nothing here
changes it.

Ordinary AnyTLS is a DIFFERENT path and must not be confused with either:

```text
AnyTLS -> direct -> local-agh -> IPv4 / IPv6 (dual stack)
```

## DNS invariant

**DNS stays on the VPS by design. The residential SOCKS server does not resolve
target domains.**

The chain resolves the destination on the VPS with `strategy: ipv4_only` and then
hands the SOCKS5 proxy an **ADDRESS**:

```text
residential domain
  -> VPS DNS
  -> IPv4
  -> SOCKS5 CONNECT <IPv4>:<port>
```

Not this:

```text
SOCKS5 CONNECT <domain>     # the residential provider would resolve it
```

The ordering is what enforces it. In `release/jiejie-production-topology.json`:

```json
{ "user": ["residential"], "network": ["udp"], "action": "reject" }
{ "user": ["residential"], "network": ["tcp"], "action": "resolve", "strategy": "ipv4_only" }
{ "user": ["residential"], "network": ["tcp"], "outbound": "residential-socks" }
```

The `resolve` rule must come BEFORE the routing rule, because a resolve action
needs the destination to still be a domain. If the routing rule ran first, the
SOCKS proxy would receive a hostname and resolve it itself, moving DNS to the
residential provider.

This is pinned by `TestProductionResidentialChainOrdering` in
`test/contract/serverminimal`, which fails if the rules are reordered, if the
strategy changes, if the residential UDP reject is removed, or if the destination
outbound changes.

There is deliberately **no** remote-DNS mode: no SOCKS5h behaviour, no
"residential DNS", no GeoDNS. Adding one would be a product change, not a tuning
change.

## UDP

Residential UDP stays **rejected**. This is not a limitation to be lifted later by
default: the residential exit is IPv4 TCP only, so a datagram path would either
leak or fail silently. The pool below is TCP CONNECT only and never applies to UDP
ASSOCIATE, BIND or UoT.

## TCP preconnect (opt-in)

SOCKS5 setup - TCP connect, greeting, method negotiation, username/password
authentication - can happen **before** a user request needs it. With the pool
enabled, those connections are established ahead of time and parked in the state
"authenticated, waiting for a command". A user flow then takes one and issues only
its CONNECT.

```json
{
  "type": "socks",
  "tag": "residential-socks",
  "server": "...",
  "server_port": 1080,
  "version": "5",

  "tcp_preconnect": {
    "enabled": true,
    "min_idle": 2,
    "max_idle": 4,
    "idle_timeout": "20s"
  }
}
```

**CONNECT remains per target and single-use.** A SOCKS5 connection carries exactly
one command: once a parked connection has carried a CONNECT it is a tunnel and is
never returned to the pool.

Defaults when the operator enables the pool but omits parameters: `min_idle` 2,
`max_idle` 4, `idle_timeout` 20s. A bare `"enabled": true` therefore yields a small
bounded pool.

`enabled: false`, or omitting the block entirely, means no pool, no goroutine, no
extra socket, and the previous behaviour exactly.

### Behaviour

| Situation | Behaviour |
| --- | --- |
| Pool has a connection | The flow issues only its CONNECT |
| Pool is empty | The cold path runs immediately; the caller never waits for a refill |
| Parked connection is stale | Discarded, and the request falls back to exactly one cold attempt |
| CONNECT already accepted | Not retried: retrying could duplicate an effect |
| Refill keeps failing | Bounded backoff, 500ms doubling to a 30s ceiling, reset on success |
| Connection idle too long | Closed by the pool; no ping is ever written |
| Reload / outbound removed | `Close` stops the loop and closes every parked socket |

Health checking is deliberately limited to a bounded idle lifetime plus error
detection at CONNECT time. After authentication the next frame MUST be a command
request, so a ping or a speculative read would corrupt the connection state.

Pool connections are opened through the outbound's own dialer, so `bind_interface`,
`routing_mark`, `netns`, connect timeout, TCP Fast Open, keepalive, `detour`,
`auto_detect_interface` and socket control all apply exactly as they do to a cold
connection.

## Early copy-buffer growth (opt-in)

```json
"tcp_tuning": { "early_buffer_growth": true }
```

A chained hop carries an extra segment, so waiting for the framework's default
byte threshold before growing the copy buffer delays the point where the larger
buffer pays off. This option lets the route layer grow earlier for connections
through **this** outbound.

It is a capability (`adapter.ConnectionCopyTuner`), not a tag check. A tag is
operator-chosen configuration, so keying on one would make copy behaviour depend on
a naming choice. With a capability, only an outbound that explicitly opted in is
affected, and every other outbound - including every other SOCKS outbound - keeps
`bufio.DefaultIncreaseBufferAfter`.

The route layer consults the dialer that was actually selected for the connection,
so a `selector` / `urltest` resolves to the member that served it rather than to
the group. The Native Naive inbound rule is evaluated first and is unchanged.

## Security and resource properties

| Property | Bound |
| --- | --- |
| Pool size | `max_idle`, including connections still being established |
| Idle lifetime | `idle_timeout` |
| Retry | One cold fallback per request; no loop |
| Refill retry | 500ms doubling to a 30s ceiling |
| Reload | `Close` cancels the loop and closes every parked socket |
| UDP | Never pooled; residential UDP still rejected |
| Credentials | Never logged. The pool records counts and targets, not passwords |

## Evidence

Deterministic tests only. No wall-clock latency is used as a pass/fail condition,
and no real VPS or residential proxy is involved.

**Preconnect pool** (`protocol/socks` in the sing fork, driven by an in-process
counting SOCKS5 server):

| Scenario | Observed |
| --- | --- |
| Disabled | 0 background connections |
| `min_idle: 2` | 2 accepted, 2 greeting, 2 auth, **0 CONNECT** |
| Consume | No re-greet, no re-auth, correct target, not returned to the pool |
| Empty pool | Cold path used immediately |
| Stale connection | Request still succeeds via the cold fallback |
| Idle timeout | Expired connections discarded |
| Bad credentials | Bounded attempts: backoff, not a tight loop |
| `max_idle` | Never exceeded |
| Close | Every socket closed, loop exits, idempotent |

**Copy tuning** (`route`): the capability opts in; reporting false or not
implementing it keeps the default; Native Naive still wins; the selected group
member is what counts.

**Residential DNS contract** (`test/contract/serverminimal`): the fixture's rule
ordering is asserted, and reordering it makes the test fail.

## What is NOT done here

- No DNS rework, and no remote-DNS mode.
- No latency or RTT profiler, and no tracing or timing instrumentation.
- No real-VPS or real-residential-proxy benchmark was run.
- No SOCKS multiplexing, no custom SOCKS extensions, no residential UDP.
- The Xray VLESS path is untouched.
