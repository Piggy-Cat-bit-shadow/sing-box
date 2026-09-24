# Jiejie Server Edition — configuration field matrix

This document records, for **every** custom configuration field this fork adds,
whether it is actually implemented. A field is only marked **IMPLEMENTED** when
there is a runtime test that drives the real data path and observes the effect. A
field that is merely parsed successfully is marked **DECODE ONLY**.

This exists because the fork has already shipped two fields that decoded cleanly
and did nothing (`server_profile` and `bbr_profile`), and because an earlier CI
summary claimed data-plane coverage that a schema test did not provide.

Legend:

| Verdict | Meaning |
| --- | --- |
| **IMPLEMENTED** | Decodes, reaches the running component, and a runtime test observes the effect on the real data path. |
| **DECODE ONLY** | Parses and is validated, but no test proves a runtime effect. Must not be presented as working. |
| **N/A** | Not applicable to this build. |

---

## HTTP inbound — resource control (server side)

| Field | Decode | Effective runtime value | Data path | Runtime test | Verdict |
| --- | --- | --- | --- | --- | --- |
| `server_profile` | `option.HTTPInboundOptions` | Fills only unset fields of the inbound's HTTP/2 and QUIC option sets | HTTP/2 server config and QUIC config built by `NewServer` / `NewQUICConfig` | `TestServerProfileReachesHTTP2Server`, `TestServerProfileReachesQUICConfig`, `TestJiejieMinimalServerProfileTakesEffect` | **IMPLEMENTED** |
| `max_header_bytes` | same | Resolved limit, falling back to profile then `UpstreamMaxHeaderBytes` (1 MiB) | `http.Server.MaxHeaderBytes` (HTTP/2) and `http3.Server.MaxHeaderBytes` (HTTP/3) | `TestH3HeaderLimitIsAdvertised`, `TestH2HeaderLimitIsEnforced`, `TestJiejieMinimalServerProfileTakesEffect` | **IMPLEMENTED** |
| `bbr_profile` | same | `congestion_meta2.Profile` selected at listener construction | `ConnContext` → `conn.SetCongestionControl` on the HTTP/3 listener | `TestBBRProfileReachesQUICOptions`, `TestParseBBRProfileAcceptsDependencyProfiles` | **IMPLEMENTED** |
| `unauthenticated_limits` | `UnauthenticatedLimitsOptions` | Per-source-IP token bucket + in-flight counter, released on successful auth | `admitUnauthenticated` / `rejectUnauthenticated` in the shared HTTP handler | `TestUnauthenticatedLimiterDoesNotHitMasqueradeBackend`, `TestJiejieMinimalMASQUEH2/H3UnauthenticatedLimiter` | **IMPLEMENTED** |
| `masquerade` | `Hysteria2Masquerade` | Handler built at inbound construction | `serveAuthFailure`, and `rejectUnauthenticated` for the over-limit case | `TestJiejieMinimalMASQUEH2Masquerade`, `TestJiejieMinimalMASQUEH3Masquerade`, `TestJiejieMinimalAnyTLSFallback` | **IMPLEMENTED** |

### `unauthenticated_limits` sub-fields

Every sub-field below is decoded by `UnauthenticatedLimitsOptions` and reaches
`unauthenticatedLimiter.acquire` on the request path. `requests_per_second`,
`burst`, `max_concurrent_per_ip` and `max_tracked_ips` are all consumed by the
same `acquire` call; `idle_timeout` drives `expireLocked`.

| Field | Default when omitted | Effect on the data path | Runtime test | Verdict |
| --- | --- | --- | --- | --- |
| `enabled` | `false` | When false no limiter is constructed at all, so behaviour is exactly upstream | `TestUnauthenticatedLimiterNotConstructedWhenDisabled` | **IMPLEMENTED** |
| `requests_per_second` | 10 | Token refill rate; `0` disables refill | `TestUnauthenticatedLimiterBurstThenRefill` | **IMPLEMENTED** |
| `burst` | 20 | Token bucket capacity | `TestUnauthenticatedLimiterBurstThenRefill` | **IMPLEMENTED** |
| `max_concurrent_per_ip` | 8 | Holds the slot across the whole masquerade request, so it bounds backend concurrency | `TestUnauthenticatedLimiterConcurrencyPerIP` | **IMPLEMENTED** |
| `idle_timeout` | 10s | Idle entries expire; in-flight ones never do | `TestUnauthenticatedLimiterExpiry`, `TestUnauthenticatedLimiterDoesNotExpireInFlightEntries` | **IMPLEMENTED** |
| `max_tracked_ips` | 4096 | Caps limiter memory; reaching it evicts least-recently-seen idle entries | `TestUnauthenticatedLimiterTrackedIPCap` | **IMPLEMENTED** |
| accounting position | — | Authenticated requests never touch the limiter; only a failed authentication is accounted | `TestAuthenticatedRequestsNeverTouchTheLimiter`, `TestFailedAuthenticationIsAccounted` | **IMPLEMENTED** |
| unauthenticated body bound | 256 KiB (not configurable) | `http.MaxBytesReader` caps the body a failed-auth request can push at the decoy backend | `TestUnauthenticatedBodyIsBounded` | **IMPLEMENTED** |
| expiry amortization | sweep every 256 acquisitions (not configurable) | Keeps `acquire` off an O(tracked IPs) path | `TestUnauthenticatedLimiterDoesNotSweepEveryRequest` | **IMPLEMENTED** |

### `jiejie-balanced-1g` profile values

| Profile field | Value | Runtime test | Verdict |
| --- | --- | --- | --- |
| `max_header_bytes` | 64 KiB | `TestH3HeaderLimitIsAdvertised` | **IMPLEMENTED** |
| `max_concurrent_streams` | 256 | `TestServerProfileReachesQUICConfig` | **IMPLEMENTED** |
| `idle_timeout` | 60s | `TestServerProfileReachesHTTP2Server`, `TestServerProfileReachesQUICConfig` | **IMPLEMENTED** |
| `stream_receive_window` | **not set** | `TestJiejieProfileDoesNotRaiseQUICWindows` | **IMPLEMENTED (as a deliberate non-override)** |
| `connection_receive_window` | **not set** | same | **IMPLEMENTED (as a deliberate non-override)** |
| `keep_alive_period` | **not set** (0 = disabled) | same | **IMPLEMENTED (as a deliberate non-override)** |

The three "not set" rows are intentional. `NewQUICConfig` assigns a configured
receive-window value to **both** the initial and the maximum window, so a profile
value raises the initial window above the quic-go default (2 MiB stream /
10 MiB connection). A keep-alive actively pings idle connections. Neither is
memory-conservative, so the profile leaves all three alone.

---

## AnyTLS inbound

| Field | Decode | Effective runtime value | Data path | Runtime test | Verdict |
| --- | --- | --- | --- | --- | --- |
| `fallback` | `option.AnyTLSInboundOptions` | Upstream sing-anytls `FallbackHandler` | AnyTLS inbound → fallback backend | `TestJiejieMinimalAnyTLSFallback` (ordinary HTTPS and raw TLS clients both reach the decoy) | **IMPLEMENTED** |
| `fallback_for_alpn` | same | Per-ALPN fallback destination map | same | Not covered by a runtime test in this fork; upstream behaviour is untouched. | **DECODE ONLY** |
| `padding_scheme`, `users`, TLS | upstream | upstream | upstream | upstream suites | unchanged upstream |

`server_profile` and `bbr_profile` do not apply to AnyTLS; it is not an HTTP
inbound.

---

## Fields that are rejected rather than ignored

| Field | Where | Behaviour | Test |
| --- | --- | --- | --- |

The inbound shares `QUICOptions` with the outbound, so without an explicit check
these would be accepted and silently change nothing — the same failure mode as the
`server_profile` bug.

---

## Not implemented, and deliberately so

| Item | Status | Reason |
| --- | --- | --- |
| `memory_budget` | **NOT IMPLEMENTED** | A byte-accurate QUIC memory budget cannot be measured honestly on the current quic-go/sing-quic lifecycle. Deterministic limits are used instead. |
| H3 connection-count / per-source connection cap | **NOT IMPLEMENTED** | Would require hooking quic-go's connection acceptance. `max_concurrent_streams` bounds streams *within* a connection and the limiter counts HTTP requests, so neither bounds the number of connections. The documentation states this limitation rather than implying a total bound. |
| Server-side enforcement of `max_header_bytes` over HTTP/3 | **NOT IMPLEMENTED (protocol limitation)** | HTTP/3 carries the limit as `SETTINGS_MAX_FIELD_SECTION_SIZE`; quic-go publishes it but does not police inbound header blocks. The tests assert the advertisement, not a rejection. |

---

## How to re-verify this table

```sh
TAGS=$(cat release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL)

# Server-side fields
go test -tags "$TAGS" -run 'TestServerProfile|TestH3HeaderLimit|TestH2HeaderLimit|TestBBRProfile|TestHTTPServerProfile|TestJiejieProfile' \
  ./option ./transport/http

# Runtime data path in the production build
cd test/jiejie && go test -tags "$TAGS" -run 'TestJiejie|TestProductionBinary' .
```

If a field is added and no runtime test can observe its effect, add it here as
**DECODE ONLY** rather than claiming it works.
