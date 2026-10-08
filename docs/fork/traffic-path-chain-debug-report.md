# Traffic-path chain debug — system proxy → inbound → route → DNS → outbound → remote, and TUN

Audit baseline `6927861bf`, branch `testing`. Every command below was run with
`export GOTOOLCHAIN=go1.25.5` and `TAGS=$(cat release/DEFAULT_BUILD_TAGS)`.

This round did not read the chain, it **ran** it. A new package, `e2e/`, starts real boxes from
real JSON configuration documents, connects real clients to real loopback ports, terminates them at
real far ends, and observes both the bytes that crossed **and** the metadata the router published.
The route decision is captured by an `adapter.ConnectionTracker` appended to the live router - the
same interface the connection manager and the Clash API use - so every assertion is on the
product's own view of a flow rather than on a test double's.

## What the harness is

| Piece | What is real |
| --- | --- |
| Box | `box.New` + `Start` from a JSON document, through the full registry/decode path |
| Inbound | `mixed` (SOCKS5 + HTTP CONNECT + forward proxy + UDP ASSOCIATE) on a real loopback port |
| Client | hand-written SOCKS5 (so ATYP is chosen by the test), hand-written CONNECT, `net/http` with a proxy URL, raw UDP-associate framing |
| Far end | real loopback TCP/UDP/TLS peers; a real SOCKS5 server that records what it was asked for (address form included) |
| DNS | real UDP+TCP DNS responders that log every question, so "which server answered" is measured |
| TUN | `tun.MemoryTun` + the pinned sing-tun Go stack, real IPv4/TCP and IPv4/UDP frames with real checksums |
| Route metadata | `adapter.ConnectionTracker` on the live router: `Destination`, `Domain`, `Protocol`, `Client`, `User`, `DestinationAddresses`, `RouteRule`, `RouteOutbound`, `OutboundChain`, `TrafficClass`, `FakeIP`, `OriginDestination`, `RouteOriginalDestination` |

Files: [`e2e/harness_test.go`](../../e2e/harness_test.go),
[`e2e/system_proxy_chain_test.go`](../../e2e/system_proxy_chain_test.go),
[`e2e/tun_chain_test.go`](../../e2e/tun_chain_test.go),
[`e2e/dns_chain_test.go`](../../e2e/dns_chain_test.go),
[`e2e/route_metadata_chain_test.go`](../../e2e/route_metadata_chain_test.go),
[`e2e/lifecycle_chain_test.go`](../../e2e/lifecycle_chain_test.go). 47 subtests, all green on
`-count=1` and on `-race -count=20`, except where noted below.

## Per-hop result

### System proxy: app → inbound → route → DNS → outbound → remote — **works**

Driven: SOCKS5 to a literal IPv4, to a literal IPv6 (`::1`, ATYP 0x04), and to a **domain**; HTTP
CONNECT to IPv4 and IPv6; a forward-proxy `GET` (`net/http` with `Proxy` configured); a WebSocket
upgrade through the same proxy; a 3-second long-lived TLS connection with ~500 request/response
rounds; SOCKS5 UDP ASSOCIATE; 16 concurrent CONNECTs; repeat passes.

Observed and asserted, at the far end and in the metadata:

- a domain destination reaches the remote node **as a domain** (`atyp=3 forwarded.test:PORT`), i.e.
  it is not resolved locally;
- `direct` traffic never reaches the remote node (the sink's own request log is the evidence);
- rule order: two rules naming one domain, the first wins;
- a CIDR rule that cannot match does not overmatch;
- the sniffed SNI selects the outbound (`Protocol: "tls"`, `Domain: "sniffed.test"` from the
  sniffer, since the client connected to an IP) **and does not rewrite the destination** - the
  remote node is asked for the address the client named;
- `action: resolve` publishes `DestinationAddresses` **and** the following CIDR rule then matches on
  it, so the DNS answer really feeds the route decision;
- a wrong password is refused and cannot become an unauthenticated flow;
- `auth_user` rules match on the metadata the inbound authenticated.

### TUN: device → Go stack → route → DNS → outbound → remote — **works** (except the device half)

Driven: real IPv4/TCP and IPv4/UDP frames injected into a `tun.MemoryTun`, the pinned Go stack, and
the live router behind the handler.

- TCP through the tunnel, rule-selected onto a real SOCKS5 outbound, bytes verified at the far end;
- TCP on the final `direct` outbound, with `override_address` measured: it rewrites
  `metadata.Destination` and preserves `metadata.RouteOriginalDestination`;
- UDP through the tunnel: one NAT mapping, a real datagram peer, and the reply written back through
  the device;
- a hijacked DNS query written to the device address, answered by the real responder, and the
  answer written back out of the device;
- **FakeIP across the whole chain**: the device asks, receives a `198.19.x.y` placeholder, opens a
  TCP flow to it, and the flow reaches the far end as the **domain** (`FakeIP: true`,
  `OriginDestination` = the placeholder, `Destination` = the domain);
- a refused dial produces a real RST on the device.

Two engine facts had to be measured rather than assumed, and both are correct behaviour that a test
must respect: the Go engine **drops any frame whose destination is not global unicast**
(`goEngine.dropNonUnicast`), so a TUN test cannot use `127.0.0.1` as a device-side destination - the
rules use `override_address` to reach loopback peers instead; and the engine parks an accepted flow
until the handler reports the outbound handshake.

Not executed: `protocol/tun.Inbound`'s own delegation (which destination is a DNS-hijack
destination, the process/neighbour metadata search) and the device half (a real utun, route table
entry, namespace). See the coverage table.

### DNS — **works**, with one expectation corrected

- Split routing: two real servers, two rules, the answer and each server's own question log agree;
  the query is **not** leaked to the other server.
- Cache: a repeated query is served from cache.
- A network reset **keeps** the answer cache and **purges** the reverse mapping - both halves pinned
  at the chain level.
- Reverse mapping: a connection to a literal address that a previous answer named carries that name
  on the flow (`Domain = revmap.test`), and `ResetNetwork` removes it.
- FakeIP: mapped and unmapped, over the proxy path and over TUN.

### Route selection — **works**

Asserted on metadata rather than on success: `User` from authentication, `OutboundChain` for a
`selector` (`["sel", "remote"]`) and a `loadbalance` group (`["lb", <member>]`), `TrafficClass`
automatic from an AI group tag (`interactive`) and explicit from configuration (`bulk`), and the
`bypass` verdict through the router's own `PreMatch`: `ActionBypass` **with no Port**, which is the
contract sing-tun depends on (`ActionBypass` + `Port` is rewritten back into a userspace flow).

### Lifecycle — **works**, with one defect found (see below)

- `ResetNetwork` while four flows are mid-conversation: returns in ~140µs, every in-flight flow
  reaches a conclusion (survives or fails) within its deadline, and new traffic works immediately.
- Five consecutive resets under traffic: no accumulation, traffic still works.
- `TrimMemory` with an active flow: the **same** connection still echoes afterwards and a new one
  can be created - the trim does not kill active flows.
- `Close` under 32 busy connections: returns without error, every connection fails rather than
  hangs, the listener is gone (no resurrection), and a repeated `Close` is a no-op.
- Five full start/close cycles: goroutine count flat (baseline 5, after each cycle 5).

## Defects found

### D1 — a connection made just after `Start` is sometimes cancelled as a network change

**Symptom.** The first SOCKS5 request through a freshly started box fails with reply code `0x01`,
and the box's own log says:

```text
connection: open connection to 127.0.0.1:51702 using outbound/direct[direct]:
  dial 127.0.0.1: network changed while dialling
```

**Reproduction.**

```bash
go test -race -count=20 -tags "$(cat release/DEFAULT_BUILD_TAGS)" ./e2e/
```

Observed: **2 of 20** iterations without `-race`, and **both** `-race -count=20` runs - once with a
single lifecycle subtest failing, once with four failing at once on their first dial. In the same
window, `TestDNSSplitRouting/split_rule_selects_secondary` twice timed out after 15s waiting for the
first hijacked DNS answer, which is the same signature one layer up (a failed exchange writes no
response).

**What is certain.** The error string has exactly one source: `common/dialer`'s epoch guard
(`default.go`, `errNetworkChanged`), which captures `(epoch, settled)` when a dial *starts* and
refuses the connection when the network was unsettled then, or the epoch moved while the dial was in
flight. That contract is deliberate and correct - it is what stops a dial begun on the old network
from being handed over on the new one.

**What is not established.** What advances the epoch, or clears the settled flag, in that window.
The leading hypothesis, with one supporting measurement:

- `route/network_environment.go` publishes the first network-environment fingerprint
  asynchronously (`updateEnvironment` → `beginTransition`), so that transition can land **after**
  `Box.Start` returns;
- a probe on a box whose `Start` has just returned reads the transition snapshot and sees
  **epoch 1, settled true** - epoch 1, not 0, because the startup transition already claimed one.
  Under a loaded scheduler it can complete late enough to catch the first dial.

The hypothesis is *not* proven: the flake never reproduced in isolation (240 consecutive box starts,
60 DNS iterations, all passing), and one probe run of the full package passed 20/20, so the trigger
is timing-dependent in a way this environment does not let me pin down further. It is reported as an
**unresolved intermittent defect with a confirmed layer and a confirmed symptom**, not as a
diagnosed root cause.

**Ownership.** Not this suite's to fix, and not touched: the startup transition lives in
`route/network*.go` (Apple lifecycle agent) and the guard in `common/dialer`. Two candidate fixes,
for the owner to choose: publish the initial environment before `Start` returns, or treat a dial that
began before the **first** transition as not crossing a network change (there was no previous
network to leave).

**Regression test added.** `TestFirstDialAfterStartIsNotCancelled`
([`e2e/lifecycle_chain_test.go`](../../e2e/lifecycle_chain_test.go)) dials immediately after `Start`
with nothing in between and asserts success, with no retry, so it fails whenever the window opens
and becomes the gate for the fix.

### D2 — a policy-rejected destination is announced to the client as established

Measured, in both dialects, with a controlled A/B for the SOCKS5 half:

| configuration | SOCKS5 reply | HTTP CONNECT status |
| --- | --- | --- |
| no sniff rule | `0x01` general failure | `200 Connection established` |
| with `{"action":"sniff"}` | **`0x00` success** | `200 Connection established` |

Both mechanisms are **inherited from upstream, not fork regressions**, verified against the
upstream sources:

- `SagerNet/sing`'s `LazyConn` writes the success reply on the first read **or** write of the
  connection, and a sniff rule peeks the stream before the router decides - so enabling sniffing,
  which every real configuration does, commits the reply before any rule has run;
- `transport/http/server_conn.go` `serveConnect` writes `200 Connection established` *before*
  `handler.NewConnectionEx`, and upstream `sing/protocol/http/handshake.go` is identical.

The invariant that holds in every configuration is asserted and passes: **a rejected destination is
never dialled and nothing egresses.**

`TestRejectReplyCode` pins the measured values with an explicit comment that the contract is *not*
met, so a fix flips one line and the test is its regression test. Ownership: `protocol/**`
(tech-debt agent). Fixing the HTTP half means deferring the 200 behind an `N.HandshakeSuccess`
wrapper on the connection handed to the route layer - the mechanism SOCKS already uses - and it
would diverge from upstream for the naive/anytls/masque inbounds too.

## Corrections to previously recorded expectations

- **"A cached answer must not cross a network generation" is not what this product does.**
  `ResetNetwork` advances the generation, resets the transports and purges the reverse mapping, but
  it does **not** clear the DNS answer cache. That is upstream policy ("Avoid clearing DNS caches
  during network resets"), pinned in `dns/reset_ordering_window_test.go`; the generation guard
  governs what may be **written**, not what may be **read**. `TestDNSSplitRouting` pins both halves
  at the chain level: the answer cache survives a reset, the reverse mapping does not.
- **The `client` rule has no HTTP source.** Only the QUIC and SSH sniffers populate
  `metadata.Client`; `common/sniff/http.go` is byte-identical to upstream and does not read
  `User-Agent`. Pinned in `TestRouteSelectionMetadata/client_rule_has_no_http_source` by two rules
  naming one domain, where only the first needs `client` - so the rule that matched *is* the
  measurement. Not a regression; worth knowing before anyone writes a `client: ["curl"]` rule.
- **`protocol/socks` and `mixed` hand-rolled request framing is not required for a domain rule to
  match**: `metadata.Domain` is the *sniffed* domain and stays empty for an unsniffed flow; the
  domain conditions fall back to the FQDN destination. Asserted in both directions.

## Coverage honesty

| Hop | Status | Evidence / reason |
| --- | --- | --- |
| Listener binding (mixed) | VERIFIED-END-TO-END | real client connects to a real loopback port |
| SOCKS5 handshake, no-auth, user/pass, failure | VERIFIED-END-TO-END | hand-written client; wrong password refused |
| HTTP CONNECT (v4, v6, IP target, hostname target) | VERIFIED-END-TO-END | hand-written CONNECT + real TLS inside the tunnel |
| HTTP forward proxy (`GET` absolute-form) | VERIFIED-END-TO-END | `net/http` with `Proxy`; origin received the request |
| WebSocket upgrade through the proxy | VERIFIED-END-TO-END | 101 + three echo rounds over the upgraded tunnel |
| TLS long connection | VERIFIED-END-TO-END | 3s, ~500 rounds, real handshake verified against a real cert |
| IPv6 destinations | VERIFIED-END-TO-END | SOCKS5 ATYP 4 and `CONNECT [::1]:port`, both reaching a `[::1]` peer |
| Bypass / direct fast path | VERIFIED-END-TO-END (control plane) | `adapter.JudgeFlow` → `router.PreMatch` → `ActionBypass`, no Port. The *data plane* consequence (the platform carrying the flow) is UNIT-ONLY: `protocol/tun/native_bypass_trace_test.go` drives it over an in-memory TUN |
| UDP through the proxy (UDP ASSOCIATE) | VERIFIED-END-TO-END | real datagram peer; flow metadata `udp` |
| UDP through TUN | VERIFIED-END-TO-END | memory TUN, real datagrams both ways |
| DNS split routing | VERIFIED-END-TO-END | two real UDP servers, question logs compared |
| DNS cache / reset semantics | VERIFIED-END-TO-END | measured at the chain level |
| DNS reverse mapping | VERIFIED-END-TO-END | literal destination carries the previously answered name |
| FakeIP mapping / unmapping | VERIFIED-END-TO-END | proxy path and TUN path, placeholder → domain at the far end |
| DNS over TCP | UNIT-ONLY | the responders serve TCP, but no scenario drove a TCP DNS query end to end |
| Route rule order, domain/protocol/user rules | VERIFIED-END-TO-END | asserted on `RouteRule` + the far end's log |
| `client` rule | UNIT-ONLY (pinned) | no HTTP source exists; QUIC/SSH sniffers own the field |
| Group chains (selector, loadbalance) | VERIFIED-END-TO-END | `OutboundChain` names group and leaf; the leaf really dialled |
| `urltest` group | **UNVERIFIED** | needs a live health-check URL and background probing; not driven |
| Traffic class (auto + explicit) | VERIFIED-END-TO-END | asserted on the flow's `TrafficClass` |
| TUN packet path (TCP/UDP/DNS/FakeIP/RST) | VERIFIED-END-TO-END **except** `protocol/tun.Inbound`'s delegation and the device | real frames, real stack, live router. The handler is a documented stand-in for the Inbound's delegation because the real one cannot be built without a device |
| Real TUN device, route table, namespace | **UNVERIFIED — DEVICE-ONLY** | needs root and a second interface; the Linux binary cannot be run here. Procedure: `docs/fork/real-tun-validation.md` |
| Network reset during traffic | VERIFIED-END-TO-END | bounded, flows conclude, new traffic works |
| `TrimMemory` with an active flow | VERIFIED-END-TO-END | the same connection survives and still echoes |
| `Close` under load / idempotence / no resurrection | VERIFIED-END-TO-END | 32 busy connections, listener gone, repeat Close is a no-op |
| Goroutine leak over repeated start/close | VERIFIED (bounded) | goroutine count flat over 5 cycles; **not** a full leak detector (no goleak: it is not a dependency of this module and I added none) |
| Screen-off / background / iOS/Android lifecycle | **UNVERIFIED** | needs a device; `pause.Manager` events are not drivable from here |
| WiFi → cellular switching | **UNVERIFIED — DEVICE-ONLY** | the platform interface is absent on this host; only the reset entry point it calls was driven |
| QUIC/HTTP3, MASQUE, WireGuard, REALITY transports | **NOT DRIVEN** | out of this round's scope (other agents own those reports); the outbound used here is SOCKS5 + direct |
| Production server topology (`release/jiejie-production-topology.json`) inbounds | **NOT DRIVEN HERE** | `test/` is a **separate Go module**, so the root `go test ./...` does not run `test/jiejie`, which is where those inbounds are exercised. The module compiles here (`go vet ./jiejie/` is clean) |

## Verification

```text
$ go build -tags "$TAGS" ./...
# github.com/sagernet/sing-box/experimental/boxdd
link: github.com/sagernet/sing-box/experimental/libbox: invalid reference to runtime.fwdSig
BUILD_EXIT=1                      <- the known libbox test-binary link failure, and nothing else

$ go vet -tags "$TAGS" ./e2e/      VET_EXIT=0
$ gofmt -l e2e/ ; gofmt -l .       no output (nothing outside clients/, which is untouched)
$ go mod tidy -diff                clean at HEAD in an isolated checkout of 6927861bf;
                                   the working tree shows a diff in go.sum only, from another
                                   agent's in-flight change - this package adds no requirement

$ go test -count=1 -tags "$TAGS" ./e2e/
ok  github.com/sagernet/sing-box/e2e   4.370s

$ go test -race -count=20 -tags "$TAGS" ./e2e/
green except D1 (2 of 2 runs); every other subtest passed at every repetition

$ go test -count=1 -tags "$TAGS" ./...
ok    github.com/sagernet/sing-box/e2e          4.370s
FAIL  github.com/sagernet/sing-box/experimental/libbox [build failed]   known (runtime.fwdSig)
FAIL  github.com/sagernet/sing-box/route  TestTheGovernorDrivesTheManagerThroughARealBoundary
```

**Classification of the two failures in the working tree.**

- `experimental/libbox [build failed]` - the documented, pre-existing link failure of that
  package's test binary on this toolchain. It is the only acceptable build failure.
- `route.TestTheGovernorDrivesTheManagerThroughARealBoundary` - **not mine, and not the baseline's**:
  the same test passes in a full `./route/` package run at pristine `6927861bf`, fails only in the
  working tree (twice, with `observed=[{Epoch:1 Sleep:30s Known:true Action:retire}] retires=0`),
  passes when run alone in either tree, and passed again on two consecutive re-runs of the whole
  package afterwards. `route/reference.go` and `route/route.go` are modified in the tree by another
  agent; the failure appeared and disappeared with their edits. It is recorded here as a
  concurrent-edit artefact, not as a baseline defect - but it is a real intermittent failure of that
  test under the package's own ordering and the owner may want it checked before the tree settles.

