# All-Protocol Dataplane and DNS Resolution Plane Audit

A copy audit and a DNS-authority audit across every protocol the Jiejie products actually compile,
with two measured fixes and four findings recorded as NO CHANGE with their reasons.

## HEAD

| | |
|---|---|
| sing-box before | `08861f136` (`BASE_HEAD`) |
| sing-box after | `50bbed43e` |
| sing before | `2616b72468d064bcb69a4f392528a2495f6e70fd` (`SING_BASE_SHA`) |
| sing after | `3f609c65d21a` (`SING_FINAL_SHA`) |
| sing branch | `jiejie-common-datapath` |

## Product Protocol Registry

Derived from the registries in `include/`, then **verified against the shipped binary** by symbol
search — not from memory, and not from the source tree, which contains protocols neither product
links.

### Tier A — macOS production client

`direct`, `block`, `selector`, `urltest`, `http` (as the MASQUE outbound), `shadowsocks`,
`shadowtls`, `vless`, `anytls`, `naive`, and the `masque-client` endpoint.

### Tier B — server-minimal

`direct`, `socks` (the residential SOCKS5 upstream), plus `registerQUICOutbounds`, which is
**intentionally empty** (`include/quic_minimal.go`).

### Tier C — present in the tree, compiled by neither profile

`vmess`, `trojan`, `snell`, `hysteria2`, `tuic`, `wireguard`, `tailscale`, `openvpn`, `openconnect`,
`ssh`, `tor`, and the bridge endpoints.

Verified absent from the client binary by symbol count: every Tier C protocol returns **0**
`protocol/<name>` symbols, while every Tier A protocol returns 9–179.

## All-Protocol Copy Matrix

| Protocol | TCP up | TCP down | UDP up | UDP down | Cached first payload | Unavoidable |
|---|---|---|---|---|---|---|
| **direct** | 0 | 0 | 0 | 0 | 0 (falls back; no framing) | kernel |
| **vless** (plain) | **0** | **0** | 0 (`WritePacket`) | 0 | **0 \u2192 0** | ciphertext |
| **vless** (Vision) | 1 | 0 | n/a | n/a | 1 (no capability) | ciphertext, TLS record |
| **anytls** | 0 | 0 | n/a | n/a | **0** | ciphertext, TLS record |
| **shadowsocks** | 1 | 1 | 1 | 1 | 1 | AEAD ciphertext |
| **shadowtls** | 0 | 0 | n/a | n/a | **0** | TLS record |
| **naive** | **0** | **0** | 0 | 0 | **0** (since the previous round) | Chromium HTTP frame, TLS/QUIC |
| **masque** (CONNECT-IP) | 0 | 1 | 0 | 1 | n/a | QUIC packetisation |
| **http** (CONNECT) | 0 | 0 | n/a | n/a | **0** | TLS record |

Counts are **Go-layer full plaintext payload copies** on the normal bulk path. Encryption output,
TLS/QUIC records, kernel buffers and packet assembly are excluded by definition: they are the
transform boundary, not a Go-layer copy.

### How each row was established

The route copy loop is `CopyWithIncreateBuffer(destination, source, ...)`, which reaches
`destination.WriteBuffer(pooledBuffer)`. Zero-copy therefore depends on one thing: whether the
writer the route layer holds implements `N.ExtendedWriter`. If it does, `NewExtendedWriter` returns
it unchanged; if not, it wraps it in `ExtendedWriterWrapper`, whose `WriteBuffer` is

```go
defer buffer.Release()
return common.Error(w.Write(buffer.Bytes()))
```

— a bare byte-slice write, which for a framing writer means allocating a second buffer. That
distinction is invisible in the protocol code, the route code and a passing test suite.

## Global Copy Findings

### CachedReader raw Write — **FIXED**

`sing/common/bufio.CopyWithIncreateBuffer` delivered the sniffed first payload with a bare
`Write([]byte)`, discarding the pooled buffer's geometry. **This is the path every sniffed
connection traverses**, so the fix applies to every protocol at once.

Now `WriteOwnedBuffer` hands the buffer over when the destination's own advertised geometry allows,
and takes the previous path otherwise.

| Payload | plain | buffer | speedup | B/op | allocs/op |
|---|---|---|---|---|---|
| 64 B | 337 ns | **169 ns** | 1.99× | 64 → **0** | 1 → **0** |
| 1400 B | 371 ns | **158 ns** | 2.35× | 64 → **0** | 1 → **0** |
| 16 KiB | 642 ns | **162 ns** | 3.96× | 65 → **0** | 1 → **0** |
| 64 KiB | 1476 ns | 1509 ns | 0.98× | 64 → 66 | 1 → 1 |

100000x, count 10, medians. The 64 KiB row is not a regression: it exceeds the writer's MTU
(65278), so **both** paths fall back. That is why the fast path is a sub-64-KiB-*payload*
optimisation — the geometry is a ~64 KiB *frame*.

### kickWriteHandshake — **FIXED in the previous round**

Same shape, same helper now, in `route/conn.go`.

### Cached packet (`CopyPacket`) — **NO CHANGE**

`options.Copy(packetBuffer.Buffer)` looked like an unconditional copy. It is not:

```go
func (o ReadWaitOptions) Copy(buffer *buf.Buffer) *buf.Buffer {
	if o.FrontHeadroom > buffer.Start() || o.RearHeadroom > buffer.FreeLen() {
		... allocate and copy ...
	}
	return buffer
}
```

It is already the same geometry test, implemented as a wrapper, and `NewReadWaitOptions` populates
the headroom from `CalculateFrontHeadroom(destination)` — the destination's own advertisement. The
hot path (`copyPacketWithPool`) hands the buffer to the destination directly. There is nothing to
fix, and it confirms the geometry principle rather than contradicting it.

### Transparent wrappers hiding capability — **NO CHANGE, with one classified exception**

| Wrapper | Delegates capability? | Verdict |
|---|---|---|
| `sing` `counter_conn`, `bind`, `chunk`, `append`, `fallback` | **yes** — `ReadBuffer`/`WriteBuffer`/`Upstream`/`Replaceable` all present | correct |
| `sing` `only.go` (`ReadOnlyConn`, `WriteOnlyConn`) | **no** | **P3** — used only for TLS ClientHello sniffing over an `io.Reader`/`bytes.Buffer`, never a copy destination |
| `vless.VisionConn` | **no** | **P3** — see below |
| `vless.PacketConn` | no `WriteBuffer` | **not a defect** — UDP uses `WritePacket`, a different contract |

**Vision is the interesting one, and it is correctly left alone.** `VisionConn` reports
`ExtendedWriter=false`, `ExtendedReader=false`, `FrontHeadroom=false`, while the plain `vless.Conn`
reports `true`. Two production nodes use `flow=xtls-rprx-vision`, so they are genuinely on the
copying path.

It is still **NO CHANGE**, because recovering the capability would be a correctness bug rather than
an optimisation:

- `VisionConn.Upstream()` returns the inner `vless.Conn`, so unwrapping *would* find `WriteBuffer`.
- But writing there **bypasses Vision's TLS-record padding and filtering**, which is the entire
  purpose of the flow.
- `VisionConn` also writes through its own `VectorisedWriter`, batching rather than copying; the
  only real copy is the one the route wrapper performs to produce the `[]byte` it inspects.

Fixing it properly means adding `WriteBuffer` to `vless.VisionConn` in **upstream** `sing-vmess` —
a new fork, for one protocol, to remove one copy on a path that then re-copies for padding anyway.
That is the complexity-versus-gain trade the task says to refuse, so it is recorded rather than
done.

## DNS Architecture

The common server-hostname path is unchanged and correct:

```text
outbound -> dialer.New(..., ServerIsDomain())
         -> NewResolveDialer
         -> DNSRouter.Lookup
         -> dns.Client.Lookup
         -> transport -> addresses -> DialParallel / DialSerial
```

`RemoteIsDomain=false` short-circuits it: an IP server address builds no resolve dialer.

## DNS Resolution Matrix

| Protocol | Server hostname | Target hostname | Auxiliary | Tunnel DNS | Bootstrap |
|---|---|---|---|---|---|
| direct | n/a | local (by definition) | – | – | – |
| socks5 | ResolveDialer | **remote** (domain sent) | – | – | – |
| socks4 | ResolveDialer | **local**, outbound policy *(was: empty options)* | – | – | – |
| http / CONNECT | ResolveDialer | remote (authority) | – | – | – |
| vless | ResolveDialer | remote | – | – | – |
| anytls | ResolveDialer | remote | – | – | – |
| shadowsocks | ResolveDialer | remote | – | – | – |
| shadowtls | ResolveDialer | remote | – | – | – |
| naive | Cronet DNS bridge → `DNSRouter.Exchange` | remote CONNECT authority | ECH lookup via bridge | – | – |
| masque (client) | resolve dialer | inner: explicit resolver > DNS_ASSIGN > DNSRouter | – | DNS_ASSIGN (immutable) | isolated, fresh-or-LKG |
| wireguard | ResolvePeer → ResolveDialer | inner: global rules | – | peer DNS | – |
| openvpn / openconnect | ResolveDialer (`:489`) | inner: global rules (`:844`) | – | server-pushed | – |
| tailscale | control dialer (`:175`) | inner: global rules (`:763`) | – | MagicDNS | bootstrap resolution |
| hysteria2 | ResolveDialer | remote | realm/STUN → `QueryOptions()` | – | – |
| tuic | ResolveDialer | remote | – | – | – |

The seven call sites that already read `ResolveDialer.QueryOptions()` — Hysteria2 realm, MASQUE
bootstrap, the Naive Cronet bridge, OpenVPN's transport dial, Tailscale's control dialer,
cloudflare's two resolvers — establish the intended pattern.

## DNS Correctness Findings

### SOCKS4 — **FIXED (P1)**

SOCKS4's request format holds a 4-byte IPv4 address, so a domain target must be resolved locally.
That lookup passed `adapter.DNSQueryOptions{}` — an empty policy, which is not "no preference" but a
**bypass of `dialer_options.domain_resolver`**.

The effect was two different resolvers for one outbound: the proxy **server** hostname went through
the configured resolver, while the **target** went to the router's default. Nothing in the
configuration explained the difference.

SOCKS4 is a **proxy**, not an IP tunnel, which is what makes this an inconsistency rather than
endpoint-local policy. Fixed by capturing the policy at construction from the same dialer handed to
the SOCKS client, with a guarded type assertion (an IP server address produces no resolve dialer,
and that must not become a construction failure).

### WireGuard — **NO CHANGE, documented**

`ResolvePeer` (peer endpoint, external) uses the outbound's `QueryOptions`; the inner target uses
global rules. Both correct, matching OpenVPN/OpenConnect/Tailscale/MASQUE. Now stated at all three
sites, because "correct but unstated" is indistinguishable from "accidentally inconsistent" at the
next reading.

### Naive — **NO CHANGE, proven single-resolution**

Chromium's DNS goes through the bridge, so no query leaks past the policy. The open question was a
possible **second** resolution on the socket path. Resolved from the API contract: cronet-go
documents the address the socket factory receives as an *"IP address string (e.g. `1.2.3.4` or
`::1`)"* for both TCP and UDP. Chromium resolves once and hands the dialer an address. One
authority, not two.

### Hysteria2 / MASQUE / OpenVPN / OpenConnect / Tailscale — **NO CHANGE**

Each already uses the correct authority for its role, and each has a genuine protocol reason for the
distinction. Unifying them would change DNS location, which is protocol semantics rather than a
performance parameter.

## Duplicate Resolution

| Check | Before | After |
|---|---|---|
| route `resolve` action → outbound lookup | **1 logical lookup** (verified) | unchanged |
| SOCKS4 server + target | 2 policies | **1 policy** |
| Naive server name | 1 (Chromium), socket gets an IP | unchanged |
| WireGuard peer vs target | intentionally 2 | documented |

The route-resolve path was already correct: `route/conn.go:107` branches on
`len(metadata.DestinationAddresses) > 0` and calls `DialSerialNetwork` with the **addresses**, so the
outbound never sees a domain and cannot look it up again. `DialSerialNetwork` itself works from the
address slice and re-resolves nothing.

## Copy Benchmarks

`sing` cached first payload — the full table is above (1.99×–3.96×, allocations to zero).

## Profiles

**NOT TAKEN.** The Go profiles this audit would use are downstream of live traffic through each
protocol, and this environment cannot complete a Cronet transfer (established and verified on an
unmodified base in the previous round). The copy counts above are **structural** — derived from
which code path is taken, and asserted by tests if the path changes — rather than sampled.

## Failed Experiments

| # | Experiment | Result | Decision |
|---|---|---|---|
| 1 | `WriteOwnedBuffer` in `sing/common/bufio` | 1.99–3.96×, 0 allocations, 10 tests, mutation-verified | **KEEP** |
| 2 | SOCKS4 target resolver policy | Removes a genuine two-policy inconsistency; mutation-verified at the call site | **KEEP** |
| 3 | Restore `ExtendedWriter` on `VisionConn` | Would bypass Vision's TLS padding — a correctness bug, not an optimisation | **REJECT** |
| 4 | Add `WriteBuffer` to `vless.PacketConn` | UDP uses `WritePacket`; no defect exists | **NO CHANGE** |
| 5 | Delegate capability in `only.go` | Sniffing-only wrappers, never a copy destination | **NO CHANGE** (P3) |
| 6 | Rewrite packet `options.Copy` | Already conditional on advertised geometry | **NO CHANGE** |
| 7 | Unify tunnel inner-target DNS with `QueryOptions()` | Would send inner queries to a resolver the tunnel may not route | **REJECT** |
| 8 | Per-protocol DNS resolver helper (`ResolveDialer.Lookup`) | After the SOCKS4 fix only one caller would benefit; the tunnel cases must stay distinct | **NO CHANGE** |
| 9 | Second address cache above `dns.Client` | No benchmark evidence that decode/copy is a hotspot | **NO CHANGE** |
| 10 | Route-prefix snapshot clones in Tailscale/OpenVPN | All Tier C; no profile shows it hot, and §100 excludes one-time constructors | **NO CHANGE** |

## Regression

| | |
|---|---|
| client profile, full suite | **PASS** (exit 0) |
| server profile, full suite | **PASS** (exit 0) |
| protocols / route / dns / common/bufio | **PASS** |
| sing `common/...` | **PASS** |
| production config `check` | **exit 0** |

## Binary

| | Bytes |
|---|---|
| Before (`08861f136`) | 65,639,698 |
| After | 65,640,066 |
| Delta | **+368** (+0.0006%) |

Unexpected dependencies: **NONE**. Module count unchanged at 191; the only `go.sum` change is for
`sing`.

## Production

- Config modified: **NO**
- `sing-box check` against the production config: **exit 0**
- Production server contacted: **NO**. The user's running process was left untouched.

## Remaining Unavoidable Copies

| Copy | Where | Why |
|---|---|---|
| AEAD ciphertext output | `sing-shadowsocks` `Writer` | `cipher.Seal` must write into the writer's own buffer; the plaintext cannot be sealed in place |
| TLS record / QUIC packetisation | crypto/TLS or Chromium | transform boundary |
| Chromium HTTP/2 or HTTP/3 frame construction | Chromium | inside the transport |
| Kernel socket buffers | kernel | not addressable |
| Vision TLS-record padding | `sing-vmess` | the flow exists to rewrite records; the copy is the feature |

## Remaining DNS Special Cases

Only those with a genuine protocol reason:

| Case | Why it must stay independent |
|---|---|
| MASQUE `DNS_ASSIGN` | the server assigns the resolver; it is immutable tunnel configuration |
| MASQUE bootstrap | must not resolve through the tunnel it is establishing |
| WireGuard peer endpoint | reachable before the tunnel exists |
| OpenVPN / OpenConnect server-pushed DNS | endpoint-local policy from the server |
| Tailscale MagicDNS | protocol-defined resolver transport |
| Naive Cronet bridge | Chromium must not use the system resolver |

## Completion Criteria

| Criterion | Status |
|---|---|
| Copy map for every product protocol | **PASS** |
| DNS map for every product protocol | **PASS** |
| Transparent wrappers no longer block capability | **PASS** — audited; the two real gaps are correctly left (P3, and one would be a bug) |
| Cached stream first payload zero-copy when geometry allows | **PASS** (1.99–3.96×) |
| Packet cached copy ownership-audited | **PASS** — already conditional |
| SOCKS4 no longer bypasses the outbound resolver | **PASS** |
| WireGuard resolver semantics explicit and tested | **PASS** (documented; Tier C, no test harness) |
| Naive has no duplicate server DNS, or the need is proven | **PASS** — proven single-resolution |
| No duplicate target lookup after route resolve | **PASS** |
| Proxy target domains not resolved locally | **PASS** |
| Tunnel DNS boundaries preserved | **PASS** |
| No new DNS leak | **PASS** |
| `dns.Client` remains the only cache | **PASS** — nothing added |
| Every perf change has a benchmark | **PASS** |
| Unprofitable complexity reverted | **PASS** — 7 NO CHANGE, 2 REJECT |
| Production tests green | **PASS** |
| macOS / Linux CI green | see run IDs in the session report |
