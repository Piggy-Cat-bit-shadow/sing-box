# v0.1.6 next-stage: G0 record and running integrator ledger

Integrator-owned. One section per phase. Every number here is a command output, not an estimate.

## 1. G0 — live site, read before anything was written

```text
START_SHA                    = 686c937cbb13aafdfe6276c8813993dfcb51d9ac
WORKTREE (integration)       = C:\Deepseek\内核\work   (detached, clean at G0)
LIVE_ORIGIN_SHA (origin/testing) = 686c937cbb13aafdfe6276c8813993dfcb51d9ac
MERGE_BASE HEAD origin/testing   = 686c937cbb13aafdfe6276c8813993dfcb51d9ac
BASE_DIFF_STATUS             = origin/testing == HEAD; nothing to reconcile, no upstream drift
REMOTE_HEADS                 = refs/heads/testing only
REMOTE_TAGS                  = 20 refs/tags (v0.1 … v1.0.6, tooling-v0.1.5, 1.1-beta17,
                               checkpoint-20261002-pre-resource-efficiency,
                               archive/macos-client-before-consolidation)
GO                           = go1.26.8 windows/amd64
GO_ENV                       = GOOS=windows GOARCH=amd64 CGO_ENABLED=1
                               GOROOT=C:\src\_toolchain\goroot  GOPATH=C:\Users\Jie\go
TAGS (release/DEFAULT_BUILD_TAGS_OTHERS) =
  with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,
  with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,with_xhttp,badlinkname
```

The handoff baseline and the live remote tip are the same commit, so no incremental diff had to be
read and nothing already fixed had to be re-fixed. The order warns not to force a return to this SHA
"if the site has moved"; the site had not moved.

### 1.1 ORIGINAL_DIRTY_TREE_UNTOUCHED

`C:\src\sing-box` is the **main worktree** of this repository and is the user's dirty tree. Before/after:

```text
ORIGINAL_DIRTY_TREE_SHA_BEFORE  = 8d78dcddcc434ed9091a3654e3f6b0b542fa3461
ORIGINAL_DIRTY_TREE_BRANCH      = testing
ORIGINAL_DIRTY_TREE_STATUS      = " M clients/desktop"        (git status --porcelain)
ORIGINAL_DIRTY_TREE_DIFFSTAT    = clients/desktop | 0          (gitlink only, 0 insertions/deletions)
ORIGINAL_DIRTY_TREE_GITLINK     = 160000 32f915ba595601dbc2dd346c33fe9fedd3e72979 0  clients/desktop
```

Nothing was written, checked out, stashed, reset, cleaned, added, committed or built there. All work
happened in detached worktrees carved out of `C:\Deepseek\内核\`.

### 1.2 WORKTREE_OWNERSHIP

All worktrees are detached at `686c937cbb13aafdfe6276c8813993dfcb51d9ac` unless stated.

| Worktree | Owner | Purpose |
|---|---|---|
| `C:\Deepseek\内核\work` | Integrator | integration tree, `docs/fork/` ledger, serial cherry-pick, push |
| `C:\Deepseek\内核\wA` | Agent A | FIP-01: `route/route.go`, `dns/transport/fakeip/*` |
| `C:\Deepseek\内核\wB` | Agent B | D7-02: `transport/wireguard/*`, `common/runtimecoord/*` |
| `C:\Deepseek\内核\wC` | Agent C | RNET-03: `route`/`transport/http`/`common/httpclient` tests |
| `C:\Deepseek\内核\wD` | Agent D | STATUS-04: `box.go` + new `box_*test.go` |
| `C:\Deepseek\内核\wE` | Agent E | platform/test matrix (principally read-only) |
| `C:\Deepseek\内核\wF` | Agent F | independent adversary, attack tests only |

Leftovers from the previous round, read and left untouched: `wB2`, `wC2`, `wD2`, `wD4`/`wD7` (each
carrying a deleted `transport/http/zz_capsule_probe_test.go`), `wDL` (a `common/dialer/resolve.go`
edit plus one new test — the same work already committed as `c216688f9`), `wE2E` (one evidence
`.txt`). None was reused or overwritten.

### 1.3 BASELINE_TEST_COUNTS

```text
COMMAND  = go test -count=1 -tags "$TAGS" ./route ./dns ./e2e ./transport/wireguard ./common/physicalpath
RESULT   = ok route 7.299s | ok dns 7.838s | ok e2e 10.165s | ok transport/wireguard 5.341s
           | ok common/physicalpath 0.035s
EXIT     = 0     (elapsed 18.2 s)
```

The full 83-package scan is owned by Agent E and is re-run by the integrator on the final SHA.

### 1.4 External conditions available (measured, not assumed)

```text
MINGW            = C:\Users\Jie\AppData\Local\Temp\jiejie-tools\mingw\mingw64\bin   (present)
GOROOT           = C:\src\_toolchain\goroot\bin                                    (present)
GIT              = C:\src\MinGit\cmd\git.exe                                       (present)
push_preflight   = C:\Deepseek\内核\push_preflight.py                              (present, read)
ADMIN / DRIVER   = see Agent E's attribution of common/windivert
APPLE DEVICE     = NOT AVAILABLE (no Apple hardware on this host)
WARP             = NOT AVAILABLE
GITHUB API       = PARTIAL: the Harness GitHub MCP server authenticates as
                   Piggy-Cat-bit-shadow, but it exposes no Actions-run listing tool.
WEB FETCH        = BLOCKED: github.com resolves to 198.19.0.15 on this host, which the
                   fetch tool refuses as a non-public address (see §1.5).
```

### 1.5 The host's own networking sits inside `198.18.0.0/15` — a measured fact that binds FIP-01

This machine has an active TUN interface (`tun0`, ifIndex 17, DNS `172.19.0.2`). Its resolver answers
**every** query — including one for a domain that cannot exist — with an address inside the **default
FakeIP range**, and those addresses are genuinely routable:

```text
github.com                          -> 198.19.0.15
api.github.com                      -> 198.19.0.17
example.com                         -> 198.19.0.55
www.microsoft.com                   -> 198.19.4.147
cloudflare.com                      -> 198.19.4.148
a-random-nonexistent-xyz-12345.com  -> 198.19.4.149
TCP connect 198.19.0.15:443         -> CONNECTED=True
```

This is the concrete counterexample that forbids a blanket guard over `198.18.0.0/15` or over a
user-defined FakeIP range: on this very host such a guard would black-hole the whole machine. It is
also why the discriminator has to be **proof of issuance**, never range membership. It is quoted in
full in the final report under C (FIP-01) and in F's rebuttal section.

## 2. Structural findings that change the shape of the work (established before any fix)

### 2.1 There is no true in-process reload of a Box in this tree

`daemon/started_service.go:251 StartOrReloadService` closes the old instance and builds a **new** one:

```go
oldInstance := s.instance
if oldInstance != nil {
    s.instance = nil
    ...
    _ = oldInstance.Close()
    runtimeDebug.FreeOSMemory()
    ...
}
...
instance, err := s.newInstance(ctx, profileContent, options, oldInstance != nil)
```

and `daemon/instance.go:85 newInstance` derives a fresh instance context from the long-lived
service context:

```go
ctx, _ = locale.ContextWithLocale(s.ctx, selectedLocale.Locale)
ctx = service.ExtendContext(ctx)
ctx, cancel := context.WithCancel(ctx)
...
boxInstance, err := box.New(box.Options{Context: ctx, ...})
```

Consequences, which the whole FIP-01 experiment matrix is required to respect:

- "same instance, hot reload" (the order's A3) is **not constructible**. A reload *is* an old Box
  closed plus a new Box created in the same process. A two-Box stand and a real reload are therefore
  the same shape, and that has to be stated, not glossed.
- `dns/transport_manager.go` records it too: *"dependByTag is gone: upstream removed the unreferenced
  field along with the dead hot-reload path, and nothing reads it."*
- Anything that must survive a reload therefore has to be owned by something that outlives a Box, or
  it has to be durable. A package-level singleton is explicitly forbidden by the order (A12).

### 2.2 Where FakeIP issuance actually lives

| Fact | Where |
|---|---|
| who issues | `dns/transport/fakeip/store.go:118 Store.Create` — advances a cursor, persists a window of 1024 ahead, then returns the address |
| who holds it (memory) | `MemoryStorage` — `FakeIPMetadata()` returns nil, so **nothing survives a new Box** on the default path |
| who holds it (durable) | `experimental/cachefile/fakeip.go` — bbolt bucket `fakeip_address` keyed by `address.AsSlice()` → domain, plus `fakeip_domain4/6` reverse buckets. **The address bucket is enumerable and already exists**; reading it introduces no new disk format |
| when it is lost | `Store.Start()`: if the persisted ranges differ from the configured ones it calls `storage.FakeIPReset()`, which **deletes all three buckets** |
| who finally decides egress | `route/route.go:1051 prepareMatchMetadata` |
| the gate | membership in the **currently configured** range only (`Store.Contains`), with no negative knowledge at all |

### 2.3 A second, independent escape reachable inside the current range

`github.com/sagernet/sing` (pinned fork) `common/metadata/addr.go`:

```go
func AddrFromIP(ip net.IP) netip.Addr {
	addr, _ := netip.AddrFromSlice(ip)
	return addr                       // no Unmap()
}
func (ap Socksaddr) IsIPv4() bool { return ap.Addr.Is4() }     // false for 4-in-6
func (ap Socksaddr) IsIPv6() bool { return ap.Addr.Is6() }     // TRUE for 4-in-6
```

and `netip.Prefix.Contains` compares `BitLen()` (32 for an IPv4 prefix, 128 for a 4-in-6 address) and
therefore returns **false**. So a destination spelled `::ffff:198.18.0.5` misses the FakeIP branch
entirely, falls through to the literal path, and can be dialled for real — *without any configuration
change at all*. Whether an inbound can actually produce that spelling is being measured, not assumed;
if it can, this is a strictly in-range defect and is fixable with no new state whatsoever.

### 2.4 A false READY in an exported API, found by the integrator and fixed this round

The order flags `ValidateRoots` standing alone against a missing detour as something to verify
rather than to bend green. It is a real defect in the exported API. MEASURED at the baseline, with
`exit.detour = "ghost"` and no such object in the registry:

```text
roots=[exit] nodes=[exit(exit pos=0 exit=false)] failures=[] reachable=true err=<nil>
```

The node correctly refuses to claim an exit — the enumeration reported `routeTruncated` — and
`Report.Reachable()` still called the route proven usable. `Report.Reachable` is documented as the
stronger question (*"an unknown hop does NOT count as reachable"*), and `Report.Err()` is what a
caller gates a start on, so both answered the opposite of what they document.

Why the product does not already catch it, and why that is not a defence: `adapter/outbound`'s
start-order lint rejects `dependency[tag] not found for outbound[tag]` **before** it runs the dry
run, so the one shipped caller is protected by the *order of two checks* rather than by this
function. `ValidateRoots` is exported and documents this question as its own.

Fix: `common/physicalpath/dryrun.go` refuses a route no node of which carries `Exit`, naming the hop
that declared the unresolvable tag when it can, through the same `lookupDependency` the enumeration
used. The signal is exact, not a heuristic — `numberRoute` sets `Exit = complete && index ==
len(route)-1` and `Hops` passes `complete == false` for exactly the truncation case. A root that
produced no node at all is deliberately left alone (that belongs to the group's own Start).

Committed as `e0b743f5e`. Reverse-break: the assertion was RED on unmodified code first, by
assertion and not by compile error. Discriminating control kept: the same fixture with the detour
resolving stays reachable. `common/physicalpath`, `adapter/...`, `protocol/group`, `route`, `e2e`
green; `go vet` exit 0; `gofmt -l` empty on both files.

## 3. Integrator rulings issued to the agents

- **FIP-01 contract C1–C6** (issued to Agent A verbatim): map what is mapped, refuse in-range with no
  mapping, leave genuinely-unevidenced literals alone, refuse what the Box can *prove* it issued, mark
  "cannot be attributed" honestly where no durable/shared fact exists, and never blanket-block a range.
- Any new state must be owned by a live object, bounded, and released on `Close`; interfaces are
  extended only by adding **separate optional capability interfaces**, never by widening an adapter
  interface that the libbox ABI surface depends on.
- `route/route.go` has exactly one writer this round: Agent A.
