# v0.1.6 Path MTU / dual-stack audit (Phase A, Gate A)

**Baseline:** `testing = 3cc4c3ceab3fa07c3a3e9f56123eafa9652d2ffa` (re-read live at the start of this
round; unchanged).

**Method.** Phase A changes no production code. Every claim below is either a file-and-line reading of
this tree, a reading of the pinned dependency source, or a measurement produced by a test in this
round. Where a claim could not be established, it says so.

**The headline.** The mechanism the P0 concern is about **already exists in this fork**, and it is wired
end to end. The concern is that an inner packet larger than the tunnel can carry is silently dropped
with nothing bounding it. Read against this tree, that is not what the code does: the MTU reaches the
device, the device publishes it through the interface the forward dispatcher reads, and the dispatcher
answers an over-MTU packet with a real response (resegment, fragment, or an ICMP PTB carrying the MTU)
rather than dropping it. The evidence is §3.

The one genuine defect this round found in the surrounding concurrency work is **not** in the path MTU
line at all - it is in the interaction between the Clash mode switch and the DNS cache, and it is
recorded in §6.

---

## 1. The real dial and payload path

Configuration decode produces two independent lists, `options.Endpoints` and `options.Outbounds`
(`box.go`), and the registries that consume them are separate: `include/registry.go:121` calls
`masque.RegisterEndpoint(registry)`, so **MASQUE is an Endpoint** (`constant/proxy.go:32`
`TypeMASQUEClient`), not an outbound.

That matters for the detour question, and the first reading of it was **wrong**. `DetourDialer.init`
(`common/dialer/detour.go:57-78`) resolves a detour with `outboundManager.Outbound(tag)`. That looks
like it can only ever see outbounds - but `adapter/outbound/manager.go:153-161` falls back:

```go
func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	m.access.RLock()
	outbound, found := m.outboundByTag[tag]
	m.access.RUnlock()
	if found {
		return outbound, true
	}
	return m.endpoint.Get(tag)   // <-- an ENDPOINT is resolvable as a detour
}
```

So `detour: <masque-endpoint-tag>` resolves, and the detour dialer holds the MASQUE endpoint as an
`adapter.Outbound` - which it is, because the endpoint's base is built with
`endpoint.NewAdapterWithDialerOptions(C.TypeMASQUEClient, tag, []string{TCP, UDP, ICMP}, …)`
(`protocol/masque/client.go:232`).

Where a packet then goes, for `HY2 --detour--> MASQUE`:

```
HY2 QUIC underlay socket
  → protocol/hysteria2/outbound.go:131  Dialer: outboundDialer      (the detour dialer)
  → common/dialer/detour.go:88          dialer.ListenPacket(...)
  → protocol/masque/client.go:822       ClientEndpoint.ListenPacket
  → protocol/masque/client.go:617       c.device.DialContext / the device's own stack
  → the inner TUN device created at     protocol/masque/client.go:267
  → device → MASQUE CONNECT-IP capsule  → the outer HTTP/3 QUIC connection
```

The inner device is created with the endpoint's MTU, twice over
(`protocol/masque/endpoint.go:82` and `:85`):

```go
MTU: options.MTU,
Configuration: device.Configuration{ MTU: options.MTU, Address: address },
```

and the constructor resolves an unset MTU to the documented default before that
(`protocol/masque/client.go:119-121`, `masque.DefaultMTU = 1280`, `transport/masque/session.go:18`).

### Edge types, by the order's taxonomy

| Edge | Type | Why |
| --- | --- | --- |
| TUN → route → outbound | `IP_PACKET` | the forward stage carries whole IP packets and has a defined packet MTU |
| MASQUE CONNECT-IP inner device | `IP_PACKET` | the device's whole purpose; MTU is a device parameter |
| HY2 / TUIC / Hysteria QUIC underlay | `UDP_DATAGRAM` | QUIC is UDP; the budget is a UDP payload budget |
| MASQUE outer HTTP/3 | `UDP_DATAGRAM` | QUIC datagrams on the wire |
| VLESS | **`UNKNOWN` for this purpose** | see §4; it is not established here that it propagates an IP capacity |
| `bridge`, `direct` | `PROXY_TUNNEL` | they carry datagrams; the per-connection answer depends on the dial |

**`UNKNOWN` is not `unbounded`.** Nothing in this audit treats it as a licence to compute a static
ceiling; §4 records what would have to be established first.

---

## 2. Dual-stack racing: `ALREADY_PRESENT`, do not rebuild

The order asks four questions and forbids building a second Happy Eyeballs. Answers, by reading:

1. **Is TCP to v4/v6 candidates already via `N.DialParallel`?** Yes. `protocol/masque/inner_happy_eyeballs_test.go`
   exercises the inner path, and `common/dialer` supplies the parallel scheduler for the outer one.
   This round did not modify either.
2. **Do the blackhole-fallback tests drive the real call path?** The dialer package's own tests do, and
   the previous round converted their wall-clock bounds to event gaps precisely because the timings were
   the host's, not the scheduler's. Reported in that round's record; not re-litigated here.
3. **Is a single-stack path needlessly delayed?** No evidence of it in this round's scope.
4. **Is UDP serial, and is that a real hole?** UDP has no connection to race; the family question for
   UDP is decided by the destination the caller supplied, not by a racer. No change.

**Classification: `ALREADY_PRESENT / NO_CHANGE`.**

**One diagnosis to keep separate:** an IPv6 PMTU blackhole is **not** a missing IPv4 fallback. The two
produce similar symptoms and have nothing to do with each other. Nothing in this round conflates them,
and §6 is about a third thing again.

---

## 3. The MTU already reaches the data path

This is the finding that changes the P0 conclusion, so it is stated in three links.

### Link 1 - the MTU reaches the device

`protocol/masque/client.go:119-121` defaults it; `protocol/masque/endpoint.go:82,85` puts it on both
`device.Options.MTU` and `device.Configuration.MTU`.

### Link 2 - the device publishes it through the interface the data path reads

`protocol/masque/client.go:542`:

```go
func (c *ClientEndpoint) PortMTU() uint32 { return c.device.PortMTU() }
```

`PortMTU` is not a reporting nicety. In the pinned `sing-tun`
(`v0.0.0-20261008172655-8dde9c8cbe27`) it is a method of the `Port` interface (`flow.go:58-64`), and the
forward dispatcher reads it for every outbound flow (`flow_dispatch.go:502`):

```go
effectiveMTU := verdict.Port.PortMTU()
if packet.ipVersion == 6 && effectiveMTU != 0 && effectiveMTU < header.IPv6MinimumMTU {
	return nil, createFlowUnsupported
}
```

### Link 3 - an over-MTU packet is ANSWERED, not dropped

`flow_dispatch.go:608-647`, `forwardToPort`:

```go
if effectiveMTU != 0 && uint32(len(raw)) > effectiveMTU {
	if packet.protocol == uint8(header.TCPProtocolNumber) {
		... s.resegmentTCP(flow, packet, raw, effectiveMTU); return
	}
	if packet.ipVersion == 4 {
		ipHdr := header.IPv4(packet.network)
		if ipHdr.Flags()&header.IPv4FlagDontFragment == 0 {
			... fragments, ok := fragmentIPv4Packet(ipHdr, flow.effectiveMTU) ...
			return
		}
	}
	s.writebackBatch = append(s.writebackBatch,
		buildICMPError(packet, ICMPErrorPacketTooBig, flow.effectiveMTU, s.writeback.ReturnHeadroom()))
	return
}
```

So for an oversized packet the dispatcher does one of three things, and dropping is not among them:

| Packet | What happens |
| --- | --- |
| TCP | resegmented to fit |
| IPv4, DF clear | fragmented to fit |
| IPv4 with DF set, or **IPv6** | **ICMP Packet Too Big carrying `effectiveMTU`** |

That last row is the one the P0 concern is about, and it is the opposite of the reported behaviour: an
inner IPv6 packet larger than 1280 gets an ICMPv6 PTB advertising 1280, which is exactly the signal
QUIC's DPLPMTUD consumes. It is not a silent drop.

### What this does and does not establish

**Established:** the MTU is configured, published through the exact interface the dispatcher reads, and
the dispatcher's over-MTU branch is a response rather than a discard.

**NOT established, and not claimed:** an end-to-end packet run through a real WARP path. There is no
WARP credential, no IPv6 HY2 target and no packet capture in this environment, so the order's §4.4
matrix is `NOT_RUN`. The reading above is a statement about this tree's code and its pinned dependency,
which is what Phase A is for; it is not a substitute for §4.4.

Because the mechanism is present, Phase B's P0 does **not** have an old-red to close, and no production
code was changed for it. That is the `NO_CHANGE_REQUIRED` outcome the order explicitly allows.

---

## 4. The outer HTTP/3 packet size, and why it is not 1452

`protocol/masque/client.go:134-136`:

```go
if options.HTTP3Options.InitialPacketSize == 0 {
	options.HTTP3Options.InitialPacketSize = min(int(options.MTU)+masque.QUICPacketOverhead, math.MaxUint16)
}
```

With `QUICPacketOverhead = 51` (`transport/masque/session.go:19`) and the default MTU 1280, that is
**1331**. The LX reference clamps `mtu+51` into `[1200, 1452]`. This fork clamps to `MaxUint16` and lets
the library clamp again. The order asks whether that is a defect. Read against the pinned quic-go
(`v0.61.1-0.20260929231714-9c94b1e90d94`):

- `config.go:42-44` - `if config.InitialPacketSize > 0 && config.InitialPacketSize < protocol.MinInitialPacketSize { config.InitialPacketSize = protocol.MinInitialPacketSize }`
- `config.go:45-47` - `if config.InitialPacketSize > protocol.MaxPacketBufferSize { config.InitialPacketSize = protocol.MaxPacketBufferSize }`
- `internal/protocol/protocol.go:111` - `const MaxPacketBufferSize = 1452`
- `internal/protocol/protocol.go:117` - `const MinInitialPacketSize = 1200`

So the effective ceiling **is** 1452 and the floor **is** 1200, enforced by the library on the value this
fork passes. The fork's looser `MaxUint16` bound is therefore not a reachable upper bound at all - for
MTU ≥ 1402 the library clamps 1453+ down to 1452 - and the LX clamp's numeric content is already present,
one layer down, where the constant actually lives.

**Classification: `NO_CHANGE_REQUIRED`.** The order warns specifically against "blindly lowering 1551 to
1452"; the reading above is why that would have been a change with no effect on the wire, duplicating a
library constant in a second place where it could drift.

Two things this does **not** answer, both `NOT_RUN` rather than assumed: whether a real H3 session's early
RTT suffers from a 1331-byte initial, and what the outer path's own MTU is on a real carrier. Those need
§4.4's environment.

### The two budgets, kept apart

The order's §0.2 insists these are different quantities, and they are:

| Quantity | Where | Value at default | What it bounds |
| --- | --- | --- | --- |
| inner IP MTU | `protocol/masque/client.go:119` | 1280 | inner IP **packets** |
| inner UDP payload budget | derived, per family | 1252 (v4) / 1232 (v6) | inner UDP payload, at zero extension headers |
| outer H3 `InitialPacketSize` | `protocol/masque/client.go:135` | 1331 → library-clamped ≤ 1452 | the outer QUIC datagrams this endpoint sends |

Adding or subtracting across rows is meaningless, and nothing in this audit does it.

---

## 5. PTB and IPv6 extension coverage: `ALREADY_PRESENT`

`transport/masque/` already carries `packet_size_bound_test.go`, `packet_too_big_test.go`,
`packet_too_big_session_test.go`, `ipv6_extensions_test.go` and `ipv6_extension_chain_test.go`, and
`transport/http/h3_mtu_audit_test.go` covers the QUIC option entry point. Per the order, this round did
**not** build a second PTB implementation. No reproducible divergence was found in this tree, so the
classification is `NO_CHANGE_REQUIRED` for this item rather than a rewrite.

The IPv6 extension-header point the order raises - that a fixed 40-byte header is an assumption, not a
fact - is the one to keep in view for §4.4: the 1232 figure holds **at zero extension headers**, and a
path with extension headers has less. That is recorded as a bound on the number, not as a defect.

---

## 6. The concurrency debt from the previous round

The order's §7 lists three windows around the three commits already on `testing`
(`d5a8472c`, `3711437d`, `3cc4c3ce`). This round reproduced the first and classified it; the state of all
three is in the final report's §E table.

### DNS-01 - the store-before-purge window: measured, and why it was NOT "fixed"

`experimental/clashmode/manager.go` SetMode publishes the mode and then invalidates the DNS cache:

```
m.mode.Store(newMode)   // the new policy is now visible to routing
m.updateAccess.Unlock()
... hooks ...
m.dnsRouter.ClearCache()
```

For the duration of that purge, a `clash_mode` rule matches the **new** mode while the previous
policy's answers are still cached. That is measured, not argued:
`route/rule/clash_mode_store_window_test.go` holds the invalidation open and asks the production
`ClashModeItem` what it matches - it matches the new mode.

**What was implemented and then REVERTED.** Moving `ClearCache()` inside the critical section. It does
not close the window, and the reason is a property this tree deliberately has: `Mode()` is an **atomic
load with no lock**, because the connection routing path must not queue behind a controller. A reader
therefore is not blocked by the writer holding the mutex, and reordering the writer's two steps changes
nothing a reader can observe. Holding a control lock across cache work would have bought nothing, and
`experimental/clashmode/manager.go` is byte-identical to what is already pushed - verified with
`git diff --stat` returning empty.

**Why it is not a wrong answer either.** Whether the window can serve a stale answer is decided by the
DNS cache key, not by this ordering. `dnsCacheKey` is `{Question, transportTag, clientSubnet,
environment}`:

- if the two modes select **different** servers, the transport tag differs and the old entry is
  unreachable, so there is a miss and a fresh query on the new policy's server;
- if the two modes select the **same** server, the answer does not depend on the mode, so serving it is
  correct.

The store-side hole - an answer **recorded across** a switch - is the one that was real, and it is what
`3711437d`'s policy epoch closes, with a reproduction and a reverse break.

**Classification: `HARDENING` at most, and not reachable as a wrong answer on this reading. No
production change.** The measurement is kept as a test so a future reordering is visible rather than
silent.

---

## 7. What is NOT done

Stated plainly so the following report cannot overclaim:

| Item | State |
| --- | --- |
| §4.4 real WARP / IPv6 HY2 target matrix | `NOT_RUN` - no WARP credential, no IPv6 target |
| §4.1 B-level packet-capacity reproduction | `NOT_RUN` - no controlled real endpoint to reject over-MTU packets |
| §8.2 real path graph matrix G01-G13 | `NOT_RUN` - Phase B/C did not start, because Phase A found the mechanism present |
| §5 path capacity model / pre-pass | **Not implemented**, and not needed for this round's finding |
| Xray reference interop | `BLOCKED_DEPENDENCY` - no reference binaries |
| CI at this SHA | `CI_NOT_RUN` - Actions disabled for the repository |
| Cross-platform build matrix | `NOT_RUN` |

The order's §12 Gate B requires an old-red for the P0. There is none, because the mechanism exists. Gate B
is therefore reported as **`NO_CHANGE_REQUIRED`**, not as a silently skipped gate.
