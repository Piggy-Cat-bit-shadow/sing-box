# Path MTU audit — correction and addendum

**Appended to** `docs/fork/v016-path-mtu-audit.md` (which stays as written; this file corrects it).
**Baseline:** `testing = 6b6e31fe784aebd492b29039e887f572dcfba624`, re-read live at the start of this
round and unchanged.

---

## 1. The correction: the PTB argument used the wrong path

The previous audit concluded `NO_CHANGE_REQUIRED` for the HY2-over-MASQUE concern because
`sing-tun`'s `flow_dispatch.go:608-647` answers an over-MTU packet with an ICMP Packet Too Big
carrying the MTU. **That conclusion does not follow from that evidence, and this round withdraws it.**

`flow_dispatch.go` is the **ForwardDispatcher** branch: it is reached by packets arriving on the TUN
that a route verdict forwards out through a port. HY2's QUIC socket does **not** travel that way. It is
a userspace UDP socket inside the MASQUE endpoint's own Go stack, and it transmits through a different
function entirely. The two paths are both real, and the first is not evidence about the second.

The corrected send path for `HY2 --detour--> MASQUE`, each link read in source:

```
protocol/hysteria2/outbound.go:131   Dialer: outboundDialer        (the detour dialer)
common/dialer/detour.go:88           dialer.ListenPacket(...)
adapter/outbound/manager.go:153-161  Outbound(tag) falls back to m.endpoint.Get(tag)
protocol/masque/client.go:822        ClientEndpoint.ListenPacket
protocol/masque/client.go:617        c.device.DialContext  <- the MASQUE inner device
sing-tun stack_go_udp_socket.go:325  GoUDPConn.transmit          <- THE SEND PATH (not flow_dispatch)
sing-tun stack_go_udp_socket.go:353  mtu := platformIO.mtu()
sing-tun stack_go_udp_socket.go:354  if packet.Len() <= mtu { write } else { goWriteFragmented }
sing-tun stack_go_udp.go:435-453     goFragmentPacket -> fragmentIPv6Packet
```

`platformIO.mtu()` is the device's MTU, traced the rest of the way: `stack_go_io_windows.go:384-386`
returns `o.stack.mtu`, which `stack_go.go:60` sets from `options.TunOptions.MTU`, which the MASQUE
endpoint supplies as `device.Configuration.MTU` (`protocol/masque/endpoint.go:85`) = 1280 by default.

**What this changes.** An over-MTU IPv6 packet on this path is **fragmented at the IPv6 layer**
(`fragmentIPv6Packet`), not answered with a PTB. That is materially different from what the previous
audit described, and it is the mechanism the LX report is about.

---

## 2. The second finding: ChromeParrot discards the value a fix would set

This is the part that makes the concern reachable rather than theoretical, and it is verified against
the **actually pinned** versions rather than the ones the order's background section names.

`go.mod` pins `github.com/sagernet/quic-go v0.61.0-sing-box-mod.9` **replaced by**
`github.com/Piggy-Cat-bit-shadow/quic-go v0.61.1-0.20260929231714-9c94b1e90d94`.

The chain, each link in a different module:

| # | Module | Location | What it does |
| --- | --- | --- | --- |
| 1 | sing-box | `protocol/hysteria2/outbound.go:157` | `ChromeParrot: !options.DisableChromeParrot` → **true** by default (`option/hysteria2.go:225`) |
| 2 | sing-quic | `hysteria2/client.go:54,97` | `ChromeParrot: options.ChromeParrot` onto the quic.Config |
| 3 | sing-quic | `quic.go:72-74` | `ApplyQUICOptions` sets `InitialPacketSize` … and **never touches `ChromeParrot`** |
| 4 | quic-go | `config.go:109-125` | `if config.ChromeParrot { … initialPacketSize = chromeInitialPacketSize }` |
| 5 | quic-go | `chrome_parrot.go:19` | `chromeInitialPacketSize = 1250` |
| 6 | quic-go | `config.go:127-152` | `return &Config{… InitialPacketSize: initialPacketSize}` — **a NEW Config, so the override is final** |

`ApplyQUICOptions` runs *before* `populateConfig`, so an explicit `InitialPacketSize` from
configuration is applied and then **discarded**. quic-go says so itself at `config.go:115`:
*"Chrome pins these, so anything the caller asked for is overridden."*

### The arithmetic this produces

For an inner IPv6 packet with no extension headers, inside a 1280-byte inner IP MTU:

```
IPv6 header 40 + UDP 8 + QUIC initial UDP payload 1250 = 1298 bytes
1298 - 1280 = 18 bytes over the tunnel's capacity
safe UDP payload ceiling = 1280 - 40 - 8 = 1232 bytes
```

So the default HY2 configuration produces an 18-byte over-capacity first flight, and the obvious fix -
setting `initial_packet_size: 1232` - is **silently discarded**. This is exactly the shape the order's
§4.0 describes.

---

## 3. Classification, stated precisely

| Item | Classification | Basis |
| --- | --- | --- |
| ChromeParrot overrides an explicit `InitialPacketSize` | **`CONFIRMED`** (source-verified across three modules, including the pinned fork) | the six links above, all read |
| HY2's send path is `GoUDPConn.transmit`, not `flow_dispatch` | **`CONFIRMED`** | the corrected path above |
| An over-MTU IPv6 packet on that path is fragmented, not PTB'd | **`CONFIRMED`** | `stack_go_udp_socket.go:354-357`, `stack_go_udp.go:447-453`, `flow_mtu.go:108-130` |
| The 18-byte overage causes a real WARP handshake failure | **`NOT_RUN` — not claimed** | needs a real WARP path; see §4 |
| A packet-level measurement of the first datagram | **`BLOCKED`** | see §4 - a working harness was attempted and removed |

The distinction matters: the *configuration and framing* facts are established from the pinned source,
and the *carrier behaviour* fact is not. The order's Appendix β item 3 forbids turning the first into
the second.

---

## 4. What was attempted for the packet-level measurement, and why it is BLOCKED

A harness was written in `protocol/hysteria2` that dialled a loopback address nothing answers and read
`quic.Conn.InitialPacketSize()`, which returns the **populated** config value. Two shapes were tried:

1. a hand-written `net.PacketConn` — `quic.Dial` blocked for the full test timeout: the dial bound is
   not the context, so a peer that neither answers nor closes leaves it waiting;
2. a real loopback UDP socket with `DialEarly`, keeping the handshake idle timeout at the default -
   still blocked; the connection object is only handed back once the handshake has made progress,
   which a silent peer never provides.

The harness was **removed, not committed, and not pushed**. The order's §4.4 is explicit that a
harness which cannot produce a red must be fixed rather than carried, and it also forbids forcing a
green. Reporting `BLOCKED` with the reason is the honest outcome for this link.

A real packet capture needs a QUIC peer that completes a handshake inside a tunnel with a known MTU, or
a WARP-equivalent path - neither is present in this environment.

---

## 5. What this means for the fix, and what was NOT done

The minimal fix the order sketches is "make the effective QUIC initial packet size respect the bounded
lower path". **It cannot be done with the configuration surface alone**, because of finding 2: writing
a smaller `InitialPacketSize` does not survive `populateConfig` while ChromeParrot is on. The order
anticipates this:

> "如现有依赖确实无法同时维持 ChromeParrot 且满足 1232 上限，**显式说明设计冲突及安全/隐蔽性权衡**"

That is the situation. The three candidates and their costs:

| Option | Effect | Cost |
| --- | --- | --- |
| set `InitialPacketSize ≤ 1232` | **no effect** — overridden to 1250 | none, and none of the benefit |
| disable ChromeParrot on this path | the requested size survives | changes the TLS/QUIC fingerprint, which is an anti-identification property; the order forbids doing it silently or globally |
| leave it as is | 18 bytes of IPv6-level fragmentation per large first flight | fragmentation exists and is handled; the risk is carrier behaviour, which is NOT_RUN |

**No production change was made.** Choosing between these requires either a real WARP measurement or
an explicit product decision about the ChromeParrot trade-off, and neither belongs in a round that
cannot measure the outcome. Writing a clamp that the library discards would have been the worst option:
it would look like a fix in the diff and change nothing on the wire.

---

## 6. Corrections to the previous audit's other claims

| Previous claim | Status |
| --- | --- |
| PTB in `flow_dispatch.go` bounds the HY2 path | **WITHDRAWN** — wrong path (§1) |
| `PortMTU()` reaches the data path | **STANDS** — it reaches the ForwardDispatcher, which is a different consumer than the one HY2 uses |
| outer H3 `1331` vs LX's `1452` clamp is `NO_CHANGE_REQUIRED` | **STANDS** — `config.go:42-47` clamps to `MaxPacketBufferSize = 1452` and `MinInitialPacketSize = 1200`; that reading is unaffected by this correction |
| inner UDP budget is 1252 v4 / 1232 v6 | **STANDS as arithmetic**, and is now the *relevant* arithmetic rather than a supporting note |

---

## 7. Not done, and why

| Item | State | Needs |
| --- | --- | --- |
| packet-level first-datagram measurement | `BLOCKED` | a QUIC peer that completes inside a known-MTU tunnel, or WARP |
| real WARP / IPv6 HY2 matrix (§8.4) | `NOT_RUN` | WARP credentials and an IPv6 target |
| the fix itself | **deliberately not made** | the ChromeParrot trade-off is a product decision, and the outcome is unmeasurable here |
| TUIC / Hysteria / WireGuard generalisation (Phase C/D) | `DEFERRED_TO_POST_V016` | upgrade conditions in §6.1 not met |
| DNS §7.2 / §7.3 | `NOT_RUN` | see the round report |
| L0 boundary矩阵 | `NOT_RUN` | see the round report |
