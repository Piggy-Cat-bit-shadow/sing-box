# Keepalive and the power governor

What "lengthen the keepalives while the device is asleep" runs into, audited before any code
was written.

## The inventory

| Where | Value | When it is chosen |
| --- | --- | --- |
| `protocol/masque/client.go` | `defaultKeepAlivePeriod = 10s`, applied only when the configuration leaves `KeepAlivePeriod` unset | `NewClientEndpoint`, once, and the result is written into the HTTP client options |
| `protocol/hysteria2`, `protocol/hysteria`, `protocol/tuic` | from configuration | per dial, copied into `QUICOptions` |
| `transport/http/server.go` | from configuration, as HTTP/2 `ReadIdleTimeout` | server construction |

That is the whole production surface. Everything except MASQUE's fallback comes from the user's
configuration, and this fork does not change a user's stated value.

## What the audit found

**There is no live keepalive anywhere.** Every one of them is chosen once and handed to a
transport that captures it:

- `transport/http` reads `KeepAlivePeriod` into `ReadIdleTimeout` at construction and exposes no
  setter.
- `quic.Config.KeepAlivePeriod` is copied into the connection when it is dialled — the quic-go
  fork's `config.go` does `KeepAlivePeriod: config.KeepAlivePeriod` — and a `Config` field is
  construction-time by definition.

So the governor cannot turn a keepalive down on a connection that already exists. The two ways to
get there are both worse than the thing they would save:

1. **Reconnect the transport under a longer keepalive.** That is the teardown this entire work
   stream exists to remove, applied to the sessions least able to afford it — the idle ones a user
   is about to come back to. A device that drops its tunnel to save a keepalive and then has to
   rebuild it when the screen lights up has traded a wakeup for a handshake.
2. **Add a live keepalive mechanism** to `transport/http`, the QUIC outbounds and the MASQUE
   client. That is a change to protocol transports, not to the governor, and it cannot be verified
   without a real peer for each of them.

## What is true today, and what the governor already does

Connections established **while the device is idle** could take a longer value, because that is
the one moment the value is still being chosen. That is a small and narrow win: a tunnel is
normally established while the device is awake, so the connection a sleeping phone is holding was
almost always dialled under the ACTIVE policy.

What the governor does cover is everything around the keepalive: it stops speculative work
(provider refresh, UI statistics, the traffic-total save), it stops URLTest's ticker through the
existing `pause.RegisterTicker`, and it does so without closing a session or clearing a cache.

## The recommendation, rather than a half-measure

Do not change keepalives from the governor until a transport offers a live value. When one does,
the shape is:

- a `Policy` field per state, alongside the ones already there, so the threshold stays in one
  place rather than in the protocol;
- the transport asking the governor at the moment it arms its timer, not at construction;
- and the keepalive remaining strictly below the connection's negotiated idle timeout, because a
  keepalive longer than the idle timeout does not save a wakeup — it drops the connection and
  takes a handshake instead.

This is recorded rather than implemented because the alternative was a behaviour change to
protocol transports that this work cannot verify, and because the brief is explicit that a
protocol-correctness change is worse than an unclaimed optimisation.

## Correction: WireGuard is the exception, and it moves the blocker

The first version of this note said there is no live keepalive "anywhere in this tree". That was
too broad, and the exception matters because it changes what is actually blocking.

WireGuard's `PersistentKeepaliveInterval` is applied the same construction-time way in the fork —
it is read into `Endpoint.keepalive` from the option and written once, in `Start()`, through

```go
err = wgDevice.IpcSet(ipcConf.String())
```

— but `IpcSet` is not a constructor. It is wireguard-go's live configuration API, and
`persistent_keepalive_interval` is one of the fields it accepts. Unlike `quic.Config`, which is
copied into a connection at dial time, this value can be changed on a device that is already
running, with no teardown and no reconnect. So WireGuard is the one protocol in this tree where
"lengthen the keepalive in DEEP_IDLE" is mechanically possible today.

**Which means the blocker is not the mechanism. It is that the consequence cannot be verified
here, and the consequence is connectivity.**

A persistent keepalive exists to hold a NAT mapping open so the peer can reach the device
unsolicited. Lengthening it, or suspending it, risks that mapping expiring — and whether it
expires depends on the carrier's NAT, which varies by network and cannot be modelled from this
repository. The failure mode is the one this work stream is least allowed to produce: a tunnel
that is up, reports healthy, and silently cannot be reached until the user's next outbound packet
happens to re-establish it.

For a client-side mobile tunnel the argument that this is *probably* safe is real — the phone
initiates, and a lost mapping costs one WireGuard handshake when traffic resumes rather than a
TLS handshake storm. But "probably" is doing the work there, and the brief's own ordering is
correctness first, then power. This is therefore a change to ship only behind device validation
on a real mobile network: measure the mapping lifetime, confirm recovery, and only then decide
whether the saving is worth it.

What would make it implementable without that validation is a value that is lengthened by a
bounded factor rather than suspended — long enough to remove most of the wakeups, short enough to
stay inside a conservative mapping lifetime — but choosing that bound is exactly the measurement
this note is saying has not been done.
