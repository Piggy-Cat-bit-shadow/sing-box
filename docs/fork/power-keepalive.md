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
