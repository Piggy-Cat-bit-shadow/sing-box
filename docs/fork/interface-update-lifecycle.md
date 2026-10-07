# What `InterfaceUpdated` does, and what it should do

An interface notification reaches every endpoint, inbound and outbound as
`adapter.InterfaceUpdateListener.InterfaceUpdated`. The question this document answers is not "should
it be called" — it should — but **what each implementation is entitled to assume from it**.

The reason to write it down: `ConnectionManager` no longer closes managed connections on a network
transition (see `conn_reclaim.go`), and that is only half the story. A stream is not independently
alive; it is carried by an outbound's session. An outbound that treats the notification as
"everything is dead" defeats the drain underneath it, with no symptom at the connection layer to
show for it.

## The inventory

Classification per the brief:

| | meaning |
| --- | --- |
| **A** | must reset immediately; the socket is bound to a path that is gone |
| **B** | may be kept; reset on observed failure instead |
| **C** | the protocol can migrate; use that rather than reconnecting |
| **D** | refresh state only — no data path is torn down |

| Implementation | Does | Class | Evidence |
| --- | --- | --- | --- |
| `protocol/group/urltest.go` | re-tests, after checking the pause state | **D** | the only listener that consults `IsDevicePaused`/`IsNetworkPaused` (line 287) |
| `protocol/tun/inbound.go` | `tunStack.ResetNetwork()` | **D** | rebinds the stack's addresses; no session |
| `protocol/direct/outbound.go` | `fetchMyAddresses()`, close ICMP port | **D** | refreshes local addresses only |
| `protocol/direct/inbound.go` | `udpNat.Purge()` | **D** | NAT mappings are keyed by the old source address |
| `protocol/redirect/tproxy.go` | `udpNat.Purge()` | **D** | same |
| `protocol/tailscale/*` | `netMon` / `node.interfaceUpdated()` | **C** | delegates to tailscale's own path manager, which is migration-aware |
| `protocol/trojan/outbound.go`, `protocol/vmess/outbound.go` | `transport.Close()`, `multiplexer.Reset()` | **A** | pooled TCP/QUIC transports keyed to the old path |
| `protocol/http/outbound.go` | `client.ResetConnections()` | **A** | TCP connection pool |
| `protocol/naive/outbound.go` | `client.CloseAllConnections()` | **A** | cronet pool |
| `protocol/snell/outbound.go` | `client.Reset()` | **A** | multiplexed TCP |
| `protocol/ssh/outbound.go` | `common.Close(s.clientConn)` | **A** | a single TCP socket |
| `protocol/anytls/outbound.go` | `client.Reset()` | **A** | session pool |
| `protocol/hysteria/outbound.go`, `protocol/hysteria2/outbound.go` | `CloseWithError("network changed")` | **A** | QUIC, but the session is closed rather than migrated |
| `protocol/masque/client.go` | `client.RestartSession()` | **A** | see below |
| `protocol/openconnect/client.go`, `protocol/openvpn/client.go` | `client.RestartSession()` | **A** | tunnel session |
| `transport/masque/client.go` | `RestartSession` | **A** | cancels the current session and calls `httpClient.ResetConnections()` |

`build/`-time and wireguard device paths are not listed: they are constructed per network, not
notified.

## What `RestartSession` actually does

```go
func (c *Client) RestartSession() {
	c.access.Lock()
	c.restarting = true
	if c.current != nil {
		c.current.cancel(E.New("network changed"))
	}
	c.lastError = nil
	c.notifyStateLocked()
	c.access.Unlock()
	c.httpClient.ResetConnections()
}
```

Every notification cancels the live session and resets the HTTP client, so a MASQUE user is
disconnected on a Wi-Fi roam that may not have broken anything.

## Two things the code shows, and one it does not

1. **No implementation uses QUIC connection migration.** A search for migration-capable dialling
   across `transport/masque` and the hysteria outbounds finds none. The HTTP/3 and QUIC-based
   outbounds therefore have no fallback but reconnection, which is why class A is where they sit —
   not because migration is impossible, but because nothing here attempts it.
2. **Only one listener consults the platform's pause state** (`urltest`, line 287), even though
   `pause.Manager` already exposes `IsNetworkPaused`/`IsDevicePaused` and `NetworkManager` drives
   them from the platform's own report. Every other class-A listener tears down unconditionally,
   including while the device is known to be offline — where the teardown cannot lead to a working
   connection and only produces a dial that is certain to fail.
3. **What is not established:** whether the observed behaviour is *necessary*. Class A above records
   what each implementation does and why its socket is plausibly path-bound. It does not establish
   that a medium transition must be acted on at the instant it arrives rather than on the wake
   notification that follows it.

## What was done about it

`NetworkManager.resetNetworkLocked` now skips the endpoint, inbound and outbound notifications while
`pause.Manager` reports the network paused, and lets the wake notification run the same body with the
pause lifted. The work is deferred, not dropped, and no protocol implementation changed — so a
listener still needs no opinion about the platform's state, and the ones that already had one
(`urltest`) are not double-guarded.

`router.ResetNetwork()` stays unconditional, deliberately: it is where the DNS transports and their
environment pins move together, so gating it on the pause would let the pin and the socket disagree.

This does not turn class A into class B. A socket that is genuinely dead still fails on its own and
reconnects; what was removed is the teardown issued while there is provably nowhere to reconnect to.
The class-C question — whether the QUIC-based outbounds should migrate rather than reconnect — is
untouched and remains open, because nothing in this tree attempts migration today.

---

# Medium-transition audit: the three open questions

The section above closed the offline case. These are the three that were still open, audited
individually rather than answered by a rule.

## A. Is a medium transition still tearing carriers down unnecessarily?

**Two carriers audited in detail. Both keep their teardown, and for stated reasons — not by default.**

### MASQUE

`InterfaceUpdated → client.RestartSession()`, which cancels the live session and calls
`httpClient.ResetConnections()`.

The reconnect machinery would cope without it. `Client.loop()` calls `connect()`, which establishes
the session **and blocks until it ends**; when it returns, the loop backs off (`reconnectBackoffInitial`)
and re-establishes. So failure-driven reconnect already exists, and on that evidence alone the eager
restart looks redundant.

It is not, and the reason is what the session does *not* have: a search across `transport/masque`
finds a dial timeout (`C.TCPTimeout`) and **no session keepalive and no read deadline**. Once
established, nothing in this implementation probes liveness. A half-open path — the common outcome of
a handover, where the peer never sends a reset — is therefore undetectable by the session itself, and
for an HTTP/2 tunnelled session over TCP there is no lower layer that will notice either. The
notification is the only signal available, so cancelling on it is the backstop that makes the
reconnect loop reachable at all.

The nuance worth recording: that argument is about the TCP case. **HTTP/3 rides QUIC, which has its own
idle timeout**, so a dead H3 path is detected without help, and the restart is *not* needed there. The
client knows which it is — `clientSession.tunnelTransport` is recorded per session and
`ClientHandlerWithTunnelTransport` exists to report it — so a transport-conditional preserve is
reachable. It is **not implemented here**: it needs a new accessor on `*masque.Client`, and there is no
way to verify session preservation without a real HTTP/3 endpoint. Recorded as the next step rather
than guessed at.

### AnyTLS

`InterfaceUpdated → client.Reset()`. In `sing-anytls`:

```go
func (c *Client) Reset() {
	for closing := range c.sessions { ... }
	clear(c.sessions)
	c.idleSessions.Init()
	...
}
```

It closes **every** session, active streams included — not only idle ones. The library does maintain an
`idleTimeout` and can tell idle from active (`time.Now().Add(-c.idleTimeout)`), but it exposes no
"drop the idle ones" entry point, so the fork's only leverage is the blunt one. Same liveness position
as MASQUE H2: TLS over TCP, no session keepalive, so the notification is the only signal. Kept, with
that evidence.

## B. Is the DNS transport being reset more than it needs to be?

**No. The reset is required by the pin model, and this is Result B, not a deferral.**

`Router.ResetNetwork` resets each transport, and `route/network_environment.go` already carries the
argument: the answer cache is namespaced by a **per-transport environment pin**, and a transport does
not hold one socket for its life — TCP, TLS and HTTPS re-dial through their dialer, and a dial resolves
the routes of the moment. Rebinding the pin without tearing down the socket is *worse* than the bug it
would fix: a live connection on the OLD network would begin filing its answers under the NEW
environment. The pin and the socket have to move together, which is what the reset does.

A generation-aware lazy reuse would need all three of: an old socket keeping the old environment's
identity, a new socket getting the new one, and no stale answer reaching the new generation's cache.
No such model exists here, and inventing one to save a handshake would trade a correctness invariant
for a micro-optimisation. Per the brief's §13, this is the accepted engineering answer.

The stampede side is addressed separately and already landed: the serial pool establishes with
`MaxInflight: 1`, so twenty waiting queries produce one dial rather than twenty.

## C. Does outbound reconnect bypass the governor, and does it matter?

It bypasses it — the governor bounds dials made by `ConnectionManager`, and an outbound's own
`InterfaceUpdated` path never passes through there — and **it does not matter at the scale the
governor exists for.**

The distinction is what the unit of work is. The DNS stampede was **per query**: every waiting query
that found no connection dialled, so the herd grew with traffic. Carrier reconnect is **per outbound**:
one session per configured outbound, whatever the load. A device with a handful of outbounds produces a
handful of rebuilds; the number is fixed by configuration and cannot be amplified by a burst of user
traffic.

So the brief's ordering holds without a second limiter: nothing here reconnects that does not need to,
same-resource rebuilds are already single (one session per client), and what remains is bounded by
configuration rather than by load. Adding a semaphore over it — the brief's §9 warns against exactly
that — would buy nothing and would risk the failure modes it lists: a slot held across a backoff, a
priority flow queued behind carrier recovery.
