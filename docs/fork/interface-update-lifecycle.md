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
