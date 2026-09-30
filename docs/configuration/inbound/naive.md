!!! quote "Changes in sing-box 1.13.0"

    :material-plus: [quic_congestion_control](#quic_congestion_control)

### Structure

```json
{
"type": "naive",
"tag": "naive-in",
"network": "tcp",
...
// Listen Fields

"users": [
{
"username": "sekai",
"password": "password"
}
],
"quic_congestion_control": "",

// optional Web masquerade
"masquerade": {
"type": "proxy",
"url": "http://127.0.0.1:28437",
"rewrite_host": true
},

// optional pre-authentication resource bounds
"server_limits": {
"max_connections": 0,
"max_connections_per_ip": 0,
"header_timeout": "",
"max_tracked_ips": 0
},

// optional HTTP/2 server bounds
"max_concurrent_streams": 0,
"idle_timeout": "",
"stream_receive_window": 0,
"connection_receive_window": 0,

"tls": {}
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### network

Listen network, one of `tcp` `udp`.

Both if empty.

#### users

==Required==

Naive users.

#### quic_congestion_control

!!! question "Since sing-box 1.13.0"

QUIC congestion control algorithm.

| Algorithm      | Description                     |
|----------------|---------------------------------|
| `bbr`          | BBR                             |
| `cubic`        | CUBIC                           |
| `reno`         | New Reno                        |

`bbr` is used by default.

#### masquerade

Optional Web masquerade, using the same schema and semantics as the
[HTTP inbound](/configuration/inbound/http/#masquerade).

Requests that are **not** an authenticated Naive `CONNECT` -- an ordinary browser
`GET`/`HEAD`, a probe, or a proxy attempt with no or wrong credentials -- are
answered by the masquerade instead of with a proxy error. This lets a normal
website be served on the same port as the proxy.

This is a **Web response only**. It can never open a proxy tunnel: the tunnel path
requires successful authentication first, and the masquerade handler has no access
to the proxy or UoT data paths. `Proxy-Authorization` is stripped before the
request can reach the Web backend.

Unset means the upstream behaviour: an unauthenticated `CONNECT` is rejected with
`407` and a non-`CONNECT` request with `400`.

#### server_limits

Optional bounds on what a peer may hold **before** it authenticates.

Omitted means unlimited, which is the upstream behaviour: no limit is applied by default, because
this inbound serves long-lived tunnels and a guessed limit would silently break them.

| Field | Description |
| --- | --- |
| `max_connections` | Total concurrent connections on the inbound, authenticated or not. |
| `max_connections_per_ip` | Concurrent connections from one source address. |
| `header_timeout` | How long a connection may take to deliver a complete request once the handshake is done. |
| `max_tracked_ips` | Ceiling on tracked source addresses. Defaults to `4096` when `max_connections_per_ip` is set without it. |

`max_connections` and `max_connections_per_ip` defend different things — total host exposure versus
a single offender — so they are separate. Validation rejects negative values and rejects
`max_connections_per_ip` greater than `max_connections`, which could never take effect.

The per-IP key is the **real transport peer**, never a forwarded header: a client that can name its
own source address would trivially evade a per-IP limit. An IPv4-mapped IPv6 address is unmapped so
it shares one budget with its IPv4 form.

`header_timeout` applies to the **request phase only**. An established tunnel is never subject to
it: a tunnel that is legitimately idle for longer than this must not be torn down.

There is deliberately no `handshake_timeout` here — use
[`tls.handshake_timeout`](/configuration/shared/tls/#inbound), which covers a peer that stalls
*during* the handshake. There is deliberately no `idle_timeout` here —
[`idle_timeout`](#idle_timeout) already provides one.

#### max_concurrent_streams

Maximum concurrent HTTP/2 streams, i.e. concurrent tunnels, per connection.

Unset means the upstream `x/net/http2` default.

#### idle_timeout

HTTP/2 idle timeout.

Unset means the upstream `x/net/http2` default.

#### stream_receive_window

Server-side per-stream upload buffer.

This is an **admission** bound: it limits how much a peer may have in flight
toward this server on one stream. Lowering it is the memory-conservative
direction, and it is not the client-side `stream_receive_window` of the Naive
outbound.

Unset means the upstream `x/net/http2` default.

#### connection_receive_window

Server-side per-connection upload buffer, shared by all streams on the connection.

Unset means the upstream `x/net/http2` default.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).

### UDP over TCP

UoT (UDP over TCP) is carried inside an authenticated HTTP/2 `CONNECT` whose target
is the UoT magic address, so it needs **no UDP listener** and works on an inbound
configured with `"network": "tcp"`.

Both UoT versions are supported and are decoded according to their own framing:

| Version | Magic address | Framing |
| --- | --- | --- |
| v2 | `sp.v2.udp-over-tcp.arpa` | `isConnect` byte + destination, then length-prefixed datagrams |
| v1 (legacy) | `sp.udp-over-tcp.arpa` | no request header; each datagram carries its own destination |

Unpacked datagrams enter the normal sing-box router like any other UDP traffic, so
routing rules, DNS and outbounds apply, and the authenticated user is preserved in
the connection metadata. `network` controls the **listener**; it is not a UoT
switch.

Clients enable it with:

```json
{
"udp_over_tcp": {
"enabled": true,
"version": 2
}
}
```