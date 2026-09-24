# Native NaiveProxy server

This document describes running the Naive inbound in this fork as a standalone
NaiveProxy server, including the UoT (UDP over TCP) extension, without Caddy.

## What this is, and what it is not

Three different things are routinely conflated. This fork implements one of them:

| Project | Role |
| --- | --- |
| [klzgrad/naiveproxy](https://github.com/klzgrad/naiveproxy) | The **client**, built on the Chromium network stack. Defines the protocol this server must speak. |
| [klzgrad/forwardproxy](https://github.com/klzgrad/forwardproxy) | The **Caddy server plugin**. The reference server implementation. |
| [aUsernameWoW/forwardproxy (udpintcp)](https://github.com/aUsernameWoW/forwardproxy/tree/udpintcp) | The reference server **plus a UoT extension**. |

This fork's Native Naive is a sing-box inbound that speaks the reference protocol
and additionally carries UoT. It does **not** embed Caddy, and it does not
implement its own network stack: unpacked UDP goes through sing-box's own router,
DNS and outbounds.

A plain NaiveProxy client interoperates for **TCP**. UoT is a separate extension;
a stock NaiveProxy client does not use it, and the fact that UDP works from a
sing-box client says nothing about TCP compatibility with the original client.

## Topology

```
client
  |
  v
TCP/443  ->  Nginx Stream (SNI)  ->  127.0.0.1:28545  sing-box naive inbound
                                                          |-- authenticated CONNECT -> TCP target
                                                          |-- authenticated UoT     -> UDP target (via router)
                                                          |-- anything else         -> masquerade website
```

UoT runs **inside** an HTTP/2 CONNECT over TCP. It needs **no UDP listener** and
no `UDP/443` allocation; that port remains available for MASQUE HTTP/3.

## Configuration

### Inbound

```json
{
  "type": "naive",
  "tag": "naive-in",
  "listen": "127.0.0.1",
  "listen_port": 28545,
  "network": "tcp",
  "users": [
    {
      "username": "REPLACE_WITH_USERNAME",
      "password": "REPLACE_WITH_PASSWORD"
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "example.invalid",
    "certificate_path": "/path/to/fullchain.pem",
    "key_path": "/path/to/private.key"
  },
  "masquerade": {
    "type": "proxy",
    "url": "http://127.0.0.1:28437",
    "rewrite_host": true
  }
}
```

`network: "tcp"` is correct and does **not** disable UDP. `network` selects the
**listener**; UoT is carried inside the TCP connection and needs no UDP listener.

### Outbound (client side, for reference)

```json
{
  "type": "naive",
  "tag": "naive-out",
  "server": "example.invalid",
  "server_port": 443,
  "username": "REPLACE_WITH_USERNAME",
  "password": "REPLACE_WITH_PASSWORD",
  "tls": {
    "enabled": true,
    "server_name": "example.invalid"
  },
  "udp_over_tcp": {
    "enabled": true,
    "version": 2
  }
}
```

`insecure_concurrency` keeps its existing meaning and default. It is a
client-side setting and is not required by this server.

## UoT: how UDP is carried

An authenticated `CONNECT` to a **magic address** marks the stream as a UoT
tunnel. The two versions use different addresses and different framing, and are
decoded separately:

| Version | Magic address | Framing |
| --- | --- | --- |
| v2 | `sp.v2.udp-over-tcp.arpa` | `isConnect` byte + destination, then length-prefixed datagrams |
| v1 (legacy) | `sp.udp-over-tcp.arpa` | no request header; every datagram carries its own destination |

In v2 the destination is sent once at the start (`isConnect` mode); in v1 it is
repeated on every datagram, which is what lets one v1 session address several
targets.

Two details are easy to get wrong and are worth stating, because they are what
most implementations trip over:

1. The v2 **request header** uses the SOCKS5 address serializer
   (`0x01`=IPv4, `0x04`=IPv6, `0x03`=FQDN), while **per-datagram** addresses use
   the UoT address parser (`0x00`=IPv4, `0x01`=IPv6, `0x02`=FQDN). They are
   genuinely different encodings inside one protocol. Mixing them up produces
   `unknown address family: 0`.
2. The v2 request header travels **inside** the tunnel, so when padding was
   negotiated it must itself be wrapped in a padding frame.

### Routing

Unpacked datagrams are handed to sing-box's own router as a `PacketConnection`,
with the authenticated username preserved in the inbound context. They are
therefore subject to the normal routing rules, DNS, outbound selection and access
control. The magic address is never treated as a real destination: it selects the
UoT decoder, and the real target is the one carried inside the tunnel.

## Padding

Padding is negotiated, not required. A client that sends a `Padding` header gets
the padding frame codec for the first 8 frames in each direction; a client that
does not gets plain byte-for-byte I/O. A `CONNECT` **without** a `Padding` header
is a valid plain HTTP proxy request and is treated as one.

The frame layout is fixed by the reference implementation and is not changed:

```
[2-byte big-endian data size][1-byte padding size][data][that many zero bytes]
```

Both frame fields have fixed widths, so a hostile frame cannot drive a large
allocation.

## Masquerade

With `masquerade` configured, everything that is not an authenticated `CONNECT` is
served from the configured website: browser requests, probes, and proxy attempts
with missing or wrong credentials. Without it the upstream behaviour applies
(`407` for an unauthenticated `CONNECT`, `400` for a non-`CONNECT` request).

The important property is asymmetric:

* an ordinary browser request gets a normal website;
* an unauthenticated or malformed `CONNECT` **never** opens a tunnel.

Note that an unauthorised `CONNECT` may legitimately receive `200`, because it is
relayed to the Web backend and a website may answer `200` with its own page. What
matters is that the response is the **website** and never the CONNECT target's
content. Do not use the status code alone as the security check.

`Proxy-Authorization` is stripped before the request reaches the Web backend, and
the reverse-proxy target is fixed by configuration, so the masquerade cannot be
used as an open proxy via the `Host` header or an absolute request target.

## HTTP/2 resource bounds

The inbound runs an `x/net/http2` server whose bounds are configurable:

| Option | Server field | Effect |
| --- | --- | --- |
| `max_concurrent_streams` | `MaxConcurrentStreams` | concurrent tunnels per connection |
| `idle_timeout` | `IdleTimeout` | idle HTTP/2 connection lifetime |
| `stream_receive_window` | `MaxUploadBufferPerStream` | per-stream server-side admission buffer |
| `connection_receive_window` | `MaxUploadBufferPerConnection` | per-connection admission buffer |

All are optional, and leaving them unset keeps the upstream defaults. The receive
windows are **server-side admission** bounds: they limit how much a peer may have
in flight toward this server. They are not the client's
`stream_receive_window`, whose useful direction is the opposite one.

## Resource behaviour

A finished UoT session releases its resources. This fork's tests assert that
finished sessions do not accumulate goroutines or sockets, including after abrupt
client disconnects, because the Caddy fork this replaces was patched for exactly
that leak. An active session legitimately holds resources; the requirement is that
**finished** ones do not.

## Verifying a deployment

```sh
TAGS="with_quic,badlinkname,tfogo_checklinkname0,with_naive_outbound"

# Inbound/option unit tests
go test -tags "$TAGS" ./protocol/naive/

# Wire-level TCP, UoT, masquerade and lifecycle tests.
# NOTE: these need the FULL registry; do NOT add jiejie_server_minimal, which
# deliberately does not register the Naive inbound.
(cd test && go test -tags "$TAGS" -run 'TestJiejieNaive' ./jiejie/)
```
