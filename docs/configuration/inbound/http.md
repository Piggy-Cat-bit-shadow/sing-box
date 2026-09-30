### Structure

```json
{
  "type": "http",
  "tag": "http-in",
  
  ... // Listen Fields
  
  "version": [],
  "users": [
    {
      "username": "admin",
      "password": "admin"
    }
  ],
  "tls": {},
  "set_system_proxy": false,

  // optional Web masquerade
  "masquerade": {
    "type": "proxy",
    "url": "http://127.0.0.1:28437",
    "rewrite_host": true
  },

  // optional pre-authentication limits
  "unauthenticated_limits": {
    "enabled": true,
    "max_concurrent_per_ip": 0,
    "requests_per_second": 0,
    "burst": 0,
    "idle_timeout": "",
    "max_tracked_ips": 0
  },

  ... // HTTP2 Fields / QUIC Fields
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### version

!!! question "Since sing-box 1.15.0"

List of HTTP versions to serve.

Available values: `1`, `2`, `3`.

`1` and `2` are used by default.

TLS is required for `3`.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).

#### users

HTTP users.

No authentication required if empty.

#### set_system_proxy

!!! quote ""

    Only supported on Linux, Android, Windows, and macOS.

!!! warning ""

    To work on Android and Apple platforms without privileges, use tun.platform.http_proxy instead.

Automatically set system proxy configuration when start and clean up when stop.

#### masquerade

Optional Web masquerade, using the same schema and semantics as the Hysteria2 inbound masquerade.
Available types are `proxy`, `file` and `string`.

Requests that are **not** an authenticated `CONNECT` — an ordinary browser request, a probe, or a
proxy attempt with no or wrong credentials — are answered by the masquerade instead of with a proxy
error, so a normal website can share the port.

This is a **Web response only** and can never open a tunnel. A reverse proxy preserves the backend's
real status and body; it does not manufacture a fixed `200 OK`, and `Proxy-Authorization` is
stripped before the request reaches the backend.

Unset means the upstream behaviour: `401`/`407` and the usual authentication headers.

Masquerade does not make the service undetectable. QUIC, HTTP/3 SETTINGS, `H3_DATAGRAM` and Extended
CONNECT remain observable on the wire.

#### unauthenticated_limits

Optional pre-authentication limits. Authenticated proxy traffic is unaffected.

| Field | Description |
| --- | --- |
| `enabled` | Enable the limiter. |
| `max_concurrent_per_ip` | Concurrent unauthenticated requests from one source address. |
| `requests_per_second` | Sustained request rate per source address. |
| `burst` | Short-term burst allowance. |
| `idle_timeout` | Expiry for an idle per-source entry. |
| `max_tracked_ips` | Ceiling on tracked source addresses. |

A request is rejected only when it **both** fails authentication **and** exceeds the budget, so a
legitimate authenticated client is never denied. Accounting is released as soon as authentication
succeeds.

**The limiter is evaluated before the masquerade.** A rejected request receives a locally generated
`429` and never reaches the masquerade backend; serving the proxy masquerade over-limit would still
issue one backend request per probe, which is what the limit exists to prevent.

The source address is what the inbound sees. Behind a front door that forwards at L4, that is the
front door itself unless it supplies a separately trusted identity.

### HTTP2 Fields

!!! question "Since sing-box 1.15.0"

When `version` contains `2`.

See [HTTP2 Fields](/configuration/shared/http2/) for details.

### QUIC Fields

!!! question "Since sing-box 1.15.0"

When `version` contains `3`, [HTTP2 Fields](#http2-fields) are replaced by QUIC Fields.

See [QUIC Fields](/configuration/shared/quic/) for details.
