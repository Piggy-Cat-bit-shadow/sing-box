`socks` outbound is a socks4/socks4a/socks5 client.

### Structure

```json
{
  "type": "socks",
  "tag": "socks-out",
  
  "server": "127.0.0.1",
  "server_port": 1080,
  "version": "5",
  "username": "sekai",
  "password": "admin",
  "network": "udp",
  "udp_over_tcp": false | {},
  "tcp_preconnect": {
    "enabled": true,
    "min_idle": 2,
    "max_idle": 4,
    "idle_timeout": "20s"
  },
  "tcp_tuning": {
    "early_buffer_growth": true
  },

  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### version

The SOCKS version, one of `4` `4a` `5`.

SOCKS5 used by default.

#### username

SOCKS username.

#### password

SOCKS5 password.

#### network

Enabled network

One of `tcp` `udp`.

Both is enabled by default.

#### udp_over_tcp

UDP over TCP protocol settings.

See [UDP Over TCP](/configuration/shared/udp-over-tcp/) for details.

#### tcp_preconnect

Opt-in pool of already-authenticated SOCKS5 TCP connections. Disabled by default, and disabling it
keeps the upstream behaviour exactly: no pool, no goroutine, no extra socket.

Requires `version` `5`; other versions are rejected.

| Field | Description |
| --- | --- |
| `enabled` | Enable the pool. |
| `min_idle` | Parked connections the pool maintains. Default `2`. |
| `max_idle` | Upper bound on parked connections, including those still being established. Default `4`. |
| `idle_timeout` | Closes a parked connection that has waited this long. Default `20s`. |

A bare `"enabled": true` yields a small bounded pool. The pool keeps `min_idle` ready; it does not
try to fill to `max_idle`.

Current behavior:

- When a parked connection exists, the flow issues only its CONNECT.
- When the pool is empty, the cold path runs immediately; the caller never waits for a refill.
- A stale parked connection is discarded and the request falls back to **exactly one** cold attempt.
- A CONNECT that has already been accepted is never retried, because retrying could duplicate its
  effect. A SOCKS5 connection carries exactly one command, so a parked connection that has carried a
  CONNECT is a tunnel and is never returned to the pool.
- Refill failures back off boundedly, from 500 ms doubling to a 30 s ceiling, reset on success.
- A parked connection that idles too long is closed by the pool. No ping is ever written: after
  authentication the next frame must be a command request, so a speculative read would corrupt the
  connection state.
- Reloading or removing the outbound stops the loop and closes every parked socket.

The pool is **TCP CONNECT only**. It never applies to SOCKS4, to UDP ASSOCIATE, to BIND or to UoT.
Pooled connections use the outbound's own dialer, so `bind_interface`, `routing_mark`, `netns`,
connect timeout, TCP Fast Open, keepalive, `detour` and `auto_detect_interface` apply to them exactly
as to a cold connection. Credentials are never logged.

#### tcp_tuning

Copy-path tuning for a chained hop.

| Field | Description |
| --- | --- |
| `early_buffer_growth` | Let the copy path switch to a large buffer after the first transfer instead of waiting for the default threshold. Off by default. |

A chained hop carries an extra segment, so waiting for the framework's default byte threshold delays
the point where a larger buffer pays off. This is a **capability** rather than a tag check: it is
consulted on the dialer that was actually selected, so a `selector` or `urltest` group resolves to
the member that served the connection. Only an explicitly opted-in outbound is affected; every other
outbound, including every other SOCKS outbound, keeps the default.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
