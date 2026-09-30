---
icon: material/new-box
---

!!! question "Since sing-box 1.12.0"

### Structure

```json
{
  "type": "anytls",
  "tag": "anytls-in",

  ... // Listen Fields

  "users": [
    {
      "name": "sekai",
      "password": "8JCsPssfgS8tiRwiMlhARg=="
    }
  ],
  "padding_scheme": [],
  "fallback": {
    "server": "127.0.0.1",
    "server_port": 8080
  },
  "fallback_for_alpn": {
    "http/1.1": {
      "server": "127.0.0.1",
      "server_port": 8080
    }
  },
  "tls": {}
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### users

==Required==

AnyTLS users.

#### padding_scheme

AnyTLS padding scheme line array.

Default padding scheme:

```json
[
  "stop=8",
  "0=30-30",
  "1=100-400",
  "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
  "3=9-9,500-1000",
  "4=500-1000",
  "5=500-1000",
  "6=500-1000",
  "7=500-1000"
]
```

#### fallback

Default fallback destination for connections that are not an accepted AnyTLS session. The backend
receives the **decrypted** stream, so it is reached after TLS termination.

`server` must be non-empty and `server_port` non-zero; an invalid value fails configuration load.

An authenticated AnyTLS session never falls back. The backend is dialed only after authentication
fails.

Do not point a fallback at the AnyTLS listener itself: that configuration loops.

#### fallback_for_alpn

ALPN-specific fallback destinations, keyed by the negotiated ALPN.

When this field is present, a **negotiated** ALPN with no matching entry is rejected. The default
[`fallback`](#fallback) is used only when no ALPN was negotiated at all.

The fork does not translate HTTP/2 to HTTP/1.1. A backend reached with `h2` negotiated receives the
plaintext HTTP/2 preface and frames, so it must genuinely support h2c; advertising only `http/1.1`
with a plaintext HTTP/1.1 backend is the simple deployment. This field does not override TLS ALPN —
set [`tls.alpn`](/configuration/shared/tls/#inbound) explicitly.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).
