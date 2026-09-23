# AnyTLS inbound fallback

This fork exposes the `FallbackHandler` already provided by `sing-anytls` as an
optional `fallback` object on an AnyTLS inbound. It is useful when an AnyTLS TLS
endpoint should send unauthenticated probes or ordinary browser traffic to a
decoy TCP service instead of immediately closing the connection.

```json
{
  "type": "anytls",
  "tag": "anytls-in",
  "listen": "127.0.0.1",
  "listen_port": 28436,
  "users": [{"name": "example", "password": "example"}],
  "tls": {
    "enabled": true,
    "alpn": ["http/1.1"],
    "certificate_path": "/path/to/fullchain.pem",
    "key_path": "/path/to/private.key"
  },
  "fallback": {
    "server": "127.0.0.1",
    "server_port": 28437
  }
}
```

The fallback is raw TCP **after TLS termination**. For the example above, port
28437 should normally serve plaintext HTTP/1.1, not HTTPS. `sing-anytls` keeps
the probe bytes it read while checking authentication in its cached connection,
so the backend receives the complete original stream.

No fallback is attempted for authenticated AnyTLS users, and omitting
`fallback` preserves upstream authentication-failure behavior. The fallback
destination must have a non-empty `server` and a non-zero `server_port`; invalid
configuration fails during `sing-box check`/inbound creation.

This feature does not override TLS ALPN. Set `tls.alpn` explicitly when using a
browser-style backend. If `h2` is negotiated, the backend receives plaintext
HTTP/2 preface and frames and must support h2c; this fork does not translate
HTTP/2 to HTTP/1.1.

The fallback backend is directly dialed only after authentication fails. It
does not change the AnyTLS wire protocol, padding, authentication, outbound, or
normal multiplexed data path. Run `go test ./protocol/anytls ./option` and
`sing-box check -c config.json` before deployment.
