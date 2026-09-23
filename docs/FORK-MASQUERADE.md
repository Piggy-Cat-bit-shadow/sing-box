# HTTP inbound masquerade fork

This fork adds an optional `masquerade` object to the `http` inbound. It is
intended for deployments that serve HTTP/2 and HTTP/3 on the same endpoint and
want unauthenticated probes to receive a normal web response instead of proxy
authentication challenges.

It changes only authentication failures in the shared HTTP/2/HTTP/3 handler.
Authenticated HTTP CONNECT, extended CONNECT, CONNECT-UDP, HTTP Datagram, QUIC
and routing data paths are unmodified. Without `masquerade`, upstream 401/407
responses and authentication headers are unchanged.

```json
{
  "type": "http",
  "tag": "masque-l4-h3",
  "version": [2, 3],
  "users": [{"username": "example", "password": "example"}],
  "masquerade": {
    "type": "proxy",
    "url": "http://127.0.0.1:9444",
    "rewrite_host": true
  }
}
```

The option intentionally uses the existing Hysteria2 masquerade schema: `proxy`,
`file`, and `string`. Invalid types, proxy URLs, and unreadable file directories
make configuration loading fail. The reverse proxy preserves the backend's real
status and response body; it does not manufacture a fixed `200 OK`.

Run `sing-box check -c config.json` before deployment. The focused Linux artifact
workflow builds with `release/DEFAULT_BUILD_TAGS`, which includes `with_quic`.

To sync upstream, fetch `upstream`, rebase this one feature commit on its target
branch, run the HTTP test suite, and push the rebased feature branch. Do not
force-push upstream history.
