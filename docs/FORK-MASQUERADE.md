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
workflow builds with `release/DEFAULT_BUILD_TAGS_OTHERS`, which includes `with_quic`.

## Logging

When a masquerade handler is configured, an unauthenticated or wrong-password
request is the intended design path: the client receives an ordinary web
response. Those requests are logged at **debug**, not error. Without a masquerade
handler a real `401`/`407` is still returned and still logged at **error**, so
genuine authentication failures remain visible.

## Interaction with `unauthenticated_limits`

The optional `unauthenticated_limits` object bounds pre-authentication traffic per
source IP. It is an accounting pre-filter: a request is rejected only when it
**both** fails authentication **and** exceeds the budget. A legitimate
authenticated client is never denied service by it, and the limit is released the
moment authentication succeeds.

A rejected request receives a locally generated `429` decoy, and never receives
`401`/`407` or an authentication header. It also never reaches the masquerade
backend, which is what makes the limiter an actual resource bound; serving the
proxy masquerade over-limit would still issue one backend request per probe.

The decoy keeps the proxy signal out but is not claimed to be
path-indistinguishable: it answers every over-limit request with the same body and
does not forward the request path. Forwarding the path would require reaching the
backend, which is what the limiter exists to prevent.

## Tests

Real end-to-end coverage lives in `test/jiejie_server_test.go`
(`TestJiejieMASQUEH2Masquerade`, `TestJiejieMASQUEH3Masquerade`,
`TestJiejieMASQUEH3UnauthenticatedLimits`,
`TestJiejieMASQUEH3AuthenticatedTrafficNotLimited`). The H3 cases use a real
quic-go HTTP/3 client rather than curl, so they do not depend on the runner's
curl supporting HTTP/3.

To sync upstream, fetch `upstream`, rebase these feature commits on the target
branch, run the HTTP test suite and `./test/...`, and push the rebased feature
branch. Do not force-push upstream history.
