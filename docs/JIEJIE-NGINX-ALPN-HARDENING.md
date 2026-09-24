# Nginx Stream ALPN hardening for the MASQUE H2 front door

## Scope

This document is about the **production front door**, not about sing-box.

TCP/443 belongs to Nginx. sing-box owns UDP/443 and the loopback backends only.
Nothing described here changes a single byte of any wire protocol, and no
sing-box source file is involved. If you are looking for a sing-box code change,
there is deliberately none: the fix belongs in the layer that already terminates
TCP/443.

This document is also **not** a deployable configuration. There is no production
Nginx configuration in this repository, so inventing one and committing it would
be fiction. What follows is a described, syntax-reviewed `map` design to be
applied to the real configuration on the server, by an operator, deliberately.

## The problem

The production target is:

```
Public TCP/443 -> Nginx Stream (ssl_preread) -> 127.0.0.1:28440
127.0.0.1:28440 -> sing-box HTTP inbound, version = 2  (HTTP/2 ONLY)
```

`version: 2` means the loopback listener speaks HTTP/2. It does **not** serve
HTTP/1.1. The inbound is reached by SNI alone, so every TCP connection whose SNI
is `riri.zhuzhu.jiejie12131.top` is handed to an HTTP/2-only listener:

| Probe | ALPN offered | What happens today |
| --- | --- | --- |
| Browser | `h2` | HTTP/2; unauthorised requests get the masquerade web decoy |
| Browser (legacy) | `http/1.1` | Lands on an H2-only listener |
| Old client | *no ALPN* | Lands on an H2-only listener |
| Scanner | random/garbage | Lands on an H2-only listener |

The last three cases are the issue. An HTTP/2-only endpoint does not behave like
a normal HTTPS website for a client that negotiates `http/1.1` or no ALPN at all:
the TLS handshake can complete while the HTTP conversation then fails in a way
that an ordinary web server would not produce. That is a difference a prober can
observe, and it is observable **before** authentication is ever considered.

This is exactly the kind of active-probe signal this project cares about: it
leaks that the endpoint is not a plain website, without revealing anything about
the proxy authentication surface.

## Where the fix belongs

**Nginx Stream, not sing-box.**

The alternatives were considered and rejected:

- *Enable HTTP/1.1 on the sing-box H2 inbound.* Rejected. That would make HTTP/1
  a first-class proxy protocol on the public path and widen the attack surface
  for no functional gain. HTTP/1 must not become a proxy protocol here.
- *Add an SNI+ALPN dispatcher inside sing-box.* Rejected. It duplicates Nginx's
  job and violates the topology contract that Nginx owns TCP/443.
- *Return a special error for non-H2 ALPN.* Rejected. Returning a distinguishable
  proxy-shaped error is the opposite of the goal.

Nginx already reads ALPN during `ssl_preread`, so it can make this decision for
free, before any TLS session reaches sing-box.

## The design

`ssl_preread` exposes two independent facts: the SNI name
(`$ssl_preread_server_name`) and the ALPN protocol list
(`$ssl_preread_alpn_protocols`, a comma-separated string such as `h2` or
`http/1.1`).

The MASQUE H2 SNI must route to `28440` **only** when the client actually
negotiated `h2`. Everything else for that SNI must be treated as ordinary web
traffic.

The `map` therefore needs a compound key, because Nginx `map` matches one source
variable. The standard way is to build a combined key with a second `map`:

```nginx
stream {
    # 1. Normalise the ALPN list into a marker meaning "this client offered h2".
    #    $ssl_preread_alpn_protocols is a COMMA-SEPARATED list, so this is a
    #    list-membership test, not a substring test: "h2" must appear as a whole
    #    entry. Anchoring on a comma (or the start/end of the string) is what
    #    keeps a future "h2c"-like value from matching by accident.
    map $ssl_preread_alpn_protocols $jiejie_wants_h2 {
        default            0;
        "~*(^|,)h2(,|$)"   1;
    }

    # 2. Build a compound key "<sni> <wants_h2>" for the MASQUE SNI only. A
    #    space cannot occur in either component, so it is an unambiguous
    #    separator. Every other SNI resolves to the literal "other", which is
    #    deliberately NOT a key in the next map, so it falls through to the
    #    default there.
    map $ssl_preread_server_name $jiejie_masque_key {
        default                        "other";
        "riri.zhuzhu.jiejie12131.top"  "riri";
    }
    map "$jiejie_masque_key $jiejie_wants_h2" $jiejie_masque_backend {
        default     "";
        "riri 1"    127.0.0.1:28440;
        "riri 0"    127.0.0.1:9443;
    }

    # 3. The EXISTING per-SNI map. Untouched except that the MASQUE SNI now
    #    points at the compound result instead of a fixed backend. Every other
    #    entry stays byte-for-byte as it is today.
    map $ssl_preread_server_name $jiejie_backend {
        default                        127.0.0.1:28440;
        "riri.zhuzhu.jiejie12131.top"  $jiejie_masque_backend;
        # ... every other SNI entry UNCHANGED ...
        # "api.zhuzhu.jiejie12131.top"   127.0.0.1:28436;
        # "www.intel.com"                127.0.0.1:8554;
    }

    server {
        listen      443;
        proxy_pass  $jiejie_backend;
        ssl_preread on;
    }
}
```

Two properties of this shape are worth stating explicitly, because they are the
reason it is safe to apply:

- The compound key map is consulted **only** for the riri SNI. Every other SNI
  resolves to `other`, which is intentionally not a key in
  `$jiejie_masque_backend`, so those SNIs never depend on the compound logic at
  all.
- `$jiejie_masque_backend` defaults to the **empty string**, not to a backend.
  That is deliberate: if the riri entry were ever mistyped so that no key
  matched, an empty `proxy_pass` target is a loud, obvious failure in `nginx -t`
  rather than a silent misroute of MASQUE traffic to the web backend (or vice
  versa). Do not "helpfully" give that map a real default -- the safety comes
  from the failure being loud.
- Every non-riri SNI continues to resolve through a single variable exactly as
  it does today.

`9443` stands for the existing normal HTTPS web backend that already serves the
`28437` site. Substitute whatever that backend actually is; the point is that a
non-`h2` client for the MASQUE SNI is served the *same* website as any other
browser, by the same web server, over HTTP/1.1.

### Why not collapse it into one map

A single `map "$ssl_preread_server_name:$ssl_preread_alpn_protocols"` is
possible, but it requires enumerating every SNI × ALPN combination, and every
*other* SNI must then be listed with every ALPN value it might use. That is
fragile: adding a new SNI, or a client that negotiates an ALPN nobody listed,
silently changes routing. The two-step form above keeps the non-MASQUE SNIs on
their existing single-variable map, so **only** the riri SNI is affected by this
change.

## Rules that must not be broken

- **Only the MASQUE H2 SNI is remapped.** `anytls`, `shadowtls`, `reality`,
  subscription and Naive entries go in the *existing* `map` untouched. Adding an
  entry to a `map` that keys on the full ALPN string for every SNI is how these
  get broken; that is why the design above does not do it.
- **XHTTP and any other HTTP-based path must keep its current routing.** If it
  shares the riri SNI, it needs an explicit decision before this map is applied;
  do not assume it is unaffected.
- **`ssl_preread on;` must stay on the `server` block.** Without it the
  `$ssl_preread_*` variables are empty, both maps take `default`, and every
  client goes to one backend.
- **No `proxy_protocol` change** is implied here. If the front door already
  sends PROXY protocol to a backend, keep doing exactly that for both targets.

## How to verify before trusting it

1. `nginx -t` on the real server. The `map` syntax above is standard, but the
   interaction with the existing `map` is what `-t` will catch.
2. For each SNI in the existing map, confirm the resolved backend is *unchanged*
   for a plain `openssl s_client -alpn h2` and for no ALPN. Do this per SNI, not
   just for riri.
3. Confirm the MASQUE SNI with `h2` still reaches `28440` and that an
   authenticated MASQUE CONNECT still works end to end.
4. Confirm the MASQUE SNI with `http/1.1` and with no ALPN now reaches the web
   backend and returns a normal page.

## Honest limits

- This closes the **ALPN/HTTP-version** boundary for the TCP/443 MASQUE path.
  It does not make the endpoint undetectable.
- HTTP/3 and MASQUE have protocol-observable capabilities (QUIC, SETTINGS,
  `H3_DATAGRAM`, Extended CONNECT). Those are visible on UDP/443 by design and
  no Nginx rule changes that. See
  [JIEJIE-PROBE-RESISTANCE-MATRIX.md](JIEJIE-PROBE-RESISTANCE-MATRIX.md).
- Because there is no production Nginx configuration in this repository, **none
  of the above is applied by any build, test or CI job in this repo.** It is an
  operator-facing hardening step that must be applied and verified on the
  server.
