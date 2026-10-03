### Structure

```json
{
  "type": "urltest",
  "tag": "auto",
  
  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "url": "",
  "interval": "",
  "tolerance": 0,
  "idle_timeout": "",
  "interrupt_exist_connections": false
}
```

### Fields

#### outbounds

==Required==

List of outbound tags to test.

#### url

The URL to test. `https://www.gstatic.com/generate_204` will be used if empty.

#### expected_status

The HTTP status codes that count as reachable. Empty accepts any status.

Accepted syntax:

```text
*                 any status
204               exactly 204
200-299           a range
200/204/301-399   several, separated by /
200,204,301-399   several, separated by ,
```

Ranges may be reversed (`299-200` means `200-299`), and the list may contain at most 28 entries.

This is part of the group's measurement identity: a group requiring `204` is asking a different
question from one accepting any status, so the two do not share history even for the same URL.

#### interval

The test interval. `3m` will be used if empty.

#### tolerance

The test tolerance in milliseconds. `50` will be used if empty.

#### idle_timeout

The idle timeout. `30m` will be used if empty.

#### interrupt_exist_connections

Interrupt existing connections when the selected outbound has changed.

Only inbound connections are affected by this setting, internal connections will always be interrupted.

### Unified delay

A measurement makes exactly two HTTP requests over one connection:

```text
dial (not timed)
  ↓
HEAD #1  warm-up: proxy path, TLS, HTTP and mux setup
  ↓
HEAD #2  timed: the delay shown and compared
```

The first request carries the one-off costs, so the reported delay reflects the path rather than the
setup. If the second request fails in a way that does not indicate a broken node - the server closed
a reused connection, say - the node is still considered reachable and the reported delay is the
whole attempt.

Only one outbound connection is made per measurement, and it is handed to the HTTP client at most
once.

### History

Two layers are kept, and they are independent:

- **Display** - one entry per node: the last successful measurement, whatever URL produced it. This
  is what a node list or a Clash proxy entry shows. A manual delay probe updates it.
- **Health** - one entry per (node, URL, status set). This is what selection, tolerance and interval
  skipping read, and only the group's own automatic checks write it.

A manual probe therefore never affects which node a group selects, and testing an arbitrary URL does
not accumulate state. A failed check removes only its own entry and never erases a node's last
successful measurement.
