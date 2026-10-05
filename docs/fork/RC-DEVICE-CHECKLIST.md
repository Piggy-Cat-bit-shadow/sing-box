# RC device checklist

What a device run has to answer that no off-device test can. Each item names the observation, not
the tool, so it can be run whichever way is convenient.

The diagnostics exist for this: the splice summaries are printed once per tunnel lifetime at
shutdown, so the procedure for most items is "start the tunnel, do the thing, stop the tunnel, read
the log".

## Linux (real TUN)

```text
[ ] L0 route exclusion positive control
      - with the default-route exclusion in place: excluded traffic does NOT enter the tun
      - REMOVE the exclusion: the same traffic MUST enter the tun (this is the control; without
        it, "the tun saw no packets" has two explanations and neither is ruled out)

[ ] Startup
      - `sing-box version` on the artifact
      - `sing-box check -c <config>` on the RC configuration
      - start, then confirm the tun device exists and carries the routes

[ ] TCP splice diagnostics
      - "TCP splice diagnostics: attempts=N successes=M ratio=..."
      - record the ratio and every non-zero reason
      - expected on a plain TUN path: successes should be non-zero for direct flows; a
        source_not_go_conn-heavy report means flows are being proxied in userspace, which is a
        routing fact, not a defect
      - a non-zero splice_rejected means an eligible flow was declined by the stack: record it,
        it is the one outcome the Go side cannot explain further

[ ] Traffic accounting
      - the tracker's counters for a flow match the bytes transferred (splice must not lose
        accounting: the counters are passed INTO the handover)
      - close the connection and confirm it leaves the tracker

[ ] DNS and FakeIP
      - a query to the configured DNS address is answered by the configured resolver even with the
        route's final outbound set to a loadbalance group
      - FakeIP: a domain resolves to the FakeIP range and the flow reaches the real destination
      - mapped IPv4: a client reaching the DNS address as ::ffff:a.b.c.d is still hijacked

[ ] Family policies
      - IPv4-only network, IPv6-only network, dual-stack
      - prefer_v4 / prefer_v6 / ipv4_only / ipv6_only behave as configured

[ ] Network transition
      - Wi-Fi to Ethernet (or interface down/up): new flows use the new interface, and a load
        balance group's health evidence is re-read rather than remembered

[ ] Scheduler
      - off: unchanged
      - on: unchanged for a single flow; aggregate pacing visible with several

[ ] Negative controls
      - a load balance member that is unreachable is skipped for NEW flows once its health is
        known-bad, and returns when it recovers
      - a sticky session that pins to a member which then becomes unusable is re-pinned rather
        than dialed
```

## Apple (macOS and iOS)

```text
[ ] Launch, then NetworkExtension start and stop (no leak: repeat 5x)
[ ] DIRECT, then VLESS, AnyTLS, Naive, MASQUE if the RC configuration uses them
[ ] Load balance
      - round robin: independent connections alternate A B C D ... (confirm against the client
        log, the tracker and, if possible, the server)
      - UDP: one member per session across many datagrams
      - health: disable B, confirm new flows skip it; enable B, confirm it returns
      - sticky: the same source+destination keeps its member
      - consistent hashing: the same target keeps its member across reconnects
[ ] DNS and AGH: the configured DNS is used, and a query is not diverted by a load balance group
[ ] FakeIP, and mapped IPv4 if reproducible from the device
[ ] IPv4 / IPv6 / dual-stack on real networks
[ ] Wi-Fi to cellular transition with an active flow
[ ] Dashboard and tracker agree with what the data plane did
[ ] Traffic class: a bulk flow and an interactive flow get the classes the rules name
[ ] Scheduler off, then on
[ ] Memory, CPU and thermal observation over a 10-minute mixed session, qualitatively

Not a substitute: a single speed test. Its result is dominated by the server, and it says nothing
about which member carried which flow.
```

## What these runs are for

A green off-device suite says the code does what its tests describe. A device run is the only thing
that can say the tests describe what happens on a wire: splice eligibility, route exclusion, FakeIP
substitution, interface transitions and the tunnel's own lifecycle are all things the stack decides,
and the fork only decides what it hands the stack.
