# Real data plane validation

Procedures for the measurements that need a real TUN device, root, or an Apple NetworkExtension.

**None of this has been executed in the repository's current environment.** The development machine is
macOS as an unprivileged user: no root (`sudo` requires a password), no Linux, no TUN device that can
be given an address or a route, and no signed NetworkExtension. Everything a TUN stack does — L0 route
exclusion, L2 splice, the flow table, DNS hijack, FakeIP, network transitions — therefore has no
executed evidence, and any document that claims otherwise is describing intent rather than measurement.

This file exists so the gap is a procedure rather than an omission. Each section names what to run,
what to observe, and what would falsify the claim being checked.

---

## Environment

Linux, root, and two network namespaces. This is the only environment in this repository's reach where
the routing table, the syscalls, the packet captures and the CPU are all controllable and repeatable.

```sh
ip netns add box        # runs sing-box with the TUN
ip netns add client     # runs the application
ip netns add server     # runs the endpoint
ip link add veth-box netns box type veth peer name veth-client netns client
ip link add veth-srv netns box type veth peer name veth-server netns server
# addresses, default routes, and forwarding between box's two interfaces
```

Then a `tun` inbound in `box` with `auto_route`, and the endpoint in `server`.

---

## 1. L0 — does excluded traffic actually stay out of the TUN?

**The claim.** `route_exclude_address_set` traffic never enters the TUN, because the OS routes it away;
the `ActionBypass` verdict is belt-and-braces and is not the mechanism.

**How to falsify it.** Count packets read from the TUN device for a destination in the exclude set. If
they are non-zero, the mechanism is the verdict rather than the routing table and the whole L0 story
is wrong.

```sh
ip netns exec box nft add table inet tunread   # or: ss -K, or a bpf kprobe on tun_read_iter
ip netns exec client curl -s -o /dev/null http://<server-in-exclude-set>/
```

**Observations to record:** the route table entry for the excluded prefix, the TUN read count for that
destination, and the same count with `route_exclude_address_set` removed (which must be non-zero, or
the measurement is not measuring anything).

---

## 2. L2 — is splice attempted, and does it succeed, per flow?

**The claim to establish:** which direct TCP flows reach `GoConn.Splice`, which do not, and whether the
fork's own `spliceConnection` is the thing that decided.

**Instrumentation gap, stated plainly.** `ConnectionManager.SpliceDiagnostics()` describes **UDP**
sessions only; its reasons are all about `UDPNatConn` and packet connections. The TCP path
(`route/splice.go`'s `spliceConnection` returning a bool) records nothing. So today a running process
cannot be asked "did this TCP flow splice?", and a harness would have to infer it from performance —
which is exactly the inference this repository does not accept.

Closing that gap is the first task for whoever runs this: mirror the UDP diagnostics — a
per-flow counter, not per-packet — with these reasons:
`source-not-GoConn`, `target-not-splice-target`, `reader-writer-mismatch`, `splice-rejected`,
`skipped-for-tls-rewrite`.

**The measurement.** With the counters in place, for each of: direct TCP to a literal IP, direct TCP
to a domain, proxied TCP (VLESS or AnyTLS), and direct UDP:

- bytes and connections per outcome bucket from the counters,
- `/connections` from the Clash API while the transfer runs,
- `ss -tin` on the outbound socket, showing the splice if it happened,
- CPU time (`/proc/<pid>/stat` utime+stime) and context switches across the transfer.

**The mutation that makes it mean something.** Disable splice (make `GoConn.Splice` return false) and
confirm the counters move to the L3 bucket and the throughput or CPU changes. A harness that reports
the same numbers with and without splice is measuring the harness.

---

## 3. L2 versus L3 under a realistic path

Loopback already showed that the two are indistinguishable there, which is a property of loopback
rather than of the code. The comparison needs latency and a bandwidth cap:

```sh
ip netns exec box tc qdisc add dev veth-srv root netem delay 10ms rate 100mbit
```

Record, per RTT (1 ms, 10 ms, 40 ms) and both paths: throughput, CPU seconds per gigabyte, context
switches per gigabyte, syscalls per gigabyte (`strace -c -f`), and p50/p95 connection setup for short
flows. **Throughput parity with lower CPU is a success**, and on Apple hardware it is the result that
matters most.

---

## 4. The tracker under L2

Dashboard enabled, direct TCP, known payload:

- the connection appears in `/connections` with the right outbound, rule and start time,
- upload and download counts match the payload exactly, in the unit the tracker already uses,
- close from the API terminates it,
- and the splice **still happens** — a tracker that quietly costs the fast path is a regression, not a
  feature.

The three parts are one test: a dashboard that shows the connection while the splice counters say L3 is
a failure to report, not a pass.

---

## 5. UDP on a real device

Packet rate, batch size, syscalls per packet, zero-length datagrams, the idle timeout, and the tracker's
counts. Confirm that the upload gate and the scheduler left the direct UDP path where it was: the round
1 and 2 work touched the gate that every managed UDP flow passes through, and their tests were
in-process.

---

## 6. DNS and FakeIP

With `route_address_set` and `route_exclude_address_set` configured, and a broad exclude set that
covers the FakeIP range:

- a UDP/53 query reaches the DNS handling rather than the platform,
- a TCP/53 connection is accepted rather than bypassed,
- a domain resolved to a FakeIP address produces an application connection that enters the TUN and is
  unmapped by the router,
- and the same with the guard removed, which must black-hole it.

The last item is the control. Without it, "FakeIP still works" is a statement about a configuration in
which the problem could not occur.

---

## 7. Network transitions

Interface down/up, route change, TUN restart and process shutdown, with connections open:

- every connection leaves the tracker exactly once,
- no goroutine or handle survives the transition (compare `/proc/<pid>/task` counts and the TUN's file
  descriptors before and after),
- the scheduler's parked flows are released (round 1 has an in-process test for this; the real device
  is where it can regress),
- a new flow uses the new network state rather than the old one.

---

## 8. Apple, by hand

Not automatable and not optional: it is the product environment.

**macOS / iOS NetworkExtension, with a signed build:**

| Check | How |
| --- | --- |
| direct TCP and UDP | a transfer to a known host, with the connection visible in the dashboard |
| proxied TCP | the same through the real proxy, comparing setup latency |
| DNS, including the FakeIP path | a domain that resolves to the tunnel's FakeIP range, then confirm the connection enters the tunnel |
| Wi-Fi → cellular | a transfer across the switch, watching for a stale connection row and for a leak |
| dashboard tracking | bytes in and out against a known payload, and close from the API |
| scheduler, if configured | `route.traffic_scheduler.upload_rate` at a measured-sustainable value, then the upload latency under contention |
| CPU, memory, thermal | `powermetrics` or Instruments across a fixed workload, before and after any change |

**Do not report a Speedtest number as a result.** The figures that decide whether this ships on a phone
are connection setup latency, CPU seconds per gigabyte, memory retained per connection, and whether the
tunnel survives a network change without a stale row.

---

## RC additions

The RC adds three procedures to the list above, and one item that used to be unobservable is now
reportable from the device log alone.

### TCP splice outcomes

`spliceConnection` records exactly one outcome per connection, and the connection manager prints two
lines once per tunnel lifetime at shutdown:

```text
UDP splice diagnostics: attempts=N successes=M ratio=R <reason>=<count> ...
TCP splice diagnostics: attempts=N successes=M ratio=R <reason>=<count> ...
```

So the procedure is: start the tunnel, run the workload, stop the tunnel, read two lines. What each
stream outcome means, and which of them the Go side cannot explain further, is documented in
`route/splice_diagnostics.go`; `splice_rejected` is deliberately one bucket because the underlying
call returns a boolean.

The checkout of that number is the counter invariant: `attempts == successes + sum(reasons)`, per
transport. If a device report does not add up, the report is wrong, not the code.

### The single action-to-options decision

A rule's route options must be applied identically in the pre-match pass and in the full route path.
A device run checks the visible consequence: a `bypass()` rule with no outbound bypasses, and a
`bypass()`/`route()` rule with options does not bypass when those options rewrite the destination.

### The v4-mapped boundary

A client that reaches the configured DNS address as `::ffff:a.b.c.d` must still be hijacked, while a
NAT64 destination (`64:ff9b::/96`) must be dialed as IPv6. Both are checked on the wire, not in the
metadata.

### Network transition, per load balance member

With a load balance group in the chain: disable a member's connectivity, confirm new flows skip it
once its measurement is known-bad; restore it, confirm it returns. Then change the network (Wi-Fi to
cellular on Apple, interface down/up on Linux) with a sticky session pinned, and confirm the next
flow is re-pinned rather than dialed on a member that is no longer reachable.
