# QUIC dual-stack fallback: external dependency blocker

Status: **BLOCKED** on the `sing-quic` public API. Not implemented, and deliberately not
faked.

## What is missing

Hysteria2 and TUIC have no handshake-level dual-stack fallback. If the configured server
address resolves to an IPv6 literal on a broken IPv6 path, the connection stalls for the full
handshake timeout instead of falling back to the IPv4 address that works.

MASQUE already has this: `protocol/masque/bootstrap_race.go` races independent QUIC
connections and accepts a winner only when `HandshakeComplete()` fires, explicitly NOT when
`DialEarly` returns.

## Why it cannot be done from sing-box

Both clients take a single server address and dial it internally.

    sing-quic/hysteria2/client.go
      ClientOptions.ServerAddress   M.Socksaddr      <- ONE address
      offerNew()                    c.dialer.DialContext(ctx, "udp", c.serverAddr)
                                    -> authenticateAndWrap() -> qtls.CreateTransport()

    sing-quic/tuic/client.go
      ClientOptions.ServerAddress   M.Socksaddr      <- ONE address
                                    c.dialer.DialContext(ctx, "udp", c.serverAddr)

There is no point at which sing-box can say "establish candidate N as an independent QUIC
connection and tell me when ITS handshake completes".

## Why a racing `N.Dialer` is not a substitute

The obvious shortcut is to pass a `N.Dialer` whose `DialContext` races candidate addresses.
That does not work, and it is worth stating why, because it is the trap this document exists
to prevent.

`DialContext` returns a **UDP socket**. A socket being created proves the kernel created a
socket. It does not contact the peer, so on a blackholed path it succeeds instantly and the
broken family looks healthiest. A racer built on that signal would reliably choose the broken
family — the opposite of the intended behaviour.

This is why UDP cannot use socket creation as a success criterion, and why the same shortcut
is rejected for generic UDP elsewhere in this work.

## The minimal hook required

One of the following, in `sing-quic`:

    // Option A: a per-candidate connector.
    type ClientOptions struct {
        // ConnectCandidate establishes ONE complete QUIC connection to one address and
        // returns only once the handshake is complete. Returning a connection whose
        // handshake has not completed is a contract violation.
        ConnectCandidate func(ctx context.Context, address netip.Addr) (net.Conn, error)
    }

    // Option B: expose the handshake separately from creation.
    func (c *Client) OfferAddress(ctx context.Context, address netip.Addr) (*PendingOffer, error)
    func (p *PendingOffer) WaitHandshake(ctx context.Context) (*clientQUICConnection, error)

Either keeps every existing behaviour: TLS configuration, ALPN, QUIC options, congestion
control, obfuscation, initial packet size, PMTU behaviour and session resumption stay inside
the library. The hook changes only WHICH address a connection is established to and WHEN the
connection counts as established.

Requirements for the hook:

- optional; default behaviour unchanged when unset
- existing callers unaffected
- no protocol logic duplicated in sing-box
- dedicated tests

## What is already prepared

The scheduler and planner that would consume such a hook are implemented and tested in
`common/dialer`:

    candidatePlan / planCandidates   interleaved ordering, dedup, family preference
    candidateScheduler.dial          fallback-delay scheduling, hard-failure advance,
                                     exactly-one-winner, synchronous loser cleanup,
                                     cancellation, network-scoped family health

Once a handshake-level hook exists, wiring Hysteria2 and TUIC to it is mechanical: the
per-candidate function becomes `ConnectCandidate`, and its success means "handshake complete".
