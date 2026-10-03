package dialer

import (
	"context"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

// Dual-stack recovery for direct dials to a literal address.
//
// # Why this exists
//
// Fixing the resolve action is not enough, because a real TUN deployment usually has no
// `route action: resolve` configured at all. The application has already resolved the name
// and connects to an address, so the dialer receives a literal IP - and with a broken path
// for that address's family there is nothing to fall back to. The connection fails or times
// out while the other family was available the whole time.
//
// Sniffing recovers the domain the client actually asked for. This turns that domain back
// into candidate addresses so the scheduler has something to race.
//
// # Only the configured resolver, never the system one
//
// Recovery goes through the same adapter.DNSRouter as every other lookup, so the configured
// DNS rules, transports, caching and singleflight all apply. The system resolver is never
// consulted: on a proxy that would leak the user's DNS queries outside the tunnel, which is
// a far worse outcome than a slow connection.
//
// # No recursion
//
// A DNS exchange may itself travel through a direct outbound. If that outbound then ran
// recovery, resolving a name would require resolving a name, and a DNS server's own
// connection could recurse without bound. Recovery is therefore refused whenever the context
// already carries the marker, and the marker is set for the duration of the recovery lookup.

// recoveryDisabledContextKey marks a context in which address recovery must not run.
type recoveryDisabledContextKey struct{}

// withoutAddressRecovery returns a context in which recovery will not run.
//
// It is applied around the recovery lookup itself, so a DNS exchange performed to recover
// candidates cannot trigger another recovery.
func withoutAddressRecovery(ctx context.Context) context.Context {
	return context.WithValue(ctx, recoveryDisabledContextKey{}, true)
}

// addressRecoveryDisabled reports whether recovery is suppressed for this context.
func addressRecoveryDisabled(ctx context.Context) bool {
	disabled, _ := ctx.Value(recoveryDisabledContextKey{}).(bool)
	return disabled
}

// recoverCandidates resolves the sniffed domain into candidates for a literal destination.
//
// It returns nil when recovery does not apply, which leaves the caller's behaviour exactly as
// it was. Every condition is a refusal, so an unusual situation degrades to the previous
// single-candidate dial rather than to a surprising one.
func (d *resolveDialer) recoverCandidates(ctx context.Context, destination M.Socksaddr) []netip.Addr {
	// Only for literal destinations. A domain destination is already resolved by the normal
	// path, and re-resolving it here would duplicate that work.
	if !destination.IsIP() {
		return nil
	}
	if addressRecoveryDisabled(ctx) {
		return nil
	}
	if d.router == nil {
		return nil
	}

	// The sniffed domain, validated. It is attacker-influenced - derived from bytes the peer
	// chose - and it is about to be given to a resolver.
	// Read the context metadata without copying it: recovery only reads the sniffed domain.
	domain := ""
	if metadata := adapter.ContextFrom(ctx); metadata != nil {
		domain = validRecoveryDomain(metadata.Domain)
	}
	if domain == "" {
		return nil
	}

	// The lookup is logged at debug: it is an internal recovery step, not something the user
	// asked for, and it must not add noise to the connection log.
	// Cancellation is honoured by the router lookup below. The caller abandons this work the
	// moment the original address connects, so a lookup that ignored cancellation would keep
	// running DNS for a connection that is already established.
	recoveryCtx := withoutAddressRecovery(log.ContextWithOverrideLevel(ctx, log.LevelDebug))

	// Recovery streams when the router can, so a family that has answered is usable immediately.
	//
	// The complete Lookup waits for BOTH families, which is right for a routing decision that
	// needs the whole address set and wrong here: recovery exists to provide a fallback as soon as
	// one is available. With a resolver answering A in 10ms and AAAA in 3s, waiting for the
	// complete set made the recovered IPv4 unusable for three seconds - turning a working fallback
	// into a stall.
	//
	// The first usable family is therefore returned as soon as it arrives. Only if the streaming
	// interface is unavailable does this fall back to the complete lookup, which keeps third-party
	// routers working exactly as before.
	var recovered []netip.Addr
	if dualStackRouter, supportsStreaming := d.router.(adapter.DNSDualStackRouter); supportsStreaming {
		collected := make(chan []netip.Addr, 1)
		streamCtx, cancelStream := context.WithCancel(recoveryCtx)
		defer cancelStream()

		go func() {
			_ = dualStackRouter.LookupFamilies(streamCtx, domain, d.queryOptions,
				func(result adapter.DNSFamilyResult) {
					if len(result.Addresses) == 0 {
						return
					}
					select {
					case collected <- result.Addresses:
					case <-streamCtx.Done():
					}
				})
			// The stream ended without producing anything usable.
			select {
			case collected <- nil:
			case <-streamCtx.Done():
			}
		}()

		select {
		case first := <-collected:
			recovered = first
		case <-recoveryCtx.Done():
			return nil
		}
	} else {
		addresses, err := d.router.Lookup(recoveryCtx, domain, d.queryOptions)
		if err != nil {
			// Recovery is a best-effort improvement. A failure must not turn a connection that
			// would otherwise have been attempted into an error the user never asked for.
			return nil
		}
		recovered = addresses
	}

	if len(recovered) == 0 {
		return nil
	}
	return recovered
}

// validRecoveryDomain returns the sniffed domain to recover through, or empty when it is not
// usable.
//
// A sniffed domain is attacker-influenced: it is parsed out of bytes the remote peer chose,
// and it is about to be handed to a resolver. Empty, over-long, control-character, and
// structurally implausible values are refused rather than resolved.
func validRecoveryDomain(domain string) string {
	switch {
	case domain == "":
		return ""
	case len(domain) > 253:
		return ""
	case strings.ContainsAny(domain, "\x00 \t\r\n/"):
		return ""
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		// A sniffed "domain" that is really an address literal must not be resolved.
		return ""
	}
	trimmed := strings.TrimSuffix(domain, ".")
	if trimmed == "" || !strings.Contains(trimmed, ".") {
		return ""
	}
	for _, label := range strings.Split(trimmed, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
		for _, char := range label {
			isAlnum := (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')
			if !isAlnum && char != '-' && char != '_' {
				return ""
			}
		}
	}
	return trimmed
}
