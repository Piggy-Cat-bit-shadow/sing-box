package dns

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
)

// LookupFamilies resolves both address families concurrently and reports each as it arrives.
//
// # Why this reuses Router.Lookup rather than issuing its own queries
//
// The connection path needs a family's addresses as soon as they exist, so a family that
// answers late can still join a race already under way. That is the only new capability here.
//
// The queries themselves are the SAME Router.Lookup calls every other caller makes, with the
// strategy forced to one family. So rule evaluation, transport selection, the response checker,
// caching, singleflight, ECS handling, transport environment, RDRC and the QNAME-wide NXDOMAIN
// cache all apply exactly as they do for a complete lookup.
//
// Writing a second query path here - composing A and AAAA messages directly - would have been
// shorter and would have bypassed every one of those. A query path that ignores the configured
// rules is worse than a slow one: it silently changes which policy applies, and the difference
// is invisible until someone notices their DNS rules are not being honoured.
//
// # Strict strategies
//
// IPv4Only and IPv6Only issue ONE query, for their own family. They do not query the other
// family and discard it - "only" means only, and a discarded query is still a query the user's
// resolver sees.
func (r *Router) LookupFamilies(ctx context.Context, domain string, options adapter.DNSQueryOptions, publish func(adapter.DNSFamilyResult)) error {
	if publish == nil {
		return E.New("nil result publisher")
	}

	// The strategy that will actually be applied, which is NOT necessarily options.Strategy.
	//
	// AsIS means "use the resolver's default", and that default belongs to this router. Deciding
	// single-family versus dual-family from the raw options would therefore treat a router
	// configured for one family as a dual-family request, and would report a preference the
	// connection layer could not see. Resolving it once, here, keeps this the only place that
	// knows the answer.
	effectiveStrategy := r.resolveLookupStrategy(options)

	// A strict strategy is a single-family request, reported once. The check uses the EFFECTIVE
	// strategy so a router default of ipv4_only or ipv6_only also issues a single query, rather
	// than querying a family it has been configured never to use.
	switch effectiveStrategy {
	case C.DomainStrategyIPv4Only:
		addresses, err := r.Lookup(ctx, domain, options)
		publish(adapter.DNSFamilyResult{IPv6: false, Addresses: addresses, Err: err, EffectiveStrategy: effectiveStrategy})
		if err != nil && len(addresses) == 0 {
			return err
		}
		return nil
	case C.DomainStrategyIPv6Only:
		addresses, err := r.Lookup(ctx, domain, options)
		publish(adapter.DNSFamilyResult{IPv6: true, Addresses: addresses, Err: err, EffectiveStrategy: effectiveStrategy})
		if err != nil && len(addresses) == 0 {
			return err
		}
		return nil
	}

	// Both families, concurrently, each published as it completes.
	var (
		waitGroup sync.WaitGroup
		access    sync.Mutex
		succeeded int
		lastErr   error
	)

	lookupFamily := func(strategy C.DomainStrategy, ipv6 bool) {
		defer waitGroup.Done()

		familyOptions := options
		familyOptions.LookupStrategy = strategy
		// The forced family has to win over a preference, so Strategy is set too: the
		// underlying lookup reads Strategy to decide whether to issue one query or two.
		familyOptions.Strategy = strategy

		addresses, err := r.Lookup(ctx, domain, familyOptions)

		access.Lock()
		if err != nil {
			lastErr = err
		}
		if len(addresses) > 0 {
			succeeded++
		}
		access.Unlock()

		publish(adapter.DNSFamilyResult{
			IPv6:      ipv6,
			Addresses: addresses,
			Err:       err,
			// Both families report the same effective strategy, so a consumer never has to
			// decide which result to believe.
			EffectiveStrategy: effectiveStrategy,
		})
	}

	waitGroup.Add(2)
	go lookupFamily(C.DomainStrategyIPv4Only, false)
	go lookupFamily(C.DomainStrategyIPv6Only, true)
	waitGroup.Wait()

	access.Lock()
	defer access.Unlock()
	if succeeded == 0 {
		if lastErr != nil {
			return lastErr
		}
		return E.New("no address for ", domain)
	}
	return nil
}

// dualStackRouter is the capability this package provides.
var _ adapter.DNSDualStackRouter = (*Router)(nil)
