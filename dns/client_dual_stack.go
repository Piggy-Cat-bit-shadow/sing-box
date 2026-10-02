package dns

import (
	"context"
	"net/netip"
	"sync"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

// Incremental dual-stack resolution.
//
// # The problem
//
// Lookup issued A and AAAA concurrently but then waited for BOTH before returning anything.
// A resolver that answers A in 10ms and never answers AAAA therefore delayed the connection
// by the AAAA timeout - ten seconds in the default configuration - even though a usable
// address was in hand almost immediately. Symmetrically, a fast AAAA was held up by a slow A.
//
// # What this does
//
// Each family's result is published as soon as it arrives, so a consumer can begin connecting
// with one family while the other is still outstanding. The existing Lookup keeps its
// signature and semantics by collecting the same stream.
//
// # What it deliberately does NOT do
//
// It does not issue its own queries. Every exchange still goes through lookupToExchange,
// which means the configured DNS rules, response checker, address filtering, cache,
// singleflight, ECS handling, transport environment and the QNAME-wide NXDOMAIN cache all
// apply exactly as before. Re-querying A and AAAA from the dialer would have bypassed every
// one of those, and a bypassed policy is worse than a slow lookup.
//
// Only the WAITING is incremental. The policy is untouched.

// familyResult is one family's outcome.
type familyResult struct {
	// IPv6 reports which family this result is for.
	IPv6 bool
	// Addresses are the usable addresses for this family, empty when none were returned.
	Addresses []netip.Addr
	// Err is the exchange error, if any. A nil error with no addresses means the family
	// answered with no usable data (NODATA), which is not a failure of the other family.
	Err error
}

// familyCollector receives results as they complete.
//
// onResult is called exactly once per requested family, from the goroutine performing that
// family's exchange, so an implementation must be safe to call concurrently.
type familyCollector struct {
	// onResult publishes one family's outcome.
	onResult func(result familyResult)
	// resolutionDelay is how long a fast family waits for the preferred family before the
	// fast family is published on its own.
	//
	// This is NOT the connection fallback delay. That staggers connection ATTEMPTS; this
	// bounds how long a DNS answer already in hand is withheld in the hope that the
	// preferred family is about to arrive. They are different concerns and different
	// magnitudes, and conflating them would either delay connections or make the grace
	// period useless.
	resolutionDelay time.Duration
	// preferIPv6 reports which family is preferred, so the grace period is applied in the
	// right direction: only a slower PREFERRED family is worth waiting a little for.
	preferIPv6 bool

	access sync.Mutex
	// decided records that the first result has settled the hold question.
	decided bool
	// releasedResult records that the held result has been published.
	releasedResult bool
	// held is the result waiting out the grace period, if any.
	held  *familyResult
	timer *time.Timer
}

// defaultResolutionDelay bounds how long a completed family waits for its sibling.
//
// It is deliberately short. Its only job is to let the preferred family win when both
// answers are in flight and the preferred one is marginally slower; it must never be long
// enough to become the delay it exists to avoid.
const defaultResolutionDelay = 50 * time.Millisecond

func newFamilyCollector(onResult func(familyResult), resolutionDelay time.Duration, preferIPv6 bool) *familyCollector {
	if resolutionDelay <= 0 {
		resolutionDelay = defaultResolutionDelay
	}
	return &familyCollector{
		onResult:        onResult,
		resolutionDelay: resolutionDelay,
		preferIPv6:      preferIPv6,
	}
}

// publish records one family's result.
//
// The ordering rule:
//
//   - The FIRST result is held only briefly when it is the non-preferred family, giving the
//     preferred family a short grace period to arrive. It is then released regardless, so a
//     hung preferred family cannot hold a usable answer hostage.
//   - The preferred family, when it arrives first, is published immediately: there is nothing
//     better to wait for.
//   - Any result arriving after the grace period has passed is published at once.
func (c *familyCollector) publish(result familyResult) {
	c.access.Lock()

	if c.decided {
		// The first result already settled the question. Publish immediately and
		// unconditionally: nothing is ever held a second time.
		c.access.Unlock()
		c.onResult(result)
		return
	}
	c.decided = true

	isPreferred := result.IPv6 == c.preferIPv6
	if isPreferred || c.resolutionDelay <= 0 {
		c.access.Unlock()
		c.onResult(result)
		return
	}

	// The non-preferred family arrived first and is held briefly, giving the preferred
	// family a chance to arrive. The timer guarantees it is released regardless, so a
	// preferred family that never answers cannot withhold an answer already in hand, and
	// close publishes it if the caller returns sooner.
	held := result
	c.held = &held
	c.timer = time.AfterFunc(c.resolutionDelay, func() { c.release(held) })
	c.access.Unlock()
}

// release publishes a held result, at most once.
func (c *familyCollector) release(result familyResult) {
	c.access.Lock()
	if c.releasedResult {
		c.access.Unlock()
		return
	}
	c.releasedResult = true
	c.access.Unlock()
	c.onResult(result)
}

// close stops the timer and publishes a still-held result, so no family is lost.
//
// Without this the family that arrived FIRST could be dropped entirely: it is held for the
// grace period, and if the caller returns before that timer fires, nothing ever publishes it.
// The caller would then see only the second family - which is worse than not streaming at
// all, because the fast answer is the one that was discarded.
func (c *familyCollector) close() {
	c.access.Lock()
	timer := c.timer
	held := c.held
	c.access.Unlock()

	if timer != nil {
		timer.Stop()
	}
	if held == nil {
		return
	}
	c.release(*held)
}

// queryFamilies issues the family exchanges for a name and publishes each as it completes.
//
// It returns immediately after launching; the collector is called from the exchange
// goroutines. callers that need the complete set use collectFamilies.
func (c *Client) queryFamilies(
	ctx context.Context,
	transport adapter.DNSTransport,
	dnsName string,
	options adapter.DNSQueryOptions,
	responseChecker func(response *mDNS.Msg) bool,
	collector *familyCollector,
) {
	var waitGroup sync.WaitGroup

	exchange := func(qType uint16, ipv6 bool) {
		defer waitGroup.Done()
		addresses, err := c.lookupToExchange(ctx, transport, dnsName, qType, options, responseChecker)
		collector.publish(familyResult{IPv6: ipv6, Addresses: addresses, Err: err})
	}

	waitGroup.Add(2)
	go exchange(mDNS.TypeA, false)
	go exchange(mDNS.TypeAAAA, true)

	go func() {
		waitGroup.Wait()
		collector.close()
	}()
}

// collectFamilies runs both family exchanges and returns the result set.
//
// # The waiting rule, and why it is a single decision
//
// The caller must return as soon as it has something usable, but it should include a sibling
// answer that is already in flight - a caller holding both families can race the connection,
// which is the entire point of resolving both.
//
// So there is ONE decision: wait until the collector has published a family that produced
// addresses, which is exactly when a usable answer exists and the grace period has resolved.
// Only when neither family will ever produce one does the all-finished signal matter, and it
// is consulted as a separate, later case rather than racing the first.
//
// An earlier version selected on both signals at once. Both could be closed - the second
// family finishing while the first was still held for its grace period - and Go picks a ready
// case at random, so the function sometimes returned before the held result was published and
// reported an empty family.
func (c *Client) collectFamilies(
	ctx context.Context,
	transport adapter.DNSTransport,
	dnsName string,
	options adapter.DNSQueryOptions,
	responseChecker func(response *mDNS.Msg) bool,
	resolutionDelay time.Duration,
	preferIPv6 bool,
) ([]netip.Addr, []netip.Addr, error) {
	var (
		response4 []netip.Addr
		response6 []netip.Addr
		err4      error
		err6      error
		access    sync.Mutex
		remaining = 2
	)

	// haveAnswer closes when a family with addresses has been PUBLISHED, so by the time it is
	// observed the corresponding result is already recorded.
	haveAnswer := make(chan struct{})
	// allFinished closes when both families have reported, whether or not they had addresses.
	allFinished := make(chan struct{})
	var answerOnce, finishedOnce sync.Once

	collector := newFamilyCollector(func(result familyResult) {
		access.Lock()
		if result.IPv6 {
			response6 = result.Addresses
			err6 = result.Err
		} else {
			response4 = result.Addresses
			err4 = result.Err
		}
		hasAddresses := len(result.Addresses) > 0
		remaining--
		finished := remaining == 0
		access.Unlock()

		if hasAddresses {
			answerOnce.Do(func() { close(haveAnswer) })
		}
		if finished {
			finishedOnce.Do(func() { close(allFinished) })
		}
	}, resolutionDelay, preferIPv6)

	c.queryFamilies(ctx, transport, dnsName, options, responseChecker, collector)

	select {
	case <-haveAnswer:
		// A usable answer exists. Include a sibling already in flight, bounded by the
		// resolution delay - NOT the DNS timeout. A family that has not answered within that
		// window did not answer promptly, and connecting with what we have serves the caller
		// better than waiting.
		select {
		case <-allFinished:
		case <-time.After(resolutionDelay):
		case <-ctx.Done():
		}
	default:
		// Nothing usable yet. Wait for either a usable answer or for both families to finish.
		select {
		case <-haveAnswer:
			select {
			case <-allFinished:
			case <-time.After(resolutionDelay):
			case <-ctx.Done():
			}
		case <-allFinished:
		case <-ctx.Done():
			// The exchanges share this context and are already unwinding. Take whatever they
			// reported rather than discarding it.
			select {
			case <-allFinished:
			case <-time.After(defaultResolutionDelay):
			}
		}
	}

	collector.close()

	access.Lock()
	defer access.Unlock()
	if len(response4) == 0 && len(response6) == 0 {
		if err := E.Errors(err4, err6); err != nil {
			return nil, nil, err
		}
		// Both families answered and neither produced an address: NODATA for both. That is a
		// real answer with nothing in it, and reporting success would hand the caller an empty
		// candidate list to dial.
		return nil, nil, E.New("no address for ", dnsName)
	}
	return response4, response6, nil
}
