package dns

import (
	"net/netip"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
)

// QNAME-wide negative caching for NXDOMAIN.
//
// # The problem
//
// RFC 2308 says NXDOMAIN means the NAME does not exist, not merely that one record
// type is absent for it. The ordinary cache here keys on dns.Question, which
// includes Qtype, so a single non-existent name costs one upstream query per record
// type:
//
//	A     ads.example -> NXDOMAIN
//	AAAA  ads.example -> upstream again
//	HTTPS ads.example -> upstream again
//	SVCB  ads.example -> upstream again
//
// With a filtering resolver in the path - AdGuard Home, or any other - that is four
// round trips and four rule evaluations to learn the same fact four times. The name
// cache below records the verdict once per name and answers the rest locally.
//
// # What is deliberately NOT here
//
// No AdGuard-specific handling. Their blocked responses often carry a synthetic SOA
// for fake-for-negative-caching.adguard.com, and it would be easy to key off that
// string, but the behaviour we want is exactly what RFC 2308 already specifies.
// Matching the standard means authoritative resolvers and every other filtering
// resolver benefit too, and nothing breaks if AdGuard changes its marker.
//
// No disk persistence: this is a hot judgement cache, not a database, and the
// persistent format is untouched.
//
// No cross-namespace sharing. The key carries transport tag, client subnet and
// environment, so two servers or two networks can never poison each other.
//
// # What it is not allowed to do
//
// Only NXDOMAIN with a usable SOA is recorded. NODATA (NOERROR with an empty
// answer) is a statement about one type and must not be widened to the name;
// SERVFAIL, REFUSED, FORMERR, timeouts and transport errors are not statements about
// the name at all. Widening any of those would turn a transient upstream fault into
// a sustained outage for every record type on that name.
//
// The client always receives a real response. A hit produces an NXDOMAIN message
// built for the CURRENT question, never a replay of the first one, and never a
// silent drop - a dropped query would make the client retry or fall back, costing
// more than the upstream query that was saved.

// nxdomainCacheKey identifies a name whose non-existence has been established.
//
// It deliberately omits Qtype: that omission is the entire point. It also omits
// nothing else from dnsCacheKey, so the namespace scoping is identical to the
// ordinary cache.
type nxdomainCacheKey struct {
	name         string // canonical (lowercase, fully qualified)
	qClass       uint16
	transportTag string
	clientSubnet netip.Prefix
	environment  uint64
}

// nxdomainCacheEntry is the stored verdict.
type nxdomainCacheEntry struct {
	// response is the ORIGINAL NXDOMAIN message, kept so a hit can be answered with
	// the authorities the upstream provided (the SOA in particular). It is copied and
	// re-questioned on every hit; it is never handed out as-is.
	response *mDNS.Msg
}

// nxdomainCacheCapacity bounds the name cache.
//
// It is intentionally small. This is a hot verdict cache for names that are being
// asked about repeatedly, not a rule database: the advertising rules live in the
// filtering resolver, and mirroring them here would cost memory on every platform
// for no additional benefit. A few thousand entries covers the names a client
// actually re-queries across types.
const nxdomainCacheCapacity = 2048

// nxdomainCacheForCapacity keeps the name cache inside the configured DNS cache
// budget rather than adding to it: a deployment that reduced cache_capacity did so
// for a reason, and the negative cache should not quietly exceed it.
func nxdomainCacheForCapacity(cacheCapacity uint32) uint32 {
	if cacheCapacity < nxdomainCacheCapacity {
		return cacheCapacity
	}
	return nxdomainCacheCapacity
}

// initializeNXDomainCache sets up the name cache. It is a no-op when caching is
// disabled, so a client built with disable_cache has no negative cache either.
func (c *Client) initializeNXDomainCache() {
	if c.disableCache {
		return
	}
	capacity := nxdomainCacheForCapacity(c.cacheCapacity)
	if capacity == 0 {
		return
	}
	c.nxdomainCache = common.Must1(freelru.New[nxdomainCacheKey, *nxdomainCacheEntry](
		capacity, maphash.NewHasher[nxdomainCacheKey]().Hash32, true,
	))
}

// nxdomainKeyFrom builds the name-scoped key from an ordinary cache key, dropping
// Qtype and canonicalising the name so lookup is case-insensitive as DNS requires.
func nxdomainKeyFrom(key dnsCacheKey) nxdomainCacheKey {
	return nxdomainCacheKey{
		name:         mDNS.CanonicalName(key.Name),
		qClass:       key.Qclass,
		transportTag: key.transportTag,
		clientSubnet: key.clientSubnet,
		environment:  key.environment,
	}
}

// storeNXDomain records a name-wide negative verdict.
//
// It is only called for a validated NXDOMAIN with a usable SOA TTL, and it only
// applies to simple single-question requests, because a multi-question message has
// no single name to record.
func (c *Client) storeNXDomain(key dnsCacheKey, response *mDNS.Msg, timeToLive uint32) {
	if c.nxdomainCache == nil {
		return
	}
	// Guard the conditions here as well as at the call site. This is the one place
	// that widens a verdict from a type to a name, so it should be impossible to
	// reach with anything but a genuine, usable NXDOMAIN.
	if response.Rcode != mDNS.RcodeNameError {
		return
	}
	if timeToLive == 0 {
		return
	}
	if len(response.Question) != 1 {
		return
	}
	if _, hasSOA := extractNegativeTTL(response); !hasSOA {
		// Without a SOA there is no RFC 2308 TTL to respect, and inventing one would
		// extend an incomplete answer across every record type.
		return
	}
	c.nxdomainCache.AddWithLifetime(
		nxdomainKeyFrom(key),
		&nxdomainCacheEntry{response: response.Copy()},
		time.Second*time.Duration(timeToLive),
	)
}

// loadNXDomain answers the current question from a recorded name verdict.
//
// The returned message is built for the caller's question: its ID, name, type and
// class all come from the request, and only the verdict (NXDOMAIN plus the authority
// records) is reused. Returning the stored message directly would answer an AAAA
// question with an A question, which is a protocol error a resolver is entitled to
// discard.
func (c *Client) loadNXDomain(key dnsCacheKey, question mDNS.Question, requestID uint16) (*mDNS.Msg, bool) {
	if c.nxdomainCache == nil {
		return nil, false
	}
	entry, loaded := c.nxdomainCache.Get(nxdomainKeyFrom(key))
	if !loaded || entry == nil || entry.response == nil {
		return nil, false
	}
	response := entry.response.Copy()
	response.Id = requestID
	response.Question = []mDNS.Question{question}
	// The authority section carries the SOA whose TTL the caller is about to be told;
	// the remaining lifetime is applied from the cache entry on the way out.
	return response, true
}
