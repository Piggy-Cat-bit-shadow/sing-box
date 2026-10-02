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
	// negativeTTL is the RFC 2308 lifetime the verdict was recorded with, so a hit can
	// report what remains of it rather than replaying the original value.
	negativeTTL time.Duration
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
	// Idempotent. This is called from Client.Start as well as from the memory-cache
	// path, and re-creating the cache would silently discard every verdict already
	// recorded - a behaviour change with no symptom other than extra upstream queries.
	if c.nxdomainCache != nil {
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
	// A terminal NXDOMAIN that travelled through a CNAME does NOT mean the QNAME is
	// absent: it means the alias target is. Widening it to the QNAME would make
	// "AAAA <alias>" fail locally as NXDOMAIN even though the alias itself exists and has
	// an A record, and would even wrongly answer a CNAME query for it.
	//
	// Following the chain authoritatively is a larger change than this one; until then the
	// safe rule is to cache name-wide only when the answer section is empty.
	if len(response.Answer) > 0 {
		return
	}
	// A name-wide verdict must come from the SOA, not from whatever TTL the response
	// carries after rewriting.
	//
	// timeToLive is computed after applyResponseOptions, so an operator's rewrite_ttl can
	// raise it. If the authoritative negative TTL was 0 - meaning the zone did not ask for
	// this answer to be cached at all - a rewrite must not promote it into a verdict that
	// then answers every other query type for that name for the rewritten duration. The
	// ordinary exact cache is free to keep applying the rewrite; only this widening is
	// gated on the real value.
	soaTTL, hasSOA := extractNegativeTTL(response)
	if !hasSOA || soaTTL == 0 {
		return
	}

	entry := &nxdomainCacheEntry{
		response:    response.Copy(),
		negativeTTL: time.Second * time.Duration(soaTTL),
	}
	// Mirror storeCache exactly. Under disable_expire the ordinary cache stores WITHOUT a
	// lifetime, and freelru's Get() skips anything that has one - so registering a lifetime
	// here would leave the entry present in the map but unreachable, and the two caches
	// would disagree about the same client configuration.
	if c.disableExpire {
		c.nxdomainCache.Add(nxdomainKeyFrom(key), entry)
		return
	}
	c.nxdomainCache.AddWithLifetime(
		nxdomainKeyFrom(key),
		entry,
		time.Second*time.Duration(soaTTL),
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
	nxKey := nxdomainKeyFrom(key)

	// disable_expire means the ordinary cache keeps entries regardless of their lifetime,
	// so this one must behave the same way. Letting the negative cache expire on its own
	// TTL while the exact cache never does would answer one query type from an expired
	// verdict while its neighbour is served indefinitely - a difference in behaviour that
	// no operator asked for and cannot observe.
	if c.disableExpire {
		// Stored without a lifetime by storeNXDomain, exactly like the exact cache, so a
		// plain Get is the matching read.
		entry, loaded := c.nxdomainCache.Get(nxKey)
		if !loaded || entry == nil || entry.response == nil {
			return nil, false
		}
		// Zero remaining means "no lifetime", which the exact cache also reports as 0.
		return nxdomainResponseFor(entry, question, requestID, 0), true
	}

	entry, expireAt, loaded := c.nxdomainCache.GetWithLifetimeNoExpire(nxKey)
	if !loaded || entry == nil || entry.response == nil {
		return nil, false
	}

	timeNow := time.Now()
	if timeNow.After(expireAt) {
		// Lapsed. Remove it so the next lookup is a clean miss, then let the caller go
		// upstream rather than answering from a stale verdict.
		c.nxdomainCache.Remove(nxKey)
		return nil, false
	}

	// Report what REMAINS of the negative TTL, not the value it was stored with. Without
	// this a verdict recorded at TTL 300 would still claim 300 seconds ninety-five
	// seconds later, and a client that honours negative caching would hold the name for
	// longer than the authoritative server said.
	remaining := max(int(expireAt.Sub(timeNow).Seconds()), 0)
	return nxdomainResponseFor(entry, question, requestID, uint32(remaining)), true
}

// nxdomainResponseFor builds the reply for the question being asked now.
//
// Every field that describes the QUESTION comes from the current request; only the
// verdict - NXDOMAIN, and the SOA authority that carries the negative TTL - is reused.
// Replaying the stored message would answer an AAAA query with an A question, which is a
// protocol error a resolver is entitled to discard.
func nxdomainResponseFor(entry *nxdomainCacheEntry, question mDNS.Question, requestID uint16, remainingTTL uint32) *mDNS.Msg {
	response := entry.response.Copy()
	response.Id = requestID
	response.Question = []mDNS.Question{question}
	// The SOA TTL is what tells the client how long to cache the non-existence, so it
	// carries the remaining lifetime rather than the original.
	normalizeTTL(response, remainingTTL)
	return response
}

// clearNXDomainCache discards every name-wide verdict.
//
// Locking is deliberately absent: the underlying LRU is safe for concurrent use, and
// ClearCache already documents the same best-effort semantics as the exact cache.
func (c *Client) clearNXDomainCache() {
	if c.nxdomainCache == nil {
		return
	}
	c.nxdomainCache.Purge()
}
