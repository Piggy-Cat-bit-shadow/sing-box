package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/compatible"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
	"github.com/sagernet/sing/service"

	"github.com/miekg/dns"
)

var (
	ErrNoRawSupport           = E.New("no raw query support by current transport")
	ErrNotCached              = E.New("not cached")
	ErrResponseRejected       = E.New("response rejected")
	ErrResponseRejectedCached = E.Extend(ErrResponseRejected, "cached")
)

var _ adapter.DNSClient = (*Client)(nil)

type Client struct {
	ctx               context.Context
	timeout           time.Duration
	disableCache      bool
	disableExpire     bool
	optimisticTimeout time.Duration
	cacheCapacity     uint32
	clientSubnet      netip.Prefix
	rdrc              adapter.RDRCStore
	initRDRCFunc      func() adapter.RDRCStore
	dnsCache          adapter.DNSCacheStore
	initDNSCacheFunc  func() adapter.DNSCacheStore
	networkManager    adapter.NetworkManager
	networkGeneration func() uint64
	// environmentPins holds the network environment each transport was LAST reset in.
	//
	// # Why the environment is pinned rather than read live
	//
	// A DNS cache key records which network an answer belongs to, and the transport that carried the
	// query is what actually defines that network. But NetworkManager publishes the new environment
	// BEFORE it resets the DNS router:
	//
	//	updateNetworkEnvironment()   <- the fingerprint becomes B
	//	ResetNetwork()               <- transports are reset here
	//
	// A query issued in between travels over a connection belonging to network A while a live read
	// of NetworkEnvironment() already reports B, so its answer was stamped B and served to every
	// later query on the new network for the rest of its TTL. The answer described A; the stamp said
	// B; and because the stamp matched, nothing downstream could tell.
	//
	// Pinning the environment to the transport makes the stamp mean "the network this transport
	// serves". Router.ResetNetwork refreshes the pin when it resets the transports, which is exactly
	// the moment a transport stops belonging to the old network.
	environmentPins compatible.Map[string, uint64]
	logger          logger.ContextLogger
	cache           *freelru.Cache[dnsCacheKey, *dns.Msg]
	// QNAME-wide negative verdicts for NXDOMAIN, keyed without Qtype. See
	// client_negative.go: one name costs one upstream query, not one per record type.
	nxdomainCache     *freelru.Cache[nxdomainCacheKey, *nxdomainCacheEntry]
	cacheLock         compatible.Map[dnsExchangeKey, chan struct{}]
	backgroundRefresh compatible.Map[dnsCacheKey, struct{}]
}

type ClientOptions struct {
	Context           context.Context
	Timeout           time.Duration
	DisableCache      bool
	DisableExpire     bool
	OptimisticTimeout time.Duration
	CacheCapacity     uint32
	ClientSubnet      netip.Prefix
	RDRC              func() adapter.RDRCStore
	DNSCache          func() adapter.DNSCacheStore
	Logger            logger.ContextLogger
	// NetworkGeneration reports the current network generation.
	//
	// # Why a generation is needed on top of the environment fingerprint
	//
	// The fingerprint namespaces the cache by WHICH network an answer belongs to. It cannot express
	// "same network identity, different epoch": a reset that leaves the fingerprint unchanged - the
	// same SSID reconnected, the same interface re-addressed to the same values - produces an
	// identical fingerprint, so a response issued before the reset and captured after it looks like
	// it belongs. Comparing only fingerprints therefore accepts it.
	//
	// This is the OWNERSHIP guard for an in-flight response: it says whether the answer still belongs
	// to the network its request was issued on. It is deliberately separate from the fingerprint,
	// which is a NAMESPACE, and it is never part of a persistent key - a process-local counter would
	// make persisted entries meaningless to the next process.
	//
	// nil means the caller has no generation concept, and only the fingerprint applies.
	NetworkGeneration func() uint64
}

func NewClient(options ClientOptions) *Client {
	cacheCapacity := max(options.CacheCapacity, 1024)
	client := &Client{
		ctx:               options.Context,
		timeout:           options.Timeout,
		disableCache:      options.DisableCache,
		disableExpire:     options.DisableExpire,
		optimisticTimeout: options.OptimisticTimeout,
		cacheCapacity:     cacheCapacity,
		clientSubnet:      options.ClientSubnet,
		initRDRCFunc:      options.RDRC,
		initDNSCacheFunc:  options.DNSCache,
		logger:            options.Logger,
		networkGeneration: options.NetworkGeneration,
	}
	if client.timeout == 0 {
		client.timeout = C.DNSTimeout
	}
	if !client.disableCache && client.initDNSCacheFunc == nil {
		client.initializeMemoryCache()
	}
	return client
}

type dnsCacheKey struct {
	dns.Question
	transportTag string
	clientSubnet netip.Prefix
	environment  uint64
}

type dnsExchangeKey struct {
	dnsCacheKey
	timeout time.Duration
}

func (k dnsCacheKey) persistentName() string {
	name := k.transportTag
	if k.clientSubnet.IsValid() {
		name += "\x00" + k.clientSubnet.String()
	}
	if k.environment != 0 {
		name += "\x01" + strconv.FormatUint(k.environment, 36)
	}
	return name
}

func (c *Client) newCacheKey(transport adapter.DNSTransport, question dns.Question, message *dns.Msg, options adapter.DNSQueryOptions) dnsCacheKey {
	var clientSubnet netip.Prefix
	if !options.RemoveClientSubnet {
		clientSubnet = options.ClientSubnet
		if !clientSubnet.IsValid() {
			clientSubnet = c.clientSubnet
		}
		if !clientSubnet.IsValid() {
			clientSubnet = clientSubnetFromMessage(message)
		}
	}
	return dnsCacheKey{
		Question:     question,
		transportTag: transport.Tag(),
		clientSubnet: clientSubnet,
		environment:  c.environmentHash(transport),
	}
}

// captureGeneration records the network generation a query is being issued on.
//
// It is called where the cache key is built - before the round trip - so the value describes the
// network the question was asked on rather than the one that happens to be current when the answer
// arrives. Reading it at store time would compare the current value against itself and therefore
// never reject anything.
func (c *Client) captureGeneration(operation *exchangeOperation) {
	if c.networkGeneration == nil {
		return
	}
	operation.generation = c.networkGeneration()
	operation.hasGenerationGuard = true
}

// generationStillCurrent reports whether a captured generation still describes the live network.
//
// A caller with no generation concept is always current, so this degrades to fingerprint-only
// behaviour rather than rejecting everything.
func (c *Client) generationStillCurrent(operation *exchangeOperation) bool {
	if !c.networkTransitionStable() {
		// A transition is pending: the network this answer describes is not settled.
		//
		// The generation check below cannot catch this. It compares the DNS generation, which
		// Router.ResetNetwork advances - and that has not run yet. Neither can the environment pin:
		// the pin is refreshed by the same reset, so it still names the network being left and
		// matches the key exactly.
		//
		// The consequence of accepting here is not a stale answer but a MISLABELLED one. A query
		// issued during the transition captures the transition's own epoch, so nothing else rejects
		// it; its transport may already have re-dialled on the new network, so the answer describes
		// the NEW network; and both guards agree it belongs to the OLD one. The entry is then served
		// to every later query on the old namespace for the rest of its TTL.
		//
		// Refusing the cache write is the smallest behaviour change that closes it: the answer is
		// still returned to the caller that asked, and only its storage is declined. The query is
		// not failed, because the exchange itself was legitimate.
		return false
	}
	if !operation.hasGenerationGuard || c.networkGeneration == nil {
		return true
	}
	return operation.generation == c.networkGeneration()
}

// networkTransitionStable reports whether the network is settled, from the manager when it can say.
//
// A manager without the capability is one where the distinction does not arise, so the check
// degrades to "settled" and the previous behaviour is preserved exactly.
func (c *Client) networkTransitionStable() bool {
	if c.networkManager == nil {
		return true
	}
	if state, isState := c.networkManager.(adapter.NetworkTransitionState); isState {
		return state.NetworkTransitionStable()
	}
	return true
}

// finishCacheKey decides whether a response may be stored, and under which environment.
//
// # Why an unknown captured environment is not "adopt the current one"
//
// A query records its environment when it is SENT. If nothing is known yet the value is 0, and the
// response is stored later - after a network change, possibly. The previous rule accepted any key
// whose captured value was 0 and rewrote it with the CURRENT environment:
//
//	if environment == key.environment || key.environment == 0 {
//
// That relabels an answer produced elsewhere with the identity of the network that is current now,
// so a query on the new network is answered from a cache entry that was never true there. It is the
// same class of defect the reverse-mapping path guards against with a generation check.
//
// An unknown environment therefore means "cannot be attributed", and the response is not stored.
// The cost is one uncached answer while the environment is still unknown, which is the safe
// direction: a cache MISS costs a lookup, a wrong HIT returns an answer about a different network.
func (c *Client) finishCacheKey(transport adapter.DNSTransport, key dnsCacheKey) (dnsCacheKey, bool) {
	// A transport that does not participate in environments has 0 as its REAL, stable identity.
	// Distinguishing this from "participates, but nothing is known yet" is what keeps caching
	// enabled for such transports while refusing to guess for the others.
	if _, withEnvironment := transport.(adapter.DNSTransportWithEnvironment); !withEnvironment {
		return key, true
	}

	environment := c.environmentHash(transport)
	if environment != key.environment {
		// The environment the query was issued under is not the one that holds now.
		//
		// # The two shapes this covers
		//
		//	key == 0, environment != 0   the environment became KNOWN after the query was sent
		//	key != 0, environment != key the network changed while the query was in flight
		//
		// Both are the same mistake: storing the answer would attribute it to an environment it was
		// not measured on. The first is the relabelling defect - a zero captured value overwritten
		// with whatever number is current - and it is why this comparison is on the VALUE rather
		// than on `key == 0`.
		//
		// # Why a zero fingerprint is not automatically "unknown"
		//
		// A transport that participates in environments, advertises none, and runs on a platform
		// reporting NetworkEnvironment() == 0 has 0 as its real and permanent identity. Refusing it
		// disabled caching for the whole process lifetime - every query went upstream - which is a
		// silent behaviour change rather than a safety property. When the captured value and the
		// current value are both zero they ARE the same environment, so the answer is correctly
		// attributed and belongs in the cache.
		//
		// Residual hole, stated rather than implied: an environment that goes 0 -> B -> 0 would let
		// a response issued at the first 0 be stored at the second. NetworkEnvironment does not
		// return to "unknown" once it has reported a value within a process lifetime, so this needs
		// a generation counter to close properly; the environment fingerprint is not one.
		return key, false
	}
	return key, true
}

// transportEnvironment returns the network environment the given transport belongs to.
//
// The first observation pins it, and Router.ResetNetwork refreshes the pin when it resets the
// transports. Until then the pinned value is used, so a query cannot be stamped with a network its
// transport does not serve - see the environmentPins field for the ordering this exists to close.
func (c *Client) transportEnvironment(transport adapter.DNSTransport) uint64 {
	var current uint64
	if c.networkManager != nil {
		current = c.networkManager.NetworkEnvironment()
	}
	pinned, loaded := c.environmentPins.Load(transport.Tag())
	if loaded {
		return pinned
	}
	// LoadOrStore, so two concurrent first observations cannot pin different values.
	actual, _ := c.environmentPins.LoadOrStore(transport.Tag(), current)
	return actual
}

// refreshTransportEnvironments re-pins every transport to the environment that is current now.
//
// Called from the network reset, which is the moment a transport stops belonging to the previous
// network. Everything observed afterwards is stamped with the new environment, and everything
// observed before it keeps the environment its transport actually served.
func (c *Client) refreshTransportEnvironments() {
	for _, transport := range c.knownTransports() {
		var current uint64
		if c.networkManager != nil {
			current = c.networkManager.NetworkEnvironment()
		}
		c.environmentPins.Store(transport, current)
	}
}

// knownTransports lists the transport tags this client has observed.
func (c *Client) knownTransports() []string {
	var tags []string
	c.environmentPins.Range(func(tag string, _ uint64) bool {
		tags = append(tags, tag)
		return true
	})
	return tags
}

func (c *Client) environmentHash(transport adapter.DNSTransport) uint64 {
	environmentTransport, withEnvironment := transport.(adapter.DNSTransportWithEnvironment)
	if !withEnvironment {
		return 0
	}
	networkEnvironment := c.transportEnvironment(transport)
	environment := environmentTransport.Environment()
	if len(environment) == 0 {
		return networkEnvironment
	}
	digest := fnv.New64a()
	for _, entry := range environment {
		digest.Write([]byte(entry))
		digest.Write([]byte{0})
	}
	var hashBytes [8]byte
	binary.BigEndian.PutUint64(hashBytes[:], networkEnvironment)
	digest.Write(hashBytes[:])
	return digest.Sum64()
}

func (c *Client) Start() {
	c.networkManager = service.FromContext[adapter.NetworkManager](c.ctx)
	if c.initRDRCFunc != nil {
		c.rdrc = c.initRDRCFunc()
	}
	if c.initDNSCacheFunc != nil {
		c.dnsCache = c.initDNSCacheFunc()
	}
	if c.dnsCache == nil {
		c.initializeMemoryCache()
	}
	// The name-wide negative cache is a bounded in-memory HOT cache and is independent of
	// whichever exact backend is configured. Initialising it from initializeMemoryCache
	// meant a deployment with a persistent exact cache never got one at all: every
	// NXDOMAIN would be recorded only under its own QTYPE and the name would cost one
	// upstream query per record type, which is the whole thing this cache exists to avoid.
	c.initializeNXDomainCache()
}

func (c *Client) initializeMemoryCache() {
	if c.disableCache || c.cache != nil {
		return
	}
	c.cache = common.Must1(freelru.New[dnsCacheKey, *dns.Msg](c.cacheCapacity, maphash.NewHasher[dnsCacheKey]().Hash32, true))
}

func extractNegativeTTL(response *dns.Msg) (uint32, bool) {
	for _, record := range response.Ns {
		if soa, isSOA := record.(*dns.SOA); isSOA {
			soaTTL := soa.Header().Ttl
			soaMinimum := soa.Minttl
			if soaTTL < soaMinimum {
				return soaTTL, true
			}
			return soaMinimum, true
		}
	}
	return 0, false
}

func computeTimeToLive(response *dns.Msg) uint32 {
	var timeToLive uint32
	if len(response.Answer) == 0 {
		if soaTTL, hasSOA := extractNegativeTTL(response); hasSOA {
			return soaTTL
		}
	}
	for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range recordList {
			if record.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if timeToLive == 0 || record.Header().Ttl > 0 && record.Header().Ttl < timeToLive {
				timeToLive = record.Header().Ttl
			}
		}
	}
	return timeToLive
}

func normalizeTTL(response *dns.Msg, timeToLive uint32) {
	for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range recordList {
			if record.Header().Rrtype == dns.TypeOPT {
				continue
			}
			record.Header().Ttl = timeToLive
		}
	}
}

type exchangeStatus int

const (
	exchangeReady exchangeStatus = iota
	exchangeDone
	exchangeWait
)

type exchangeOperation struct {
	ctx             context.Context
	message         *dns.Msg
	question        dns.Question
	messageId       uint16
	options         adapter.DNSQueryOptions
	responseChecker func(response *dns.Msg) bool
	disableCache    bool
	cacheKey        dnsCacheKey
	releaseCond     func()
	// generation is the network generation this query was issued on. Captured when the operation is
	// built, which is BEFORE the round trip, and compared before anything is stored.
	generation         uint64
	hasGenerationGuard bool
}

func (o *exchangeOperation) release() {
	if o.releaseCond != nil {
		o.releaseCond()
		o.releaseCond = nil
	}
}

func (c *Client) beginExchange(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool, allowWait bool) (*exchangeOperation, *dns.Msg, exchangeStatus, error) {
	err := ctx.Err()
	if err != nil {
		return nil, nil, exchangeDone, err
	}
	if len(message.Question) == 0 {
		if c.logger != nil {
			c.logger.WarnContext(ctx, "bad question size: ", len(message.Question))
		}
		return nil, FixedResponseStatus(message, dns.RcodeFormatError), exchangeDone, nil
	}
	question := message.Question[0]
	if question.Qtype == dns.TypeA && options.Strategy == C.DomainStrategyIPv6Only || question.Qtype == dns.TypeAAAA && options.Strategy == C.DomainStrategyIPv4Only {
		if c.logger != nil {
			c.logger.DebugContext(ctx, "strategy rejected")
		}
		return nil, FixedResponseStatus(message, dns.RcodeSuccess), exchangeDone, nil
	}
	isSimpleRequest := len(message.Question) == 1 &&
		len(message.Ns) == 0 &&
		(len(message.Extra) == 0 || len(message.Extra) == 1 &&
			message.Extra[0].Header().Rrtype == dns.TypeOPT &&
			message.Extra[0].Header().Class > 0 &&
			message.Extra[0].Header().Ttl == 0 &&
			common.All(message.Extra[0].(*dns.OPT).Option, func(it dns.EDNS0) bool {
				return it.Option() == dns.EDNS0SUBNET
			}))
	message = c.prepareExchangeMessage(message, options)
	disableCache := !isSimpleRequest || c.disableCache || options.DisableCache
	operation := &exchangeOperation{
		message:         message,
		question:        question,
		messageId:       message.Id,
		options:         options,
		responseChecker: responseChecker,
		disableCache:    disableCache,
	}
	if !disableCache {
		cacheKey := c.newCacheKey(transport, question, message, options)
		operation.cacheKey = cacheKey
		c.captureGeneration(operation)
		exchangeKey := dnsExchangeKey{dnsCacheKey: cacheKey, timeout: options.Timeout}
		for {
			cond, loaded := c.cacheLock.LoadOrStore(exchangeKey, make(chan struct{}))
			if !loaded {
				operation.releaseCond = func() {
					c.cacheLock.Delete(exchangeKey)
					close(cond)
				}
			}
			response, ttl, isStale := c.loadResponse(cacheKey)
			if response != nil {
				if isStale && !options.DisableOptimisticCache {
					c.backgroundRefreshDNS(transport, cacheKey, message.Copy(), options, responseChecker)
					logOptimisticResponse(c.logger, ctx, response)
					response.Id = message.Id
					operation.release()
					return nil, response, exchangeDone, nil
				} else if !isStale {
					logCachedResponse(c.logger, ctx, response, ttl)
					response.Id = message.Id
					operation.release()
					return nil, response, exchangeDone, nil
				}
			}
			// The exact cache missed. Before any upstream work, check whether this NAME
			// is already known not to exist: RFC 2308 makes NXDOMAIN a statement about
			// the name, so one verdict answers every record type and the name costs one
			// query rather than one per type. This sits after the exact lookup so a
			// still-valid positive answer always wins.
			if negative, hit := c.loadNXDomain(cacheKey, question, message.Id); hit {
				logCachedResponse(c.logger, ctx, negative, int(computeTimeToLive(negative)))
				operation.release()
				return nil, negative, exchangeDone, nil
			}
			if !loaded {
				break
			}
			if !allowWait {
				operation.release()
				return nil, nil, exchangeWait, nil
			}
			select {
			case <-cond:
			case <-ctx.Done():
				return nil, nil, exchangeDone, ctx.Err()
			}
			err = ctx.Err()
			if err != nil {
				return nil, nil, exchangeDone, err
			}
			cacheKey = c.newCacheKey(transport, question, message, options)
			operation.cacheKey = cacheKey
			c.captureGeneration(operation)
			exchangeKey = dnsExchangeKey{dnsCacheKey: cacheKey, timeout: options.Timeout}
		}
	}

	contextTransport, transportTagLoaded := adapter.DNSTransportTagFromContext(ctx)
	if transportTagLoaded && transport.Tag() == contextTransport {
		operation.release()
		return nil, nil, exchangeDone, E.New("DNS query loopback in transport[", contextTransport, "]")
	}
	operation.ctx = adapter.ContextWithDNSTransportTag(ctx, transport.Tag())
	if !disableCache && responseChecker != nil && c.rdrc != nil {
		rejected := c.rdrc.LoadRDRC(transport.Tag(), question.Name, question.Qtype)
		if rejected {
			operation.release()
			return nil, nil, exchangeDone, ErrResponseRejectedCached
		}
	}
	return operation, nil, exchangeReady, nil
}

func (c *Client) finishExchange(transport adapter.DNSTransport, operation *exchangeOperation, response *dns.Msg) (*dns.Msg, error) {
	ctx := operation.ctx
	question := operation.question
	disableCache := operation.disableCache || (response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError)
	if operation.responseChecker != nil {
		var rejected bool
		if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
			rejected = true
		} else {
			rejected = !operation.responseChecker(response)
		}
		if rejected {
			if !disableCache && c.rdrc != nil {
				c.rdrc.SaveRDRCAsync(transport.Tag(), question.Name, question.Qtype, c.logger)
			}
			logRejectedResponse(c.logger, ctx, response)
			return response, ErrResponseRejected
		}
	}
	timeToLive := applyResponseOptions(question, response, operation.options)
	if !disableCache && c.generationStillCurrent(operation) {
		cacheKey, storable := c.finishCacheKey(transport, operation.cacheKey)
		if storable {
			c.storeCache(cacheKey, response, timeToLive)
			// A validated NXDOMAIN is a statement about the NAME, so record it once
			// and let every other record type for that name reuse it. Reaching here
			// means the response already passed the checker above, the exchange
			// succeeded, and caching is enabled.
			//
			// storeNXDomain re-checks the conditions that make widening safe:
			// RcodeNameError, a usable SOA TTL, and a single question. NODATA and the
			// error rcodes never reach it, because disableCache already excludes them
			// above.
			if response.Rcode == dns.RcodeNameError {
				c.storeNXDomain(cacheKey, response, timeToLive)
			}
		}
	}
	response.Id = operation.messageId
	requestEDNSOpt := operation.message.IsEdns0()
	responseEDNSOpt := response.IsEdns0()
	if responseEDNSOpt != nil && (requestEDNSOpt == nil || requestEDNSOpt.Version() < responseEDNSOpt.Version()) {
		response.Extra = common.Filter(response.Extra, func(it dns.RR) bool {
			return it.Header().Rrtype != dns.TypeOPT
		})
		if requestEDNSOpt != nil {
			response.SetEdns0(responseEDNSOpt.UDPSize(), responseEDNSOpt.Do())
		}
	}
	logExchangedResponse(c.logger, ctx, response, timeToLive)
	return response, nil
}

func (c *Client) Exchange(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) (*dns.Msg, error) {
	if options.Timeout == 0 {
		options.Timeout = c.timeout
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	operation, earlyResponse, status, err := c.beginExchange(ctx, transport, message, options, responseChecker, true)
	if status != exchangeReady {
		return earlyResponse, err
	}
	defer operation.release()
	response, err := c.exchangeToTransport(operation.ctx, transport, operation.message)
	if err != nil {
		return nil, err
	}
	return c.finishExchange(transport, operation, response)
}

func (c *Client) ExchangeAsync(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool, callback func(response *dns.Msg, err error)) {
	if options.Timeout == 0 {
		options.Timeout = c.timeout
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	operation, earlyResponse, status, err := c.beginExchange(ctx, transport, message, options, responseChecker, false)
	switch status {
	case exchangeDone:
		cancel()
		callback(earlyResponse, err)
		return
	case exchangeWait:
		go func() {
			response, exchangeErr := c.Exchange(ctx, transport, message, options, responseChecker)
			cancel()
			callback(response, exchangeErr)
		}()
		return
	}
	finish := func(response *dns.Msg, exchangeErr error) {
		cancel()
		if exchangeErr != nil {
			operation.release()
			callback(nil, exchangeErr)
			return
		}
		finishedResponse, finishErr := c.finishExchange(transport, operation, response)
		operation.release()
		callback(finishedResponse, finishErr)
	}
	c.exchangeToTransportAsync(operation.ctx, transport, operation.message, finish)
}

func (c *Client) Lookup(ctx context.Context, transport adapter.DNSTransport, domain string, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) ([]netip.Addr, error) {
	domain = FqdnToDomain(domain)
	dnsName := dns.Fqdn(domain)
	var strategy C.DomainStrategy
	if options.LookupStrategy != C.DomainStrategyAsIS {
		strategy = options.LookupStrategy
	} else {
		strategy = options.Strategy
	}
	lookupOptions := options
	if options.LookupStrategy != C.DomainStrategyAsIS {
		lookupOptions.Strategy = strategy
	}
	switch strategy {
	case C.DomainStrategyIPv4Only:
		return c.lookupToExchange(ctx, transport, dnsName, dns.TypeA, lookupOptions, responseChecker)
	case C.DomainStrategyIPv6Only:
		return c.lookupToExchange(ctx, transport, dnsName, dns.TypeAAAA, lookupOptions, responseChecker)
	}
	// Lookup is the COMPLETE-lookup contract, and this is deliberate.
	//
	// Both families are exchanged concurrently but Lookup waits for BOTH. Callers use it for
	// routing, rule matching, the candidate list published on metadata, and diagnostics, and
	// every one of them expects the whole address set. Returning as soon as one family
	// answered would hand routing a half-populated candidate list, which is a correctness
	// change disguised as a latency improvement.
	//
	// A family that answers slowly therefore delays the result. That is the intended
	// trade-off here, and it is why latency-sensitive connection setup does NOT go through
	// this function: a caller that wants to start connecting before both families have
	// answered needs a different entry point, not a partial answer from this one.
	//
	// Concretely: a resolver answering A in 10ms and AAAA in 3s makes Lookup take about 3s.
	// That is correct for routing. It would be wrong to shorten it by dropping the second
	// family, because DestinationAddresses and the rule matcher would then see only half the
	// addresses the resolver returned.
	// The epoch this lookup belongs to, captured BEFORE either family is dispatched.
	//
	// # Why a complete lookup needs its own epoch
	//
	// collectFamiliesComplete runs A and AAAA as two independent exchanges, and each of those
	// captures the generation when its own request is issued. A reset landing between them therefore
	// splits them: the A half is answered on the network that has been left and the AAAA half on the
	// one that is current. Both are individually well-formed, and the caller receives ONE address
	// set that was never simultaneously true on any network - with nothing in the result
	// distinguishing the halves.
	//
	// Unlike the streaming API, where each family is its own published observation and a superseded
	// one simply loses a connection race, a complete lookup is a single claim about a name. The two
	// halves have to belong to the same epoch for that claim to mean anything.
	//
	// Refusing is the minimal behaviour change: the caller's answer was never valid, so it is
	// reported as an error rather than silently returned half-stale. The per-exchange generation
	// guard still does its own job - nothing from a superseded family is cached either way.
	var lookupEpoch uint64
	var lookupHasEpoch bool
	if c.networkGeneration != nil {
		lookupEpoch = c.networkGeneration()
		lookupHasEpoch = true
	}

	response4, response6, err := c.collectFamiliesComplete(
		ctx,
		transport,
		dnsName,
		lookupOptions,
		responseChecker,
	)
	if err != nil {
		return nil, err
	}

	// Refuse a set assembled across an epoch change.
	//
	// Checked after the family exchanges and before the result is assembled, so a split lookup can
	// never be observed as a complete answer.
	if lookupHasEpoch && c.networkGeneration() != lookupEpoch {
		return nil, E.New("network changed while resolving ", dnsName,
			"; the address families belong to different networks")
	}

	return sortAddresses(response4, response6, strategy), nil
}

// collectFamiliesComplete runs both family exchanges and waits for BOTH.
//
// This is the previous task.Group behaviour, kept because Lookup's contract depends on it:
// callers need the complete set, not the fastest answer.
func (c *Client) collectFamiliesComplete(
	ctx context.Context,
	transport adapter.DNSTransport,
	dnsName string,
	options adapter.DNSQueryOptions,
	responseChecker func(response *dns.Msg) bool,
) ([]netip.Addr, []netip.Addr, error) {
	var (
		response4 []netip.Addr
		response6 []netip.Addr
		err4      error
		err6      error
		access    sync.Mutex
		waitGroup sync.WaitGroup
	)

	exchange := func(qType uint16, ipv6 bool) {
		defer waitGroup.Done()
		addresses, err := c.lookupToExchange(ctx, transport, dnsName, qType, options, responseChecker)
		access.Lock()
		if ipv6 {
			response6 = addresses
			err6 = err
		} else {
			response4 = addresses
			err4 = err
		}
		access.Unlock()
	}

	waitGroup.Add(2)
	go exchange(dns.TypeA, false)
	go exchange(dns.TypeAAAA, true)
	waitGroup.Wait()

	access.Lock()
	defer access.Unlock()
	if len(response4) == 0 && len(response6) == 0 {
		if err := E.Errors(err4, err6); err != nil {
			return nil, nil, err
		}
		return nil, nil, E.New("no address for ", dnsName)
	}

	// At least one family answered. Before returning it, honour the caller's own lifecycle.
	//
	// Lookup's contract is the COMPLETE set - that is why it waits for both families rather than
	// taking the fastest answer. If the caller cancelled or its deadline expired while the other
	// family was still outstanding, returning the partial result with a nil error reports a
	// completed operation that the caller had already withdrawn. The caller is then entitled to
	// treat the partial set as the whole answer.
	//
	// This is deliberately narrower than "any family error fails the lookup". An upstream family
	// failure with a live context is NOT a cancellation: one family answering while the other
	// SERVFAILs is an ordinary partial result, and it stays usable. Only the caller withdrawing
	// the operation changes the outcome here.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, nil, ctxErr
	}

	return response4, response6, nil
}

func (c *Client) ClearCache() {
	// A clear that left name-wide NXDOMAIN verdicts behind would answer subsequent
	// queries from exactly the state the caller asked to discard.
	c.clearNXDomainCache()
	if c.cache != nil {
		c.cache.Purge()
	}
	if c.dnsCache != nil {
		err := c.dnsCache.ClearDNSCache()
		if err != nil && c.logger != nil {
			c.logger.Warn("clear DNS cache: ", err)
		}
	}
}

func sortAddresses(response4 []netip.Addr, response6 []netip.Addr, strategy C.DomainStrategy) []netip.Addr {
	if strategy == C.DomainStrategyPreferIPv6 {
		return append(response6, response4...)
	} else {
		return append(response4, response6...)
	}
}

func (c *Client) storeCache(key dnsCacheKey, message *dns.Msg, timeToLive uint32) {
	if timeToLive == 0 {
		return
	}
	if c.dnsCache != nil {
		packed, err := message.Pack()
		if err == nil {
			expireAt := time.Now().Add(time.Second * time.Duration(timeToLive))
			c.dnsCache.SaveDNSCacheAsync(key.persistentName(), key.Name, key.Qtype, packed, expireAt, c.logger)
		}
		return
	}
	if c.cache == nil {
		return
	}
	if c.disableExpire {
		c.cache.Add(key, message.Copy())
	} else {
		c.cache.AddWithLifetime(key, message.Copy(), time.Second*time.Duration(timeToLive))
	}
}

func (c *Client) lookupToExchange(ctx context.Context, transport adapter.DNSTransport, name string, qType uint16, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) ([]netip.Addr, error) {
	question := dns.Question{
		Name:   name,
		Qtype:  qType,
		Qclass: dns.ClassINET,
	}
	message := dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: []dns.Question{question},
	}
	disableCache := c.disableCache || options.DisableCache
	if !disableCache {
		cachedAddresses, err := c.questionCache(ctx, transport, &message, options, responseChecker)
		if err != ErrNotCached {
			return cachedAddresses, err
		}
	}
	response, err := c.Exchange(ctx, transport, &message, options, responseChecker)
	if err != nil {
		return nil, err
	}
	if response.Rcode != dns.RcodeSuccess {
		return nil, RcodeError(response.Rcode)
	}
	return MessageToAddresses(response), nil
}

func (c *Client) questionCache(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) ([]netip.Addr, error) {
	question := message.Question[0]
	cacheKey := c.newCacheKey(transport, question, message, options)
	response, _, isStale := c.loadResponse(cacheKey)
	if response == nil {
		// The name-wide NXDOMAIN lookup lives in beginExchange, which is the single
		// cache entry point for both Exchange and ExchangeAsync. Doing it here as well
		// would be a second site to keep in step for no additional coverage.
		return nil, ErrNotCached
	}
	if isStale {
		if options.DisableOptimisticCache {
			return nil, ErrNotCached
		}
		c.backgroundRefreshDNS(transport, cacheKey, c.prepareExchangeMessage(message.Copy(), options), options, responseChecker)
		logOptimisticResponse(c.logger, ctx, response)
	}
	if response.Rcode != dns.RcodeSuccess {
		return nil, RcodeError(response.Rcode)
	}
	return MessageToAddresses(response), nil
}

func (c *Client) loadResponse(key dnsCacheKey) (*dns.Msg, int, bool) {
	if c.dnsCache != nil {
		return c.loadPersistentResponse(key)
	}
	if c.cache == nil {
		return nil, 0, false
	}
	if c.disableExpire {
		response, loaded := c.cache.Get(key)
		if !loaded {
			return nil, 0, false
		}
		return response.Copy(), 0, false
	}
	response, expireAt, loaded := c.cache.GetWithLifetimeNoExpire(key)
	if !loaded {
		return nil, 0, false
	}
	timeNow := time.Now()
	if timeNow.After(expireAt) {
		if c.optimisticTimeout > 0 && timeNow.Before(expireAt.Add(c.optimisticTimeout)) {
			response = response.Copy()
			normalizeTTL(response, 1)
			return response, 0, true
		}
		c.cache.Remove(key)
		return nil, 0, false
	}
	nowTTL := max(int(expireAt.Sub(timeNow).Seconds()), 0)
	response = response.Copy()
	normalizeTTL(response, uint32(nowTTL))
	return response, nowTTL, false
}

func (c *Client) loadPersistentResponse(key dnsCacheKey) (*dns.Msg, int, bool) {
	rawMessage, expireAt, loaded := c.dnsCache.LoadDNSCache(key.persistentName(), key.Name, key.Qtype)
	if !loaded {
		return nil, 0, false
	}
	response := new(dns.Msg)
	err := response.Unpack(rawMessage)
	if err != nil {
		return nil, 0, false
	}
	if c.disableExpire {
		return response, 0, false
	}
	timeNow := time.Now()
	if timeNow.After(expireAt) {
		if c.optimisticTimeout > 0 && timeNow.Before(expireAt.Add(c.optimisticTimeout)) {
			normalizeTTL(response, 1)
			return response, 0, true
		}
		return nil, 0, false
	}
	nowTTL := max(int(expireAt.Sub(timeNow).Seconds()), 0)
	normalizeTTL(response, uint32(nowTTL))
	return response, nowTTL, false
}

func applyResponseOptions(question dns.Question, response *dns.Msg, options adapter.DNSQueryOptions) uint32 {
	if question.Qtype == dns.TypeHTTPS && (options.Strategy == C.DomainStrategyIPv4Only || options.Strategy == C.DomainStrategyIPv6Only) {
		for _, rr := range response.Answer {
			https, isHTTPS := rr.(*dns.HTTPS)
			if !isHTTPS {
				continue
			}
			content := https.SVCB
			content.Value = common.Filter(content.Value, func(it dns.SVCBKeyValue) bool {
				if options.Strategy == C.DomainStrategyIPv4Only {
					return it.Key() != dns.SVCB_IPV6HINT
				}
				return it.Key() != dns.SVCB_IPV4HINT
			})
			https.SVCB = content
		}
	}
	timeToLive := computeTimeToLive(response)
	if options.RewriteTTL != nil {
		timeToLive = *options.RewriteTTL
	}
	normalizeTTL(response, timeToLive)
	return timeToLive
}

func (c *Client) backgroundRefreshDNS(transport adapter.DNSTransport, key dnsCacheKey, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) {
	_, loaded := c.backgroundRefresh.LoadOrStore(key, struct{}{})
	if loaded {
		return
	}
	go func() {
		defer c.backgroundRefresh.Delete(key)
		timeout := options.Timeout
		if timeout == 0 {
			timeout = c.timeout
		}
		ctx := adapter.ContextWithDNSTransportTag(c.ctx, transport.Tag())
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		// The refresh makes its OWN round trip, so it captures the generation at ITS issue point
		// rather than inheriting the one from the stale read that scheduled it. A refresh started
		// before a reset and completing after it must not repopulate the cache the reset cleared.
		refreshOperation := &exchangeOperation{}
		if c.networkGeneration != nil {
			refreshOperation.generation = c.networkGeneration()
			refreshOperation.hasGenerationGuard = true
		}

		response, err := c.exchangeToTransport(ctx, transport, message)
		if err != nil {
			if c.logger != nil {
				c.logger.DebugContext(ctx, "optimistic refresh failed for ", FqdnToDomain(key.Name), ": ", err)
			}
			return
		}
		if responseChecker != nil {
			var rejected bool
			if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
				rejected = true
			} else {
				rejected = !responseChecker(response)
			}
			if rejected {
				if c.logger != nil {
					c.logger.DebugContext(ctx, "optimistic refresh rejected for ", FqdnToDomain(key.Name))
				}
				if c.rdrc != nil {
					c.rdrc.SaveRDRCAsync(transport.Tag(), key.Name, key.Qtype, c.logger)
				}
				return
			}
		} else if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
			return
		}
		if !c.generationStillCurrent(refreshOperation) {
			return
		}
		storeKey, storable := c.finishCacheKey(transport, key)
		if !storable {
			return
		}
		timeToLive := applyResponseOptions(key.Question, response, options)
		c.storeCache(storeKey, response, timeToLive)
		logRefreshedResponse(c.logger, ctx, response, timeToLive)
	}()
}

func (c *Client) prepareExchangeMessage(message *dns.Msg, options adapter.DNSQueryOptions) *dns.Msg {
	if options.RemoveClientSubnet {
		return removeClientSubnet(message)
	}
	clientSubnet := options.ClientSubnet
	if !clientSubnet.IsValid() {
		clientSubnet = c.clientSubnet
	}
	if clientSubnet.IsValid() {
		message = SetClientSubnet(message, clientSubnet)
	}
	return message
}

func stripDNSPadding(response *dns.Msg) {
	for _, record := range response.Extra {
		opt, isOpt := record.(*dns.OPT)
		if !isOpt {
			continue
		}
		opt.Option = common.Filter(opt.Option, func(it dns.EDNS0) bool {
			return it.Option() != dns.EDNS0PADDING
		})
	}
}

func (c *Client) exchangeToTransport(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg) (*dns.Msg, error) {
	response, err := transport.Exchange(ctx, message)
	if err == nil {
		stripDNSPadding(response)
		return response, nil
	}
	var rcodeError RcodeError
	if errors.As(err, &rcodeError) {
		return FixedResponseStatus(message, int(rcodeError)), nil
	}
	return nil, err
}

func (c *Client) exchangeToTransportAsync(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, callback func(response *dns.Msg, err error)) {
	transport.ExchangeAsync(ctx, message, func(response *dns.Msg, err error) {
		if err == nil {
			stripDNSPadding(response)
			callback(response, nil)
			return
		}
		var rcodeError RcodeError
		if errors.As(err, &rcodeError) {
			callback(FixedResponseStatus(message, int(rcodeError)), nil)
			return
		}
		callback(nil, err)
	})
}

func MessageToAddresses(response *dns.Msg) []netip.Addr {
	return adapter.DNSResponseAddresses(response)
}

func FixedResponseStatus(message *dns.Msg, rcode int) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 message.Id,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              rcode,
		},
		Question: message.Question,
	}
}

func FixedResponse(id uint16, question dns.Question, addresses []netip.Addr, timeToLive uint32) *dns.Msg {
	response := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 id,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              dns.RcodeSuccess,
		},
		Question: []dns.Question{question},
	}
	for _, address := range addresses {
		if address.Is4() && question.Qtype == dns.TypeA {
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    timeToLive,
				},
				A: address.AsSlice(),
			})
		} else if address.Is6() && question.Qtype == dns.TypeAAAA {
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    timeToLive,
				},
				AAAA: address.AsSlice(),
			})
		}
	}
	return &response
}

func FixedResponseCNAME(id uint16, question dns.Question, record string, timeToLive uint32) *dns.Msg {
	response := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 id,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              dns.RcodeSuccess,
		},
		Question: []dns.Question{question},
		Answer: []dns.RR{
			&dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    timeToLive,
				},
				Target: record,
			},
		},
	}
	return &response
}

func FixedResponseTXT(id uint16, question dns.Question, records []string, timeToLive uint32) *dns.Msg {
	response := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 id,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              dns.RcodeSuccess,
		},
		Question: []dns.Question{question},
		Answer: []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    timeToLive,
				},
				Txt: records,
			},
		},
	}
	return &response
}

func FixedResponseMX(id uint16, question dns.Question, records []*net.MX, timeToLive uint32) *dns.Msg {
	response := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 id,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              dns.RcodeSuccess,
		},
		Question: []dns.Question{question},
	}
	for _, record := range records {
		response.Answer = append(response.Answer, &dns.MX{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    timeToLive,
			},
			Preference: record.Pref,
			Mx:         record.Host,
		})
	}
	return &response
}
