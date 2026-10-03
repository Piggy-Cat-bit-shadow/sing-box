package adapter

import (
	"context"
	"net/netip"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/miekg/dns"
)

// DNSFamilyResult is one address family's outcome from a dual-stack lookup.
type DNSFamilyResult struct {
	// IPv6 reports which family this result is for.
	IPv6 bool
	// Addresses are the usable addresses for this family, empty when none were returned.
	Addresses []netip.Addr
	// Err is the lookup error, if any. A nil error with no addresses means the family
	// answered with nothing usable, which is not a failure of the other family.
	Err error
	// EffectiveStrategy is the strategy the resolver actually applied, after its own defaults
	// have been taken into account. Both families of one lookup report the same value.
	//
	// # Why the caller cannot derive this itself
	//
	// A connection-layer caller sees only DNSQueryOptions, whose Strategy is frequently AsIS.
	// AsIS is not a preference - it means "use the resolver's default", and that default is
	// owned by the DNS router (defaultDomainStrategy). A caller that read Strategy directly
	// would therefore treat AsIS as "not PreferIPv6" and rank IPv4 first even when the resolver
	// is configured to prefer IPv6, giving the opposite of the configured behaviour.
	//
	// The resolver is the only component that knows the effective value, so it reports it. The
	// caller must not guess, and must not reach into DNS options to reconstruct it.
	//
	// AsIS is still reported as AsIS when nothing overrides it: the caller then keeps the
	// existing project behaviour rather than inventing a third interpretation.
	EffectiveStrategy C.DomainStrategy
}

// DNSDualStackRouter is an OPTIONAL capability for resolving both families incrementally.
//
// # Why optional
//
// The connection path needs each family's addresses as they arrive, so a late family can join
// a race already in progress. The complete-lookup contract Lookup provides cannot express
// that. Adding the method to DNSRouter itself would force every implementation and every mock
// to provide it, so it is a separate interface that callers type-assert for and fall back from.
//
// # What an implementation must NOT do
//
// It must not issue its own queries. Every exchange has to pass through the same rule
// evaluation, transport selection, response checking, caching, singleflight, ECS handling and
// negative caching as Lookup. A second query path that bypasses any of that is worse than a
// slower one, because it silently changes what policy applies.
type DNSDualStackRouter interface {
	// LookupFamilies resolves both families concurrently and calls publish once per family,
	// as each completes. publish must be safe to call from different goroutines.
	//
	// It returns an error only when neither family could be resolved at all. A family that
	// fails while the other succeeds is reported through its own DNSFamilyResult.
	LookupFamilies(ctx context.Context, domain string, options DNSQueryOptions, publish func(DNSFamilyResult)) error
}

type DNSRouter interface {
	Lifecycle
	Exchange(ctx context.Context, message *dns.Msg, options DNSQueryOptions) (*dns.Msg, error)
	ExchangeAsync(ctx context.Context, message *dns.Msg, options DNSQueryOptions, callback func(response *dns.Msg, err error))
	Lookup(ctx context.Context, domain string, options DNSQueryOptions) ([]netip.Addr, error)
	ClearCache()
	LookupReverseMapping(ip netip.Addr) (string, bool)
	ResetNetwork()
}

type DNSClient interface {
	Start()
	Exchange(ctx context.Context, transport DNSTransport, message *dns.Msg, options DNSQueryOptions, responseChecker func(response *dns.Msg) bool) (*dns.Msg, error)
	ExchangeAsync(ctx context.Context, transport DNSTransport, message *dns.Msg, options DNSQueryOptions, responseChecker func(response *dns.Msg) bool, callback func(response *dns.Msg, err error))
	Lookup(ctx context.Context, transport DNSTransport, domain string, options DNSQueryOptions, responseChecker func(response *dns.Msg) bool) ([]netip.Addr, error)
	ClearCache()
}

type DNSQueryOptions struct {
	Transport              DNSTransport
	Strategy               C.DomainStrategy
	LookupStrategy         C.DomainStrategy
	DisableCache           bool
	DisableOptimisticCache bool
	RewriteTTL             *uint32
	Timeout                time.Duration
	ClientSubnet           netip.Prefix
	RemoveClientSubnet     bool
}

type RDRCStore interface {
	LoadRDRC(transportName string, qName string, qType uint16) (rejected bool)
	SaveRDRC(transportName string, qName string, qType uint16) error
	SaveRDRCAsync(transportName string, qName string, qType uint16, logger logger.Logger)
}

type DNSCacheStore interface {
	LoadDNSCache(transportName string, qName string, qType uint16) (rawMessage []byte, expireAt time.Time, loaded bool)
	SaveDNSCache(transportName string, qName string, qType uint16, rawMessage []byte, expireAt time.Time) error
	SaveDNSCacheAsync(transportName string, qName string, qType uint16, rawMessage []byte, expireAt time.Time, logger logger.Logger)
	ClearDNSCache() error
}

type DNSTransport interface {
	Lifecycle
	Type() string
	Tag() string
	Dependencies() []string
	// Reset closes the transport's existing connections so later requests use fresh connections.
	// Exchanges that are currently using those connections may fail.
	Reset()
	Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error)
	ExchangeAsync(ctx context.Context, message *dns.Msg, callback func(response *dns.Msg, err error))
}

type DNSTransportWithPreferredDomain interface {
	DNSTransport
	PreferredDomain(domain string) bool
}

type DNSTransportWithConfiguration interface {
	DNSTransport
	ServerAddresses() []netip.Addr
	SearchDomains() []string
}

type DNSTransportWithEnvironment interface {
	DNSTransport
	Environment() []string
}

type DNSTransportRegistry interface {
	option.DNSTransportOptionsRegistry
	CreateDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, transportType string, options any) (DNSTransport, error)
}

type DNSTransportManager interface {
	Lifecycle
	Transports() []DNSTransport
	Transport(tag string) (DNSTransport, bool)
	Default() DNSTransport
	FakeIP() FakeIPTransport
	Remove(tag string) error
	Create(ctx context.Context, logger log.ContextLogger, tag string, outboundType string, options any) error
}
