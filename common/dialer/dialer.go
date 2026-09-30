package dialer

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type Options struct {
	Context                 context.Context
	Options                 option.DialerOptions
	RemoteIsDomain          bool
	DirectResolver          bool
	ResolverOnDetour        bool
	NewDialer               bool
	DisableEmptyDirectCheck bool
	DirectOutbound          bool
	DefaultOutbound         bool
}

// TODO: merge with NewWithOptions
func New(ctx context.Context, options option.DialerOptions, remoteIsDomain bool) (N.Dialer, error) {
	return NewWithOptions(Options{
		Context:        ctx,
		Options:        options,
		RemoteIsDomain: remoteIsDomain,
	})
}

func NewWithOptions(options Options) (N.Dialer, error) {
	dialOptions := options.Options
	var (
		dialer N.Dialer
		err    error
	)
	hasDetour := dialOptions.Detour != "" || options.DefaultOutbound
	if dialOptions.Detour != "" {
		outboundManager := service.FromContext[adapter.OutboundManager](options.Context)
		if outboundManager == nil {
			return nil, E.New("missing outbound manager")
		}
		dialer = NewDetour(outboundManager, dialOptions.Detour, options.DisableEmptyDirectCheck)
	} else if options.DefaultOutbound {
		outboundManager := service.FromContext[adapter.OutboundManager](options.Context)
		if outboundManager == nil {
			return nil, E.New("missing outbound manager")
		}
		dialer = NewDefaultOutboundDetour(outboundManager)
	} else {
		dialer, err = NewDefault(options.Context, dialOptions)
		if err != nil {
			return nil, err
		}
	}
	if options.RemoteIsDomain && (!hasDetour || options.ResolverOnDetour || dialOptions.DomainResolver != nil && dialOptions.DomainResolver.Server != "") {
		var (
			server          string
			dnsQueryOptions adapter.DNSQueryOptions
		)
		hasDomainResolver := dialOptions.DomainResolver != nil && dialOptions.DomainResolver.Server != ""
		if options.DirectResolver {
			if !hasDomainResolver {
				return nil, E.New("missing domain resolver for domain server address")
			}
			dnsQueryOptions = domainResolveQueryOptions(dialOptions.DomainResolver)
		} else {
			dnsQueryOptions, err = NewDNSQueryOptions(options.Context, dialOptions.DomainResolver, options.NewDialer)
			if err != nil {
				return nil, err
			}
		}
		if hasDomainResolver {
			server = dialOptions.DomainResolver.Server
		}
		if
		//nolint:staticcheck
		dialOptions.DomainStrategy != option.DomainStrategy(C.DomainStrategyAsIS) && (!hasDomainResolver || dialOptions.DomainResolver.Strategy == option.DomainStrategy(C.DomainStrategyAsIS)) {
			//nolint:staticcheck
			dnsQueryOptions.Strategy = C.DomainStrategy(dialOptions.DomainStrategy)
			deprecated.Report(options.Context, deprecated.OptionLegacyDomainStrategyOptions)
		}
		dialer = NewResolveDialer(
			options.Context,
			dialer,
			dialOptions.Detour == "" && !dialOptions.TCPFastOpen,
			server,
			dnsQueryOptions,
			time.Duration(dialOptions.FallbackDelay),
		)
	}
	return dialer, nil
}

func NewDNSQueryOptions(ctx context.Context, domainResolver *option.DomainResolveOptions, newDialer bool) (adapter.DNSQueryOptions, error) {
	dnsTransport := service.FromContext[adapter.DNSTransportManager](ctx)
	if domainResolver != nil && domainResolver.Server != "" {
		transport, loaded := dnsTransport.Transport(domainResolver.Server)
		if !loaded {
			return adapter.DNSQueryOptions{}, E.New("domain resolver not found: ", domainResolver.Server)
		}
		dnsQueryOptions := domainResolveQueryOptions(domainResolver)
		dnsQueryOptions.Transport = transport
		return dnsQueryOptions, nil
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		// No network manager means no default resolver is configured anywhere, so there is nothing
		// to fall back to. Reporting that honestly beats dereferencing a nil service: construction
		// must not panic on a context that simply has fewer services registered than a running box.
		return adapter.DNSQueryOptions{}, nil
	}
	defaultOptions := networkManager.DefaultOptions()
	if defaultOptions.DomainResolver != "" {
		transport, loaded := dnsTransport.Transport(defaultOptions.DomainResolver)
		if !loaded {
			return adapter.DNSQueryOptions{}, E.New("default domain resolver not found: ", defaultOptions.DomainResolver)
		}
		dnsQueryOptions := defaultOptions.DomainResolveOptions
		dnsQueryOptions.Transport = transport
		return dnsQueryOptions, nil
	}
	if len(dnsTransport.Transports()) < 2 {
		return adapter.DNSQueryOptions{Transport: dnsTransport.Default()}, nil
	}
	if newDialer {
		return adapter.DNSQueryOptions{}, E.New("missing domain resolver for domain server address")
	}
	deprecated.Report(ctx, deprecated.OptionMissingDomainResolver)
	return adapter.DNSQueryOptions{}, nil
}

func domainResolveQueryOptions(domainResolver *option.DomainResolveOptions) adapter.DNSQueryOptions {
	return adapter.DNSQueryOptions{
		Strategy:               C.DomainStrategy(domainResolver.Strategy),
		Timeout:                time.Duration(domainResolver.Timeout),
		DisableCache:           domainResolver.DisableCache,
		DisableOptimisticCache: domainResolver.DisableOptimisticCache,
		RewriteTTL:             domainResolver.RewriteTTL,
		ClientSubnet:           domainResolver.ClientSubnet.Build(netip.Prefix{}),
	}
}

type ParallelInterfaceDialer interface {
	N.Dialer
	DialParallelInterface(ctx context.Context, network string, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error)
	ListenSerialInterfacePacket(ctx context.Context, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, error)
}

type ParallelNetworkDialer interface {
	DialParallelNetwork(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error)
	ListenSerialNetworkPacket(ctx context.Context, destination M.Socksaddr, destinationAddresses []netip.Addr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, netip.Addr, error)
}

type PacketDialerWithDestination interface {
	ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error)
}

// TargetQueryOptions derives the DNS query policy for a name this outbound resolves ITSELF, rather
// than one the dialer resolves in order to reach the proxy server.
//
// # Why this is separate from the dialer's own resolve policy
//
// NewWithOptions only builds a ResolveDialer when RemoteIsDomain is true, i.e. when the PROXY
// SERVER's address is a hostname. An outbound that must also resolve a TARGET name -- SOCKS4 is the
// case that exists today, because its request format carries only a 4-byte IPv4 address -- would
// get nothing from that dialer when the server happens to be an IP literal.
//
// Deriving the target policy from that would make the target's DNS authority depend on an unrelated
// fact about how the server is addressed. Both names come from the same DialerOptions, so both must
// be derived from it, and the derivation is shared rather than duplicated.
//
// # Why the last "no transports" branch differs from the dialer's
//
// NewDNSQueryOptions treats a missing domain resolver as fatal when it is building a dialer for a
// DOMAIN SERVER (newDialer=true): the connection cannot be made at all without it. A target
// resolution is not in that position -- the outbound still works for IP targets, and the router
// falls back to its own default path -- so this reports the empty policy rather than failing
// construction. Turning a working outbound into a construction error would be a behaviour change
// beyond the bug being fixed.
func TargetQueryOptions(ctx context.Context, options option.DialerOptions) (adapter.DNSQueryOptions, error) {
	hasDomainResolver := options.DomainResolver != nil && options.DomainResolver.Server != ""

	dnsQueryOptions, err := NewDNSQueryOptions(ctx, options.DomainResolver, false)
	if err != nil {
		return adapter.DNSQueryOptions{}, err
	}

	// The legacy domain_strategy applies only when the operator did not set a strategy on the
	// resolver itself. This mirrors NewWithOptions exactly, so both derivations agree.
	if
	//nolint:staticcheck
	options.DomainStrategy != option.DomainStrategy(C.DomainStrategyAsIS) &&
		(!hasDomainResolver ||
			options.DomainResolver.Strategy == option.DomainStrategy(C.DomainStrategyAsIS)) {
		//nolint:staticcheck
		dnsQueryOptions.Strategy = C.DomainStrategy(options.DomainStrategy)
		deprecated.Report(ctx, deprecated.OptionLegacyDomainStrategyOptions)
	}
	return dnsQueryOptions, nil
}
