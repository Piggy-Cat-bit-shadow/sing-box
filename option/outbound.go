package option

import (
	"context"
	"reflect"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type OutboundOptionsRegistry interface {
	OptionTypes() []string
	CreateOptions(outboundType string) (any, bool)
}

type _Outbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag,omitempty"`
	// TrafficClass is a fork extension, carried on the shared envelope rather than on
	// SelectorOutboundOptions.
	//
	// # Why the envelope
	//
	// TrafficClass is not a selector property. Any outbound - a selector, a urltest group, a leaf
	// protocol - may be given one, and the resolution walks the whole logical chain looking for
	// the first explicit value. Putting the field on one options type would make it unavailable
	// everywhere else and would tie a routing policy to a single protocol.
	//
	// # Why a pointer
	//
	// nil is "unset" and a non-nil value is an explicit choice, including an explicit "default".
	// That distinction is what lets an operator stop automatic classification for one outbound.
	// See TrafficClassPolicy.
	//
	// # Compatibility
	//
	// The field is omitted when unset, so a configuration that does not use it serialises exactly
	// as before. A configuration that DOES use it is fork-only: official sing-box does not know
	// this key. Nothing in this fork rewrites or injects it, so a configuration relying only on
	// automatic tag detection remains loadable by the official client.
	TrafficClass *TrafficClassPolicy `json:"traffic_class,omitempty"`
	Options      any                 `json:"-"`
}

type Outbound _Outbound

func (h *Outbound) MarshalJSONContext(ctx context.Context) ([]byte, error) {
	return badjson.MarshallObjectsContext(ctx, (*_Outbound)(h), h.Options)
}

func (h *Outbound) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	err := json.UnmarshalContext(ctx, content, (*_Outbound)(h))
	if err != nil {
		return err
	}
	registry := service.FromContext[OutboundOptionsRegistry](ctx)
	if registry == nil {
		return E.New("missing outbound options registry in context")
	}
	switch h.Type {
	case C.TypeDNS:
		return E.New("dns outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use rule actions instead")
	}
	options, loaded := registry.CreateOptions(h.Type)
	if !loaded {
		return E.New("unknown outbound type: ", h.Type)
	}
	err = badjson.UnmarshallExcludedContext(ctx, content, (*_Outbound)(h), options)
	if err != nil {
		return err
	}
	if listenWrapper, isListen := options.(ListenOptionsWrapper); isListen {
		//nolint:staticcheck
		if listenWrapper.TakeListenOptions().InboundOptions != (InboundOptions{}) {
			return E.New("legacy inbound fields are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use rule actions instead")
		}
	}
	h.Options = options
	return nil
}

func (h Outbound) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("Outbound", func() (*schema.Node, error) {
		registry := service.FromContext[OutboundOptionsRegistry](builder.Context())
		if registry == nil {
			return nil, E.New("missing outbound options registry in context")
		}
		return registryUnion(builder, registry, []string{C.TypeShadowsocksR, C.TypeWireGuard}, true)
	})
}

type DialerOptionsWrapper interface {
	TakeDialerOptions() DialerOptions
	ReplaceDialerOptions(options DialerOptions)
}

type DialerOptions struct {
	Detour string `json:"detour,omitempty" reference:"outbound"`
	AbstractDialerOptions
	// DestinationDNSOwnership declares that this outbound is a DOWNSTREAM physical hop - a proxy the
	// user's traffic reaches after leaving the device - and that the destination domain must
	// therefore be resolved by this fork's DNS policy plane before the request is written to it.
	//
	// # What it changes on the wire
	//
	// With it enabled, a domain destination reaching this outbound is resolved locally and the
	// outbound sends the resulting IPv4 or IPv6 ADDRESS to the proxy, never the domain. SOCKS5 gets
	// ATYP=IPv4/IPv6 instead of ATYP=DOMAIN, and HTTP CONNECT gets an `IP:port` authority instead of
	// a hostname. The original domain stays in the connection metadata, so routing, SNI, the Host
	// header, tracking and diagnostics are unaffected.
	//
	// # Why it is not the default
	//
	// It is false by default, and that default is deliberate. For a single-hop SOCKS5 or HTTP proxy
	// the downstream resolver is usually the BETTER resolver - it is in the destination's region, so
	// it picks the right CDN edge, while resolving locally picks whichever edge is nearest to the
	// device and then asks the proxy to reach it. Turning this on for such a configuration is a
	// deliberate loss of that property, which is why it is an operator's declaration rather than an
	// automatic behaviour.
	//
	// The names this applies to are the DESTINATION's. The proxy SERVER's own hostname keeps using
	// `domain_resolver` and the ordinary dial path, because a node address and a destination address
	// are different questions with different answers.
	DestinationDNSOwnership bool `json:"destination_dns_ownership,omitempty"`
}

type AbstractDialerOptions struct {
	BindInterface              string                            `json:"bind_interface,omitempty"`
	Inet4BindAddress           *badoption.Addr                   `json:"inet4_bind_address,omitempty"`
	Inet6BindAddress           *badoption.Addr                   `json:"inet6_bind_address,omitempty"`
	BindAddressNoPort          bool                              `json:"bind_address_no_port,omitempty"`
	ProtectPath                string                            `json:"protect_path,omitempty"`
	RoutingMark                FwMark                            `json:"routing_mark,omitempty"`
	ReuseAddr                  bool                              `json:"reuse_addr,omitempty"`
	NetNs                      string                            `json:"netns,omitempty" reference:"network_namespace"`
	ConnectTimeout             badoption.Duration                `json:"connect_timeout,omitempty"`
	TCPFastOpen                bool                              `json:"tcp_fast_open,omitempty"`
	TCPMultiPath               bool                              `json:"tcp_multi_path,omitempty"`
	DisableTCPKeepAlive        bool                              `json:"disable_tcp_keep_alive,omitempty"`
	TCPKeepAlive               badoption.Duration                `json:"tcp_keep_alive,omitempty"`
	TCPKeepAliveInterval       badoption.Duration                `json:"tcp_keep_alive_interval,omitempty"`
	TCPKeepAliveSystemDefaults bool                              `json:"-"`
	UDPBindPort                uint16                            `json:"-"`
	UDPFragment                *bool                             `json:"udp_fragment,omitempty"`
	UDPFragmentDefault         bool                              `json:"-"`
	DomainResolver             *DomainResolveOptions             `json:"domain_resolver,omitempty"`
	NetworkStrategy            *NetworkStrategy                  `json:"network_strategy,omitempty"`
	NetworkType                badoption.Listable[InterfaceType] `json:"network_type,omitempty"`
	FallbackNetworkType        badoption.Listable[InterfaceType] `json:"fallback_network_type,omitempty"`
	FallbackDelay              badoption.Duration                `json:"fallback_delay,omitempty"`

	// Deprecated: migrated to domain resolver
	DomainStrategy DomainStrategy `json:"domain_strategy,omitempty" schema:"omit"`
}

type _DomainResolveOptions struct {
	Server                 string                `json:"server" reference:"dns_server"`
	Timeout                badoption.Duration    `json:"timeout,omitempty"`
	Strategy               DomainStrategy        `json:"strategy,omitempty"`
	DisableCache           bool                  `json:"disable_cache,omitempty"`
	DisableOptimisticCache bool                  `json:"disable_optimistic_cache,omitempty"`
	RewriteTTL             *uint32               `json:"rewrite_ttl,omitempty"`
	ClientSubnet           *badoption.Prefixable `json:"client_subnet,omitempty"`
}

type DomainResolveOptions _DomainResolveOptions

func (o DomainResolveOptions) MarshalJSON() ([]byte, error) {
	if o.Server == "" {
		return []byte("{}"), nil
	} else if o.Strategy == DomainStrategy(C.DomainStrategyAsIS) &&
		o.Timeout == 0 &&
		!o.DisableCache &&
		!o.DisableOptimisticCache &&
		o.RewriteTTL == nil &&
		o.ClientSubnet == nil {
		return json.Marshal(o.Server)
	} else {
		return json.Marshal(_DomainResolveOptions(o))
	}
}

func (o *DomainResolveOptions) UnmarshalJSON(bytes []byte) error {
	var stringValue string
	err := json.Unmarshal(bytes, &stringValue)
	if err == nil {
		o.Server = stringValue
		return nil
	}
	err = json.Unmarshal(bytes, (*_DomainResolveOptions)(o))
	if err != nil {
		return err
	}
	if o.Server == "" {
		return E.New("empty domain_resolver.server")
	}
	return nil
}

func (o DomainResolveOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("DomainResolver", func() (*schema.Node, error) {
		objectForm := schema.StrictObject()
		err := builder.FlattenStruct(objectForm, reflect.TypeFor[DomainResolveOptions]())
		if err != nil {
			return nil, err
		}
		objectForm.Required = []string{"server"}
		return schema.AnyOf(schema.TagReferenceNode("dns_server"), objectForm), nil
	})
}

func (o *DialerOptions) TakeDialerOptions() DialerOptions {
	return *o
}

func (o *DialerOptions) ReplaceDialerOptions(options DialerOptions) {
	*o = options
}

type ServerOptionsWrapper interface {
	TakeServerOptions() ServerOptions
	ReplaceServerOptions(options ServerOptions)
}

type ServerOptions struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}

func (o ServerOptions) Build() M.Socksaddr {
	return M.ParseSocksaddrHostPort(o.Server, o.ServerPort)
}

func (o ServerOptions) ServerIsDomain() bool {
	return o.Build().IsDomain()
}

func (o *ServerOptions) TakeServerOptions() ServerOptions {
	return *o
}

func (o *ServerOptions) ReplaceServerOptions(options ServerOptions) {
	*o = options
}
