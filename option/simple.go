package option

import (
	"context"
	"reflect"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
)

type SocksInboundOptions struct {
	ListenOptions
	Users          []auth.User           `json:"users,omitempty"`
	DomainResolver *DomainResolveOptions `json:"domain_resolver,omitempty"`
}

type HTTPMixedInboundOptions struct {
	ListenOptions
	Users          []auth.User           `json:"users,omitempty"`
	DomainResolver *DomainResolveOptions `json:"domain_resolver,omitempty"`
	SetSystemProxy bool                  `json:"set_system_proxy,omitempty"`
	InboundTLSOptionsContainer
}

type _HTTPInboundOptions struct {
	ListenOptions
	Users []auth.User `json:"users,omitempty"`
	// Masquerade handles unauthenticated HTTP/2 and HTTP/3 requests.  It uses
	// the same schema and semantics as the Hysteria2 masquerade option.
	Masquerade     *Hysteria2Masquerade    `json:"masquerade,omitempty"`
	DomainResolver *DomainResolveOptions   `json:"domain_resolver,omitempty"`
	SetSystemProxy bool                    `json:"set_system_proxy,omitempty"`
	Version        badoption.Listable[int] `json:"version,omitempty" enum:"1,2,3"`
	// ServerProfile applies a named set of resource defaults. Explicit fields
	// always win. Unset means upstream defaults.
	ServerProfile string `json:"server_profile,omitempty"`
	// MaxHeaderBytes overrides the request header limit. Unset means upstream.
	MaxHeaderBytes int `json:"max_header_bytes,omitempty"`
	// BBRProfile selects the HTTP/3 server congestion control profile. It
	// accepts only the profiles provided by congestion_meta2. Unset keeps the
	// current standard behaviour.
	BBRProfile string `json:"bbr_profile,omitempty" enum:"conservative,standard,aggressive"`
	// UnauthenticatedLimits bounds pre-authentication traffic on this inbound.
	// Authenticated proxy traffic is never affected.
	UnauthenticatedLimits *UnauthenticatedLimitsOptions `json:"unauthenticated_limits,omitempty"`
	InboundTLSOptionsContainer
	HTTP2Options HTTP2Options `json:"-"`
	HTTP3Options QUICOptions  `json:"-"`
}

type HTTPInboundOptions _HTTPInboundOptions

// ServerResourceOptions is the resolved form of server_profile plus the
// explicitly configured per-inbound resource fields.
type ServerResourceOptions struct {
	Profile        HTTPServerProfile
	ProfileApplied bool
	MaxHeaderBytes int
}

// ResolveServerResources applies the named profile to the version-specific
// option sets, leaving every explicitly configured field untouched.
func (o HTTPInboundOptions) ResolveServerResources() (ServerResourceOptions, error) {
	profile, applied, err := NewHTTPServerProfile(o.ServerProfile)
	if err != nil {
		return ServerResourceOptions{}, err
	}
	err = ValidateBBRProfile(o.BBRProfile)
	if err != nil {
		return ServerResourceOptions{}, err
	}
	if applied {
		profile.ApplyToHTTP2(&o.HTTP2Options)
		profile.ApplyToQUIC(&o.HTTP3Options)
	}
	o.HTTP3Options.BBRProfile = ServerBBRProfile{Name: o.BBRProfile}
	return ServerResourceOptions{
		Profile:        profile,
		ProfileApplied: applied,
		MaxHeaderBytes: o.MaxHeaderBytes,
	}, nil
}

func (o HTTPInboundOptions) Versions() []int {
	if len(o.Version) > 0 {
		return o.Version
	}
	return []int{1, 2}
}

func (o HTTPInboundOptions) MarshalJSON() ([]byte, error) {
	return badjson.MarshallObjects(_HTTPInboundOptions(o), httpVersionsVariant(o.Versions(), o.HTTP2Options, o.HTTP3Options))
}

func (o *HTTPInboundOptions) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	err := json.UnmarshalContext(ctx, content, (*_HTTPInboundOptions)(o))
	if err != nil {
		return err
	}
	return unmarshalHTTPVersionsOptions(ctx, content, (*_HTTPInboundOptions)(o), o.Versions(), &o.HTTP2Options, &o.HTTP3Options)
}

func (o HTTPInboundOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	node := schema.StrictObject()
	err := builder.FlattenStruct(node, reflect.TypeFor[HTTPInboundOptions]())
	if err != nil {
		return nil, err
	}
	err = builder.FlattenStruct(node, reflect.TypeFor[QUICOptions]())
	if err != nil {
		return nil, err
	}
	return node, nil
}

type SOCKSOutboundOptions struct {
	DialerOptions
	ServerOptions
	Version    string             `json:"version,omitempty" enum:"4,4a,5"`
	Username   string             `json:"username,omitempty"`
	Password   string             `json:"password,omitempty"`
	Network    NetworkList        `json:"network,omitempty"`
	UDPOverTCP *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
}

type _HTTPOutboundOptions struct {
	DialerOptions
	ServerOptions
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	OutboundTLSOptionsContainer
	Path                   string               `json:"path,omitempty"`
	Headers                badoption.HTTPHeader `json:"headers,omitempty"`
	Version                int                  `json:"version,omitempty" enum:"0,1,2,3"`
	DisableVersionFallback bool                 `json:"disable_version_fallback,omitempty"`
	HTTP2Options           HTTP2Options         `json:"-"`
	HTTP3Options           QUICOptions          `json:"-"`
}

type HTTPOutboundOptions _HTTPOutboundOptions

func (o HTTPOutboundOptions) MarshalJSON() ([]byte, error) {
	return badjson.MarshallObjects(_HTTPOutboundOptions(o), httpVersionVariant(o.Version, o.HTTP2Options, o.HTTP3Options))
}

func (o *HTTPOutboundOptions) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	err := json.UnmarshalContext(ctx, content, (*_HTTPOutboundOptions)(o))
	if err != nil {
		return err
	}
	err = unmarshalHTTPVersionOptions(ctx, content, (*_HTTPOutboundOptions)(o), o.Version, &o.HTTP2Options, &o.HTTP3Options)
	if err != nil {
		return err
	}
	// Validate the HTTP/3 client options at decode time so that `sing-box check`
	// rejects a bad pool size or strategy instead of failing later when the
	// transport is built.
	return o.HTTP3Options.ValidateClientOptions()
}

func (o HTTPOutboundOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	node := schema.StrictObject()
	err := builder.FlattenStruct(node, reflect.TypeFor[HTTPOutboundOptions]())
	if err != nil {
		return nil, err
	}
	err = builder.FlattenStruct(node, reflect.TypeFor[QUICOptions]())
	if err != nil {
		return nil, err
	}
	return node, nil
}
