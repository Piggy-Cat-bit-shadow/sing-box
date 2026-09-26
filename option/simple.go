package option

import (
	"context"
	"math"
	"reflect"
	"time"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
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
	// Masquerade handles unauthenticated HTTP/2 and HTTP/3 requests. It uses
	// the same schema and semantics as the Hysteria2 masquerade option.
	Masquerade     *Hysteria2Masquerade    `json:"masquerade,omitempty"`
	DomainResolver *DomainResolveOptions   `json:"domain_resolver,omitempty"`
	SetSystemProxy bool                    `json:"set_system_proxy,omitempty"`
	Version        badoption.Listable[int] `json:"version,omitempty" enum:"1,2,3"`
	// MaxHeaderBytes overrides the request header limit. Unset means upstream.
	MaxHeaderBytes int `json:"max_header_bytes,omitempty"`
	// BBRProfile selects the HTTP/3 server congestion control profile.
	//
	// An UNSET value means "leave quic-go's congestion control unchanged", which is the
	// library default and what both reference implementations get. It does NOT mean "use
	// the standard BBR profile": resolving it that way would make BBR a protocol default
	// rather than an explicit operator choice.
	BBRProfile string `json:"bbr_profile,omitempty" enum:"conservative,standard,aggressive"`
	// UnauthenticatedLimits bounds pre-authentication traffic on this inbound.
	// Authenticated proxy traffic is never affected.
	UnauthenticatedLimits *UnauthenticatedLimitsOptions `json:"unauthenticated_limits,omitempty"`
	InboundTLSOptionsContainer
	HTTP2Options HTTP2Options `json:"-"`
	HTTP3Options QUICOptions  `json:"-"`
}

type HTTPInboundOptions _HTTPInboundOptions

// ServerResourceOptions carries the EFFECTIVE option sets an inbound must use.
//
// It returns the resolved values rather than mutating the options in place. An
// earlier revision resolved values into a copy inside ResolveServerResources and
// returned only the header limit, so the caller kept using the original
// HTTP2Options/HTTP3Options and the resolved BBR profile never reached the server.
// Returning the effective values makes that mistake impossible to repeat: the
// caller has nothing else to use.
type ServerResourceOptions struct {
	// HTTP2Options is the effective HTTP/2 option set.
	HTTP2Options HTTP2Options
	// HTTP3Options is the effective QUIC option set, including the resolved
	// BBRProfile that the HTTP/3 listener must apply.
	HTTP3Options QUICOptions
	// MaxHeaderBytes is the effective request header limit, falling back to the
	// upstream default when unset. It is never zero.
	MaxHeaderBytes int
}

// ResolveServerResources returns the effective option sets for this inbound.
//
// Every resource field is configured explicitly per inbound; there is no named
// profile to layer on top. The removal of `server_profile` is deliberate: it only
// ever had one entry, so a bundle indirection sat between the operator and the
// values for no benefit. The removed profile also carried a third constructor and
// a presence-tracking JSON probe whose sole purpose was to let that one bundle
// distinguish an absent field from an explicit zero.
func (o HTTPInboundOptions) ResolveServerResources() (ServerResourceOptions, error) {
	err := ValidateBBRProfile(o.BBRProfile)
	if err != nil {
		return ServerResourceOptions{}, err
	}

	// Work on copies and hand the copies back, so no caller can accidentally
	// keep using unresolved options.
	http2Options := o.HTTP2Options
	http3Options := o.HTTP3Options
	// An unset bbr_profile stays EMPTY, which the HTTP/3 listener reads as "leave
	// quic-go's congestion control in place". It must not resolve to a concrete
	// profile here: that would make BBR a protocol default rather than an explicit
	// operator choice, and neither reference implementation sets one.
	http3Options.BBRProfile = ServerBBRProfile{Name: o.BBRProfile}

	// Validate the numeric bounds BEFORE resolving maxHeaderBytes, so an invalid
	// explicit value is reported instead of being silently replaced.
	if err = validateHTTPResourceBounds(http2Options, http3Options); err != nil {
		return ServerResourceOptions{}, err
	}

	maxHeaderBytes := o.MaxHeaderBytes
	if maxHeaderBytes == 0 {
		// Unset means "use the upstream default".
		maxHeaderBytes = UpstreamMaxHeaderBytes
	} else if maxHeaderBytes < 0 {
		// An explicit negative value is a configuration error, not a request for
		// the default. The previous behaviour replaced it with
		// UpstreamMaxHeaderBytes, which contradicted the documented contract that
		// an explicit value wins: the operator wrote something invalid, got no
		// error, and silently received a limit they did not ask for. Naming the
		// mistake is better than guessing at intent.
		return ServerResourceOptions{}, E.New("max_header_bytes must be positive, got ",
			o.MaxHeaderBytes)
	}
	if maxHeaderBytes <= 0 {
		return ServerResourceOptions{}, E.New("resolved max_header_bytes is not positive: ",
			maxHeaderBytes)
	}

	return ServerResourceOptions{
		HTTP2Options:   http2Options,
		HTTP3Options:   http3Options,
		MaxHeaderBytes: maxHeaderBytes,
	}, nil
}

// validateHTTPResourceBounds rejects option values that cannot be represented by
// the types they are later narrowed to.
//
// Every field here is converted with a cast somewhere downstream, and an
// out-of-range value does not fail loudly at that point - it wraps, clamps, or
// becomes a nonsensical-but-plausible number:
//
//	MaxConcurrentStreams            -> uint32(max(v, 0)): negative silently
//	                                   became 0; > MaxUint32 wrapped
//	StreamReceiveWindow             -> int32(min(v, MaxInt32)): silently clamped
//	ConnectionReceiveWindow         -> int32(min(v, MaxInt32)): silently clamped
//	InitialPacketSize               -> uint16(v): > MaxUint16 WRAPPED
//
// The receive windows need special care because MemoryBytes.UnmarshalJSON accepts
// a negative integer and stores it as uint64:
//
//	-1  ->  Value() == 18446744073709551615
//
// which the downstream min() then turns into ~2 GiB. A negative window must be a
// configuration error, not a two-gigabyte allocation.
//
// Zero keeps its documented meaning of "unset, use the default" everywhere.
func validateHTTPResourceBounds(http2Options HTTP2Options, http3Options QUICOptions) error {
	if http2Options.MaxConcurrentStreams < 0 {
		return E.New("max_concurrent_streams must not be negative, got ",
			http2Options.MaxConcurrentStreams)
	}
	if uint64(http2Options.MaxConcurrentStreams) > math.MaxUint32 {
		return E.New("max_concurrent_streams must not exceed ", uint64(math.MaxUint32),
			", got ", http2Options.MaxConcurrentStreams,
			"; a larger value would wrap when narrowed to the HTTP/2 stream limit")
	}

	for _, window := range []struct {
		name  string
		value *byteformats.MemoryBytes
	}{
		{"stream_receive_window", http2Options.StreamReceiveWindow},
		{"connection_receive_window", http2Options.ConnectionReceiveWindow},
	} {
		if window.value == nil {
			continue
		}
		// A NEGATIVE value cannot be detected as negative here, and the reason is
		// worth stating because it explains why the bound below is the real
		// defence. MemoryBytes.UnmarshalJSON parses a bare number into an int64
		// and then stores it as uint64:
		//
		//	var intValue int64
		//	json.Unmarshal(bytes, &intValue)
		//	b.value = uint64(intValue)
		//
		// so "-1" survives parsing as 18446744073709551615 and the sign is gone
		// before any sing-box code sees it. Value() therefore returns that huge
		// number, and the old downstream int32(min(v, MaxInt32)) silently turned
		// it into about 2 GiB.
		//
		// The unsigned maximum is caught by the bound below, which rejects any
		// value above MaxInt32 - including the one a negative produces. The error
		// text names both possibilities so the cause is diagnosable.
		if window.value.Value() > math.MaxInt32 {
			return E.New(window.name, " must not exceed ", int64(math.MaxInt32),
				", got ", window.value.Value(),
				"; a larger value would be clamped when narrowed to the HTTP/2 ",
				"window. Note that a negative value parses to a huge unsigned ",
				"number, so this bound also rejects it")
		}
	}

	// InitialPacketSize is narrowed to uint16, and quic-go rejects values below
	// 1200 at the transport layer. Anything above MaxUint16 would wrap to a small
	// number and silently produce a packet size nobody asked for.
	if http3Options.InitialPacketSize != 0 {
		if http3Options.InitialPacketSize < 0 {
			return E.New("initial_packet_size must not be negative, got ",
				http3Options.InitialPacketSize)
		}
		if http3Options.InitialPacketSize > math.MaxUint16 {
			return E.New("initial_packet_size must not exceed ", uint64(math.MaxUint16),
				", got ", http3Options.InitialPacketSize,
				"; a larger value would wrap when narrowed to the QUIC packet size")
		}
	}

	// Durations: an explicit negative is a mistake rather than a request for the
	// default. Zero keeps its meaning of "unset".
	for _, duration := range []struct {
		name  string
		value badoption.Duration
	}{
		{"idle_timeout", http2Options.IdleTimeout},
		{"keep_alive_period", http2Options.KeepAlivePeriod},
	} {
		if duration.value < 0 {
			return E.New(duration.name, " must not be negative, got ",
				time.Duration(duration.value))
		}
	}

	return nil
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
	return unmarshalHTTPVersionOptions(ctx, content, (*_HTTPOutboundOptions)(o), o.Version, &o.HTTP2Options, &o.HTTP3Options)
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
