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
	// Present records which resource fields the user actually wrote, so a profile
	// can distinguish "absent" from "explicitly zero". Without it,
	// `keep_alive_period: 0` is indistinguishable from omitting the key and the
	// profile would silently overwrite an explicit zero.
	Present ResourceFieldPresence `json:"-"`
}

// ResourceFieldPresence records the resource fields that appeared in the config.
type ResourceFieldPresence struct {
	MaxConcurrentStreams    bool
	IdleTimeout             bool
	KeepAlivePeriod         bool
	StreamReceiveWindow     bool
	ConnectionReceiveWindow bool
	MaxHeaderBytes          bool
}

// resourceFieldNames maps the JSON key to the presence flag it sets.
var resourceFieldNames = map[string]func(*ResourceFieldPresence){
	"max_concurrent_streams":    func(p *ResourceFieldPresence) { p.MaxConcurrentStreams = true },
	"idle_timeout":              func(p *ResourceFieldPresence) { p.IdleTimeout = true },
	"keep_alive_period":         func(p *ResourceFieldPresence) { p.KeepAlivePeriod = true },
	"stream_receive_window":     func(p *ResourceFieldPresence) { p.StreamReceiveWindow = true },
	"connection_receive_window": func(p *ResourceFieldPresence) { p.ConnectionReceiveWindow = true },
	"max_header_bytes":          func(p *ResourceFieldPresence) { p.MaxHeaderBytes = true },
}

// recordPresence inspects the raw JSON for the resource keys the user supplied.
func recordPresence(content []byte) ResourceFieldPresence {
	var presence ResourceFieldPresence
	if len(content) == 0 {
		return presence
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(content, &probe); err != nil {
		return presence
	}
	for key, set := range resourceFieldNames {
		if _, present := probe[key]; present {
			set(&presence)
		}
	}
	return presence
}

type HTTPInboundOptions _HTTPInboundOptions

// ServerResourceOptions carries the EFFECTIVE option sets an inbound must use.
//
// It returns the resolved values rather than mutating the options in place. An
// earlier revision applied the profile to a copy inside
// ResolveServerResources and returned only the header limit, so the caller kept
// using the original HTTP2Options/HTTP3Options and the profile, the receive
// windows and bbr_profile never reached the server. Returning the effective
// values makes that mistake impossible to repeat: the caller has nothing else to
// use.
type ServerResourceOptions struct {
	Profile        HTTPServerProfile
	ProfileApplied bool
	// HTTP2Options is the effective HTTP/2 option set: the user's values with
	// any unset field filled from the profile.
	HTTP2Options HTTP2Options
	// HTTP3Options is the effective QUIC option set, including the resolved
	// BBRProfile that the HTTP/3 listener must apply.
	HTTP3Options QUICOptions
	// MaxHeaderBytes is the effective request header limit, already falling back
	// to the profile and then to the upstream default. It is never zero.
	MaxHeaderBytes int
}

// ResolveServerResources returns the effective option sets for this inbound.
//
// The profile fills only fields the user left unset, so an explicit value always
// wins. With no profile selected, nothing is changed and the result equals the
// inbound's own options.
func (o HTTPInboundOptions) ResolveServerResources() (ServerResourceOptions, error) {
	profile, applied, err := NewHTTPServerProfile(o.ServerProfile)
	if err != nil {
		return ServerResourceOptions{}, err
	}
	err = ValidateBBRProfile(o.BBRProfile)
	if err != nil {
		return ServerResourceOptions{}, err
	}

	// Work on copies and hand the copies back, so no caller can accidentally
	// keep using unresolved options.
	http2Options := o.HTTP2Options
	http3Options := o.HTTP3Options
	if applied {
		// The presence set lets the profile distinguish an absent field from an
		// explicit zero. An explicitly configured value always wins, including
		// `keep_alive_period: 0` and `max_concurrent_streams: 0`.
		profile.ApplyToHTTP2WithPresence(&http2Options, o.Present)
		profile.ApplyToQUICWithPresence(&http3Options, o.Present)
	}
	// The BBR profile applies to the HTTP/3 server regardless of whether a
	// resource profile was selected; an unset value resolves to standard, which
	// is the previous hardcoded behaviour.
	http3Options.BBRProfile = ServerBBRProfile{Name: o.BBRProfile}

	// Validate the numeric bounds BEFORE resolving maxHeaderBytes, so an invalid
	// explicit value is reported instead of being silently replaced.
	if err = validateHTTPResourceBounds(http2Options, http3Options); err != nil {
		return ServerResourceOptions{}, err
	}

	maxHeaderBytes := o.MaxHeaderBytes
	if !o.Present.MaxHeaderBytes {
		// Only an ABSENT max_header_bytes falls back to the profile.
		maxHeaderBytes = profile.MaxHeaderBytesValue(UpstreamMaxHeaderBytes)
	} else if o.MaxHeaderBytes <= 0 {
		// An explicit non-positive value is a configuration error, not a request
		// for the default.
		//
		// The previous behaviour replaced it with UpstreamMaxHeaderBytes, which
		// contradicted the documented contract that an explicit value always wins:
		// the operator wrote something invalid, got no error, and silently
		// received a limit they did not ask for. Naming the mistake is better than
		// guessing at intent.
		return ServerResourceOptions{}, E.New("max_header_bytes must be positive, got ",
			o.MaxHeaderBytes)
	}
	if maxHeaderBytes <= 0 {
		// Reachable only when the profile itself supplied a non-positive value,
		// which is a bug in the profile rather than in the user's configuration.
		return ServerResourceOptions{}, E.New("resolved max_header_bytes is not positive: ",
			maxHeaderBytes)
	}

	return ServerResourceOptions{
		Profile:        profile,
		ProfileApplied: applied,
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
	// Record which resource fields the user wrote BEFORE unmarshalling the
	// version-specific options, so the profile can tell "absent" from
	// "explicitly zero".
	o.Present = recordPresence(content)
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
	return nil
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
