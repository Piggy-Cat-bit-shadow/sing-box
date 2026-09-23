package option

import (
	"strconv"
	"time"

	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// HTTPServerProfileNameJiejieBalanced1G is the recommended profile for a
// ~1 GiB RAM server that terminates public HTTP/3.
const HTTPServerProfileNameJiejieBalanced1G = "jiejie-balanced-1g"

// UpstreamMaxHeaderBytes is the request header limit upstream sing-box uses when
// nothing overrides it. transport/http keeps its own copy for the HTTP/2 server;
// this one exists so option resolution can report the effective value without
// importing the transport layer.
const UpstreamMaxHeaderBytes = 1 << 20

// HTTPServerProfile holds the default values a named profile applies. Every
// field is a default only: an explicitly configured inbound field always wins,
// and an unselected profile is a zero value that changes nothing.
type HTTPServerProfile struct {
	MaxHeaderBytes          int64
	MaxConcurrentStreams    int
	StreamReceiveWindow     int64
	ConnectionReceiveWindow int64
	IdleTimeout             time.Duration
	KeepAlivePeriod         time.Duration
}

const (
	mebibyte = 1 << 20
	kibibyte = 1 << 10
)

// httpserverProfiles is the single place where profile numbers live. They are
// deliberately conservative and are never used unless a profile is selected.
var httpserverProfiles = map[string]HTTPServerProfile{
	HTTPServerProfileNameJiejieBalanced1G: {
		MaxHeaderBytes:          64 * kibibyte,
		MaxConcurrentStreams:    256,
		StreamReceiveWindow:     4 * mebibyte,
		ConnectionReceiveWindow: 16 * mebibyte,
		IdleTimeout:             60 * time.Second,
		KeepAlivePeriod:         30 * time.Second,
	},
}

// NewHTTPServerProfile resolves a profile name. An empty name yields a zero
// profile and reports false, meaning "no profile, keep upstream defaults".
func NewHTTPServerProfile(name string) (HTTPServerProfile, bool, error) {
	if name == "" {
		return HTTPServerProfile{}, false, nil
	}
	profile, loaded := httpserverProfiles[name]
	if !loaded {
		return HTTPServerProfile{}, false, E.New("unknown server_profile: ", name, " (supported: ", HTTPServerProfileNameJiejieBalanced1G, ")")
	}
	return profile, true, nil
}

// ApplyToHTTP2 fills only the fields the user left unset. A field that is
// present in the configuration always wins over the profile value.
func (p HTTPServerProfile) ApplyToHTTP2(options *HTTP2Options) {
	if p.MaxConcurrentStreams > 0 && options.MaxConcurrentStreams == 0 {
		options.MaxConcurrentStreams = p.MaxConcurrentStreams
	}
	if p.StreamReceiveWindow > 0 && options.StreamReceiveWindow == nil {
		options.StreamReceiveWindow = memoryBytesValue(p.StreamReceiveWindow)
	}
	if p.ConnectionReceiveWindow > 0 && options.ConnectionReceiveWindow == nil {
		options.ConnectionReceiveWindow = memoryBytesValue(p.ConnectionReceiveWindow)
	}
	if p.IdleTimeout > 0 && options.IdleTimeout == 0 {
		options.IdleTimeout = badoption.Duration(p.IdleTimeout)
	}
	if p.KeepAlivePeriod > 0 && options.KeepAlivePeriod == 0 {
		options.KeepAlivePeriod = badoption.Duration(p.KeepAlivePeriod)
	}
}

// memoryBytesValue builds a MemoryBytes from a byte count. MemoryBytes keeps
// its value unexported, so the supported construction path is its JSON
// decoder, which accepts a plain integer number of bytes.
func memoryBytesValue(bytes int64) *byteformats.MemoryBytes {
	value := byteformats.MemoryBytes{}
	if err := value.UnmarshalJSON([]byte(strconv.FormatInt(bytes, 10))); err != nil {
		// The profile constants are integers, so this cannot happen; return
		// nil rather than a bogus window if it ever does.
		return nil
	}
	return &value
}

// ApplyToQUIC fills unset fields of the QUIC options with profile values.
func (p HTTPServerProfile) ApplyToQUIC(options *QUICOptions) {
	p.ApplyToHTTP2(&options.HTTP2Options)
}

// MaxHeaderBytesValue returns the profile header limit, falling back to the
// upstream default when the profile does not set one.
func (p HTTPServerProfile) MaxHeaderBytesValue(upstreamDefault int) int {
	if p.MaxHeaderBytes <= 0 {
		return upstreamDefault
	}
	return int(p.MaxHeaderBytes)
}

// BBRProfile names accepted by the HTTP/3 inbound `bbr_profile` option. They
// mirror exactly the profiles exported by
// github.com/sagernet/sing-quic/congestion_meta2; no other value is accepted,
// and this fork never invents a profile the dependency does not define.
const (
	BBRProfileConservative = "conservative"
	BBRProfileStandard     = "standard"
	BBRProfileAggressive   = "aggressive"
)

// BBRProfileNames lists the accepted bbr_profile values.
func BBRProfileNames() []string {
	return []string{BBRProfileConservative, BBRProfileStandard, BBRProfileAggressive}
}

// ValidateBBRProfile rejects unknown profile names. An empty name is valid and
// means "keep the current standard profile".
func ValidateBBRProfile(name string) error {
	switch name {
	case "", BBRProfileConservative, BBRProfileStandard, BBRProfileAggressive:
		return nil
	default:
		return E.New("unsupported bbr_profile: ", name, " (supported: conservative, standard, aggressive)")
	}
}

// ServerBBRProfile carries the resolved HTTP/3 server congestion profile from
// the inbound to the HTTP/3 listener without changing the shared
// ConfigureHTTP3ListenerFunc signature.
type ServerBBRProfile struct {
	Name string
}

// BBRProfileValue resolves the configured name, defaulting to standard. It
// never returns a name the dependency does not define.
func (o ServerBBRProfile) BBRProfileValue() string {
	if o.Name == "" {
		return BBRProfileStandard
	}
	return o.Name
}
