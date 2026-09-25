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
//
// What this profile does NOT do is as important as what it does. Measured against
// quic-go v0.61.0-sing-box-mod.7 (internal/protocol/params.go):
//
//	InitialStreamReceiveWindow      2 MiB
//	MaxStreamReceiveWindow          6 MiB
//	InitialConnectionReceiveWindow  10 MiB
//	MaxConnectionReceiveWindow      15 MiB
//	KeepAlivePeriod                 0 (disabled)
//
// An earlier revision of this profile set stream_receive_window to 4 MiB and
// connection_receive_window to 16 MiB. Both of those values are applied by
// NewQUICConfig to BOTH the initial and the maximum window, so the profile
// RAISED the initial windows above the library defaults (2 MiB -> 4 MiB and
// 10 MiB -> 16 MiB) and enabled a 30s keep-alive that the default does not have.
// That is the opposite of a memory-conservative profile and it was never
// measured, so it has been removed.
//
// The current schema cannot express initial and maximum windows separately, so
// the honest choice is to leave the receive windows entirely alone rather than
// raise the initial window as a side effect of lowering the maximum. Stream
// limits, the header cap and the idle timeout are the parts that are
// unambiguously binding, and those are what this profile sets.
var httpserverProfiles = map[string]HTTPServerProfile{
	HTTPServerProfileNameJiejieBalanced1G: {
		MaxHeaderBytes:       64 * kibibyte,
		MaxConcurrentStreams: 256,
		IdleTimeout:          60 * time.Second,
		// KeepAlivePeriod is deliberately zero: it inherits the quic-go default of
		// "disabled". Actively pinging idle QUIC connections keeps them (and their
		// state) alive on a 1 GiB host, which is the opposite of the intent.
		// Receive windows are deliberately NOT set: see the comment above.
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

// BBRProfileValue resolves the configured name.
//
// An unset name stays EMPTY, and the HTTP/3 listener reads that as "leave
// quic-go's congestion control in place". It previously returned
// BBRProfileStandard, which made BBR the protocol default rather than an explicit
// choice - and neither quic-go/masque-go nor quic-go/connect-ip-go sets a
// congestion control, so the library default is what the references get.
//
// The returned value is always either empty or a name the dependency defines, so
// a caller can validate it without a second compatibility check.
func (o ServerBBRProfile) BBRProfileValue() string {
	return o.Name
}

// ApplyToHTTP2WithPresence fills only the fields the user did NOT write.
//
// The presence set matters because these fields are plain values, not pointers:
// an explicit `keep_alive_period: 0` and an omitted key both decode to 0. The
// profile must not overwrite an explicit zero, because "explicit fields always
// win" is the contract this fork documents. `keep_alive_period: 0` in particular
// means "disable keep-alive", which is the opposite of what the profile sets.
func (p HTTPServerProfile) ApplyToHTTP2WithPresence(options *HTTP2Options, present ResourceFieldPresence) {
	if !present.MaxConcurrentStreams && p.MaxConcurrentStreams > 0 && options.MaxConcurrentStreams == 0 {
		options.MaxConcurrentStreams = p.MaxConcurrentStreams
	}
	if !present.StreamReceiveWindow && p.StreamReceiveWindow > 0 && options.StreamReceiveWindow == nil {
		options.StreamReceiveWindow = memoryBytesValue(p.StreamReceiveWindow)
	}
	if !present.ConnectionReceiveWindow && p.ConnectionReceiveWindow > 0 && options.ConnectionReceiveWindow == nil {
		options.ConnectionReceiveWindow = memoryBytesValue(p.ConnectionReceiveWindow)
	}
	if !present.IdleTimeout && p.IdleTimeout > 0 && options.IdleTimeout == 0 {
		options.IdleTimeout = badoption.Duration(p.IdleTimeout)
	}
	if !present.KeepAlivePeriod && p.KeepAlivePeriod > 0 && options.KeepAlivePeriod == 0 {
		options.KeepAlivePeriod = badoption.Duration(p.KeepAlivePeriod)
	}
}

// ApplyToQUICWithPresence is the QUIC form of ApplyToHTTP2WithPresence.
func (p HTTPServerProfile) ApplyToQUICWithPresence(options *QUICOptions, present ResourceFieldPresence) {
	p.ApplyToHTTP2WithPresence(&options.HTTP2Options, present)
}
