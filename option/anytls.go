package option

import "github.com/sagernet/sing/common/json/badoption"

type AnyTLSInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	Users         []AnyTLSUser               `json:"users,omitempty"`
	PaddingScheme badoption.Listable[string] `json:"padding_scheme,omitempty"`
	Fallback      *AnyTLSFallbackOptions     `json:"fallback,omitempty"`
}

// AnyTLSFallbackOptions is the plaintext TCP backend used after AnyTLS
// authentication fails. TLS, when configured, has already terminated.
type AnyTLSFallbackOptions struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}

type AnyTLSUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

type AnyTLSOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Password                 string             `json:"password,omitempty"`
	IdleSessionCheckInterval badoption.Duration `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       badoption.Duration `json:"idle_session_timeout,omitempty"`
	MinIdleSession           int                `json:"min_idle_session,omitempty"`
	ClientMetadata           string             `json:"client_metadata,omitempty"`
}
