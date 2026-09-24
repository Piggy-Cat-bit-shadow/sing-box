package option

import (
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"
)

type NaiveInboundOptions struct {
	ListenOptions
	Users                 []auth.User `json:"users,omitempty"`
	Network               NetworkList `json:"network,omitempty"`
	QUICCongestionControl string      `json:"quic_congestion_control,omitempty" enum:"bbr,cubic,reno"`
	// Masquerade handles requests that are NOT authenticated Naive proxy
	// requests -- ordinary browser traffic, probes, and proxy attempts with no
	// or wrong credentials. It uses the same schema and semantics as the
	// Hysteria2 and HTTP inbound masquerade, so a normal website can be served
	// on the same port as the proxy.
	//
	// Unset means the upstream behaviour: the request is rejected with a proxy
	// authentication challenge or a bad-request status.
	//
	// This is a WEB response only. It can never establish a proxy tunnel: the
	// tunnel path requires successful authentication first, and the masquerade
	// handler has no access to the proxy or UoT data paths.
	Masquerade *Hysteria2Masquerade `json:"masquerade,omitempty"`
	InboundTLSOptionsContainer
}

type NaiveOutboundOptions struct {
	DialerOptions
	ServerOptions
	Username                 string                   `json:"username,omitempty"`
	Password                 string                   `json:"password,omitempty"`
	InsecureConcurrency      int                      `json:"insecure_concurrency,omitempty"`
	ExtraHeaders             badoption.HTTPHeader     `json:"extra_headers,omitempty"`
	ReceiveWindow            *byteformats.MemoryBytes `json:"stream_receive_window,omitempty"`
	UDPOverTCP               *UDPOverTCPOptions       `json:"udp_over_tcp,omitempty"`
	QUIC                     bool                     `json:"quic,omitempty"`
	QUICCongestionControl    string                   `json:"quic_congestion_control,omitempty" enum:"bbr,bbr2,cubic,reno"`
	QUICSessionReceiveWindow *byteformats.MemoryBytes `json:"quic_session_receive_window,omitempty"`
	OutboundTLSOptionsContainer
}
