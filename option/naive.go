package option

import (
	"context"
	"reflect"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
)

type NaiveInboundOptions struct {
	ListenOptions
	Users                 []auth.User `json:"users,omitempty"`
	Network               NetworkList `json:"network,omitempty"`
	QUICCongestionControl string      `json:"quic_congestion_control,omitempty" enum:"bbr,cubic,reno"`
	// QUICDisablePathManager turns off QUIC connection migration.
	//
	// Unset (the default) leaves quic-go's default, which has the path manager
	// ENABLED. That is what the reference does: Caddy sets only Versions and
	// Tracer on its quic.Config, so an unset field is reference-like.
	//
	// Disabling migration is a legitimate production choice - a client that
	// changes network path reconnects instead of migrating - but it is a
	// BEHAVIOUR difference from the reference, so it must be opted into rather
	// than compiled into the protocol default.
	QUICDisablePathManager bool `json:"quic_disable_path_manager,omitempty"`
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
	// HTTP2Options bounds the HTTP/2 server this inbound runs. Every field is
	// optional; leaving them all unset keeps the upstream net/http and
	// x/net/http2 defaults, which is the previous behaviour.
	//
	// These exist because the Naive inbound previously ran a bare
	// `&http2.Server{}`: every flow-control window and the concurrent-stream
	// limit were upstream defaults that could not be tuned from configuration at
	// all. On a 1 GiB host that is worth being able to bound, and the same
	// vocabulary is already used by the HTTP inbound so there is nothing new to
	// learn.
	//
	// The receive windows are SERVER-side admission windows, not the client's:
	// they bound how much a peer may have in flight toward this server. Do not
	// copy a client's oversized stream_receive_window here.
	HTTP2Options HTTP2Options `json:"-"`
	InboundTLSOptionsContainer
}

// NaiveInboundOptions needs a custom unmarshaler for the same reason
// HTTPInboundOptions does: the HTTP/2 resource fields live on an embedded
// struct tagged `json:"-"`, so the default decoder would silently ignore them
// even though they are documented as top-level keys.
func (o *NaiveInboundOptions) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	err := json.UnmarshalContext(ctx, content, (*_NaiveInboundOptions)(o))
	if err != nil {
		return err
	}
	return badjson.UnmarshallExcludedContext(ctx, content, (*_NaiveInboundOptions)(o), &o.HTTP2Options)
}

func (o NaiveInboundOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	node := schema.StrictObject()
	err := builder.FlattenStruct(node, reflect.TypeFor[NaiveInboundOptions]())
	if err != nil {
		return nil, err
	}
	err = builder.FlattenStruct(node, reflect.TypeFor[HTTP2Options]())
	if err != nil {
		return nil, err
	}
	return node, nil
}

type _NaiveInboundOptions NaiveInboundOptions

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
