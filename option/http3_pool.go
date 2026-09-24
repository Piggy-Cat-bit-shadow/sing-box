package option

import (
	"encoding/json"

	E "github.com/sagernet/sing/common/exceptions"
)

// HTTP3ConnectionPoolOptions keeps more than one independent HTTP/3 transport
// per client, so that concurrent requests can spread over multiple QUIC
// connections instead of sharing a single one.
//
// Size 1 (and an absent object) is exactly the upstream behaviour: one transport.
type HTTP3ConnectionPoolOptions struct {
	Size int `json:"size,omitempty"`
	// Strategy is retained for configuration compatibility, but it does NOT
	// select a scheduler. It is validated (`round_robin` is the only accepted
	// value) and then never consulted, because the two consumers schedule their
	// own members:
	//
	//   - the generic HTTP client (common/httpclient) rotates members with an
	//     atomic round-robin counter;
	//   - the MASQUE tunnel client (transport/http) picks the healthy
	//     least-active slot, breaking ties by round-robin.
	//
	// The MASQUE scheduler is the one that matters here: the pool exists to spread
	// proxy tunnels, and least-active is what keeps one saturated QUIC connection
	// from being chosen while another sits idle.
	//
	// It is deliberately NOT removed: dropping the field would make existing
	// configurations fail to decode. Do not document it as a user-selectable
	// scheduler, and do not add a second accepted value without also making a
	// consumer honour it.
	Strategy string `json:"strategy,omitempty" enum:"round_robin"`
}

const (
	// HTTP3PoolStrategyRoundRobin is the only accepted value for Strategy. It is
	// accepted for compatibility; see the field comment for what actually
	// schedules pool members.
	HTTP3PoolStrategyRoundRobin = "round_robin"

	// MaxHTTP3ConnectionPoolSize bounds the pool so that a configuration
	// mistake cannot spawn an unbounded number of QUIC connections.
	MaxHTTP3ConnectionPoolSize = 8
)

// Build resolves the pool size. A nil receiver or an unset size yields 1, which
// callers treat as "upstream behaviour, no pool".
func (o *HTTP3ConnectionPoolOptions) Build() (int, error) {
	if o == nil {
		return 1, nil
	}
	size := o.Size
	if size == 0 {
		size = 1
	}
	if size < 1 {
		return 0, E.New("invalid http3_connection_pool.size: ", size)
	}
	if size > MaxHTTP3ConnectionPoolSize {
		return 0, E.New("http3_connection_pool.size must not exceed ", MaxHTTP3ConnectionPoolSize, ", got ", size)
	}
	switch o.Strategy {
	case "", HTTP3PoolStrategyRoundRobin:
	default:
		return 0, E.New("unsupported http3_connection_pool.strategy: ", o.Strategy)
	}
	return size, nil
}

// ValidateClientOptions rejects invalid HTTP/3 client options at configuration
// decode time, so `sing-box check` fails early rather than when the transport is
// first constructed.
func (o QUICOptions) ValidateClientOptions() error {
	_, err := o.HTTP3ConnectionPool.Build()
	return err
}

// clientOnlyHTTP3Fields are HTTP/3 settings that only an HTTP client can honour.
// The http inbound shares QUICOptions with the outbound, so these have to be
// rejected explicitly rather than being silently ignored.
var clientOnlyHTTP3Fields = []string{"http3_fallback", "http3_connection_pool"}

// rejectClientOnlyHTTP3Options fails decoding when a server-side option set
// contains a client-only field.
//
// Silently accepting them would let a config look correct while having no effect,
// which is the same class of problem as the server_profile bug this fork already
// fixed once.
func rejectClientOnlyHTTP3Options(content []byte) error {
	if len(content) == 0 {
		return nil
	}
	var probe map[string]json.RawMessage
	err := json.Unmarshal(content, &probe)
	if err != nil {
		// Let the caller report its own decode error rather than masking it.
		return nil
	}
	for _, field := range clientOnlyHTTP3Fields {
		if _, present := probe[field]; present {
			return E.New(field, " is a client-only option and cannot be used on an inbound")
		}
	}
	return nil
}
