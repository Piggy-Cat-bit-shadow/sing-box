package option

import (
	E "github.com/sagernet/sing/common/exceptions"
)

// HTTP3ConnectionPoolOptions keeps more than one independent HTTP/3 transport
// per client, so that concurrent requests can spread over multiple QUIC
// connections instead of sharing a single one.
//
// Size 1 (and an absent object) is exactly the upstream behaviour: one transport.
type HTTP3ConnectionPoolOptions struct {
	Size     int    `json:"size,omitempty"`
	Strategy string `json:"strategy,omitempty" enum:"round_robin"`
}

const (
	// HTTP3PoolStrategyRoundRobin is the only strategy implemented by the
	// first version. It is deliberately simple: no adaptive scheduling.
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
