//go:build !with_quic

package http

import (
	"context"
	"net/http"

	M "github.com/sagernet/sing/common/metadata"
)

// http3RemoteAddr is a no-op without the with_quic build tag: no HTTP/3
// listener can be created in that build.
func http3RemoteAddr(request *http.Request) (M.Socksaddr, bool) {
	return M.Socksaddr{}, false
}

// HTTP3CandidateDialer reports that no HTTP/3 candidate primitive exists without the with_quic
// build tag, so a caller falls back rather than fails.
func (c *Client) HTTP3CandidateDialer() any { return nil }

// HTTP3ConnectionState reports that no live HTTP/3 connection exists without the with_quic
// build tag, which is accurate: none can be created in that build.
func (c *Client) HTTP3ConnectionState() (string, bool) { return "", false }

// RoundTripExistingHTTP3 has no HTTP/3 connection to reuse without the with_quic build tag.
func (c *Client) RoundTripExistingHTTP3(ctx context.Context, request *http.Request) (*http.Response, error) {
	return nil, ErrHTTP3Unavailable
}
