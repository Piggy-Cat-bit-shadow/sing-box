//go:build !with_quic

package http

import (
	"net/http"

	M "github.com/sagernet/sing/common/metadata"
)

// http3RemoteAddr is a no-op without the with_quic build tag: no HTTP/3
// listener can be created in that build.
func http3RemoteAddr(request *http.Request) (M.Socksaddr, bool) {
	return M.Socksaddr{}, false
}
