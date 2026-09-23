//go:build with_quic

package http

import (
	"net"
	"net/http"

	"github.com/sagernet/quic-go/http3"
	M "github.com/sagernet/sing/common/metadata"
)

// http3RemoteAddrKey is the context key quic-go's HTTP/3 server uses to expose
// the peer address. It is the exported http3 value, kept behind this
// build-tagged indirection so the shared HTTP/2 handler does not have to import
// quic-go.
var http3RemoteAddrKey any = http3.RemoteAddrContextKey

// http3RemoteAddr extracts the peer address from an HTTP/3 request context.
// quic-go does not populate http.Request.RemoteAddr for HTTP/3, so without this
// any per-source-IP logic would silently see an empty address on the public
// UDP/443 path.
func http3RemoteAddr(request *http.Request) (M.Socksaddr, bool) {
	if request == nil || http3RemoteAddrKey == nil {
		return M.Socksaddr{}, false
	}
	value := request.Context().Value(http3RemoteAddrKey)
	if value == nil {
		return M.Socksaddr{}, false
	}
	address, isAddress := value.(net.Addr)
	if !isAddress {
		return M.Socksaddr{}, false
	}
	source := M.SocksaddrFromNet(address)
	if !source.IsValid() {
		return M.Socksaddr{}, false
	}
	return source, true
}
