package badhttp

import (
	std_bufio "bufio"
	"net/http"
	"net/url"
	"strings"
	_ "unsafe"

	M "github.com/sagernet/sing/common/metadata"
)

//go:linkname ReadRequest net/http.readRequest
func ReadRequest(b *std_bufio.Reader) (req *http.Request, err error)

//go:linkname URLSetPath net/url.(*URL).setPath
func URLSetPath(u *url.URL, p string) error

//go:linkname ParseBasicAuth net/http.parseBasicAuth
func ParseBasicAuth(auth string) (username, password string, valid bool)

// SourceAddress returns the peer address of the request.
//
// It deliberately does NOT consult X-Forwarded-For. See PeerAddress.
func SourceAddress(request *http.Request) M.Socksaddr {
	return M.ParseSocksaddr(request.RemoteAddr).Unwrap()
}

// PeerAddress returns the transport-level peer of the request.
//
// This is the ONLY source address that can be trusted by default: it is derived
// from the connection itself and cannot be chosen by the client.
//
// X-Forwarded-For is NOT consulted. The header is trivially forged by any client
// that can reach the listener, and the value it feeds - metadata.Source - is used
// by source_ip_cidr route rules, the unauthenticated limiter, the logs and the
// audit trail. A client that could set it could therefore choose which source
// policy applies to it and which address appears in the logs.
//
// Neither deployment has anything to validate it against:
//
//   - the MASQUE HTTP/2 inbound sits behind Nginx Stream, which forwards at
//     layer 4 and does not add X-Forwarded-For;
//   - the MASQUE HTTP/3 inbound terminates QUIC directly on public UDP/443.
//
// If a real client address is ever needed, it must come from a layer-4 mechanism
// the front end emits deliberately (PROXY protocol), not from an HTTP header a
// client can write. No such mechanism exists in this repository today, so the
// peer address is used.
func PeerAddress(request *http.Request) M.Socksaddr {
	return M.ParseSocksaddr(request.RemoteAddr).Unwrap()
}

// ForwardedSource is retained for callers that have ALREADY established a trusted
// forwarding relationship and pass the peer as `source`.
//
// It is NOT safe to call with an untrusted request: the returned address comes
// from a client-controlled header. Use PeerAddress instead unless the deployment
// has a validated front end that is known to set X-Forwarded-For AND strips any
// client-supplied value.
//
// Deprecated: prefer PeerAddress. Kept so that an explicit trusted-proxy decision
// remains possible later without reintroducing the header read into the default
// path.
func ForwardedSource(request *http.Request, source M.Socksaddr) M.Socksaddr {
	for _, value := range request.Header.Values("X-Forwarded-For") {
		for from := range strings.SplitSeq(value, ",") {
			address := M.ParseAddr(strings.TrimSpace(from))
			if address.IsValid() {
				return M.Socksaddr{Addr: address, Port: source.Port}.Unwrap()
			}
		}
	}
	return source
}
