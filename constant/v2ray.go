package constant

const (
	V2RayTransportTypeHTTP        = "http"
	V2RayTransportTypeWebsocket   = "ws"
	V2RayTransportTypeQUIC        = "quic"
	V2RayTransportTypeGRPC        = "grpc"
	V2RayTransportTypeHTTPUpgrade = "httpupgrade"
	// XHTTP is client-only in this fork: it registers behind the with_xhttp build tag, and an
	// inbound configured with it is rejected as an unknown transport type rather than half-working.
	V2RayTransportTypeXHTTP = "xhttp"
)
