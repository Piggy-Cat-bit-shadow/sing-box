package v2raygrpclite

import "net/url"

// The custom gRPC service name is a PATH, and this transport has to put exactly the reference's
// string on the wire.
//
// # The reference's rule
//
// Xray builds the stream's `:path` by concatenation and hands the result to grpc-go as the method
// string:
//
//	c.cc.NewStream(ctx, desc, "/"+name+"/"+tun)
//
// and grpc-go writes that string into the `:path` pseudo-header unchanged
// (internal/transport/http2_client.go: `hpack.HeaderField{Name: ":path", Value: callHdr.Method}`).
// Nothing in the client decodes or re-escapes it. The server side is grpc-go as well, and it splits
// the RAW path at its LAST slash and looks the leading part up as a literal service name. So the
// service name reaches the server exactly as it was configured: a `/` inside it is another path
// segment, and a `%2F` inside it is still the three characters `%`, `2`, `F`.
//
// # Why this transport disagreed
//
// net/http has no "verbatim path" knob: it sends url.URL.EscapedPath(), and EscapedPath() honours
// RawPath only when RawPath is a valid encoding of Path (`url.PathUnescape(RawPath) == Path`). The
// previous construction set Path to the assembled path and RawPath to `url.PathEscape(name)`
// interpolated, which is a different string for every name that contains an escapable character. A
// name with a literal `/` went out as `%2F` - a different HTTP path, and a service name the
// reference server does not have - and a name that already contained `%2F` went out double-escaped
// as `%252F`. The same configuration therefore reached a different place here than through
// transport/v2raygrpc, whose grpc-go client concatenates exactly as Xray does.
//
// # What this file does instead
//
// servicePath assembles the reference's string, and serviceURLPath splits it into the (Path,
// RawPath) pair that makes EscapedPath() return that string unchanged. Path holds the DECODED form
// only because that is what EscapedPath() insists on before it will use RawPath; RawPath is the
// string the reference would send, byte for byte, and it is what leaves the process.
//
// A name whose assembled path is not a valid escape sequence at all (a lone `%`, or `%zz`) has no
// such pair, and there the assembled string is left in Path: net/http then escapes the stray
// percent. That is the one shape where a literal `%` reaches the server escaped instead of
// verbatim, and it is unavoidable without bypassing net/http's URL handling entirely - strictly
// better than double-escaping every name that contains a slash, which is what happened before.

// grpcTunStreamName is the stream the gun service exposes. It is the last path segment of every
// variant, which is why the path assembly needs it by name.
const grpcTunStreamName = "Tun"

// servicePath is the `:path` a gun stream must carry, exactly as the reference assembles it.
func servicePath(serviceName string) string {
	return "/" + serviceName + "/" + grpcTunStreamName
}

// serviceURLPath returns the (Path, RawPath) pair whose url.URL.EscapedPath is servicePath.
func serviceURLPath(serviceName string) (path string, rawPath string) {
	assembled := servicePath(serviceName)
	decoded, err := url.PathUnescape(assembled)
	if err != nil {
		return assembled, ""
	}
	return decoded, assembled
}
