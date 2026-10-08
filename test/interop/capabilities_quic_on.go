//go:build with_quic

package interop

// buildHasQUIC records the `with_quic` build tag at compile time.
//
// The XHTTP transport needs it for the HTTP/3 connection: without the tag,
// newHTTP3Transport is the stub and an ALPN of ["h3"] fails when the outbound is
// constructed. The H3 scenario must therefore skip rather than fail in a build
// that cannot speak QUIC at all.
const buildHasQUIC = true
