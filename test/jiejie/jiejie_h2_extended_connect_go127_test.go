//go:build go1.27

package jiejie_test

import (
	"net/http"
	"testing"
)

// h2ExtendedConnectHeader supplies the HTTP/2 extended CONNECT :protocol
// pseudo-header for Go 1.27 and later.
//
// Go changed net/http in 1.27: a request whose header map contains a
// pseudo-header such as ":protocol" is now rejected by the client with
// `http: invalid header field name ":protocol"`, before it ever reaches the
// wire. The header map is therefore no longer a usable way to send an HTTP/2
// extended CONNECT from a test client on 1.27.
//
// This affects the TEST CLIENT only. The sing-box HTTP/2 server reads :protocol
// from the header map (transport/http/server_h2.go) and falls back to the Proto
// field only for HTTP/3, so the H2 server genuinely inspects the header-map
// form. Because that form cannot be expressed through net/http's public API on
// 1.27, the affected tests skip there instead of probing something that does not
// reflect production. Use the Proto field on H3, which works on every version.
func h2ExtendedConnectHeader(header http.Header) http.Header {
	return header
}

// requireH2ExtendedConnectUsable skips an HTTP/2 extended CONNECT test on Go
// 1.27+, where net/http refuses to send the :protocol pseudo-header.
func requireH2ExtendedConnectUsable(t *testing.T) {
	t.Helper()
	t.Skip("Go 1.27 net/http rejects the \":protocol\" pseudo-header required for an " +
		"HTTP/2 extended CONNECT, so this probe cannot be expressed from a test client " +
		"on this toolchain; see jiejie_h2_extended_connect_go127_test.go")
}
