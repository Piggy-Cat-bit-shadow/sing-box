//go:build !go1.27

package jiejie_test

import (
	"net/http"
	"testing"
)

// h2ExtendedConnectHeader supplies the HTTP/2 extended CONNECT :protocol
// pseudo-header on Go 1.26 and earlier, where net/http still accepts a
// pseudo-header entry in the request header map.
//
// The sing-box HTTP/2 server reads :protocol from the header map
// (transport/http/server_h2.go), which is why the test client must send it there
// rather than in the Proto field. Go 1.27 rejects the header-map form; see
// jiejie_h2_extended_connect_go127_test.go.
func h2ExtendedConnectHeader(header http.Header) http.Header {
	header.Set(":protocol", "connect-udp")
	return header
}

// requireH2ExtendedConnectUsable is a no-op before Go 1.27, where the header-map
// form is accepted.
func requireH2ExtendedConnectUsable(t *testing.T) {
	t.Helper()
}
