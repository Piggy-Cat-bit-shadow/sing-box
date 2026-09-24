package http

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestServerH3DoesNotAllow0RTT pins the 0-RTT decision on the proxy HTTP/3
// inbound.
//
// A CONNECT is not a safe, idempotent request: it creates a tunnel, and 0-RTT
// application data is replayable by design, so a captured CONNECT could be
// replayed by a network attacker. quic-go does not filter this for us -- its
// http3 server documents that choosing 0-RTT-eligible requests is "the client's
// responsibility" -- so the server must refuse 0-RTT outright.
//
// Our own client already gates CONNECT on HandshakeComplete, so disabling 0-RTT
// costs the Jiejie client nothing; it closes the door for clients that do not
// gate it.
//
// This is asserted against the source rather than a live QUIC handshake because
// the property is a single configuration value: a regression would be someone
// changing that value, and a source assertion catches exactly that while staying
// deterministic.
func TestServerH3DoesNotAllow0RTT(t *testing.T) {
	source, err := os.ReadFile("server_h3.go")
	require.NoError(t, err, "server_h3.go must be readable")

	text := string(source)

	require.True(t, strings.Contains(text, "quicConfig.Allow0RTT = false"),
		"the proxy HTTP/3 inbound must disable 0-RTT: a replayable CONNECT is a "+
			"tunnel-replay vector, and quic-go leaves eligibility to the client")

	require.False(t, strings.Contains(text, "quicConfig.Allow0RTT = true"),
		"0-RTT must not be re-enabled on the proxy inbound")

	// The reasoning must stay next to the setting, so a future reader does not
	// "optimise" it back on without seeing why it is off.
	require.Contains(t, text, "REPLAYABLE BY DESIGN",
		"the comment explaining why 0-RTT is disabled must be kept with the setting")
}
