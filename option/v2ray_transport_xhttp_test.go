package option

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// XHTTP must be reachable from a config FILE, not merely from the code.
//
// # The defect this pins
//
// The transport was implemented, registered, build-tagged into every shipped profile, and given a
// MarshalJSON case and a schema entry - but the UnmarshalJSON switch was never extended, so its
// `default:` branch rejected the type:

//	outbounds[0].transport: unknown transport type: xhttp
//
// That switch is on the production load path (`cmd_run.go` goes through the extended JSON
// decoder), so the entire XHTTP client transport was unreachable by any user configuration: the
// code compiled, the tests passed, the binary contained it, and no config could select it.
//
// A round trip through the real decoder is the only thing that catches this. Asserting on the
// struct, the schema, or the registry all pass while the feature is dead.

const xhttpTransportConfig = `{
	"type": "xhttp",
	"host": "example.com",
	"path": "/interop",
	"mode": "stream-one",
	"no_grpc_header": true,
	"session_placement": "header",
	"seq_placement": "query",
	"xmux": {
		"max_concurrency": "8-16",
		"max_connections": "1-2",
		"c_max_reuse_times": "100"
	}
}`

func TestXHTTPTransportSurvivesTheConfigDecoder(t *testing.T) {
	t.Parallel()
	var transport V2RayTransportOptions
	require.NoError(t, json.Unmarshal([]byte(xhttpTransportConfig), &transport),
		"a config selecting type xhttp must load; the unmarshal switch is on the production path")

	require.Equal(t, C.V2RayTransportTypeXHTTP, transport.Type)
	require.Equal(t, "example.com", transport.XHTTPOptions.Host)
	require.Equal(t, "/interop", transport.XHTTPOptions.Path)
	require.Equal(t, "stream-one", transport.XHTTPOptions.Mode)
	require.True(t, transport.XHTTPOptions.NoGRPCHeader)
	require.Equal(t, "header", transport.XHTTPOptions.SessionPlacement)
	require.Equal(t, "query", transport.XHTTPOptions.SeqPlacement)
	require.NotNil(t, transport.XHTTPOptions.Xmux,
		"the whole nested option block must survive, not just the discriminator")
}

// And the discriminator must still reject a type that does not exist, so the fix did not turn the
// switch into a permissive one.
func TestUnknownTransportTypeIsStillRejected(t *testing.T) {
	t.Parallel()
	var transport V2RayTransportOptions
	err := json.Unmarshal([]byte(`{"type": "carrier-pigeon"}`), &transport)
	require.ErrorContains(t, err, "unknown transport type")
}

// Every declared type must be loadable. This is the general form of the bug above: adding a type
// to the enum, the marshal switch and the schema while forgetting the unmarshal switch is exactly
// how xhttp became unreachable, and this test fails for the next one.
func TestEveryDeclaredTransportTypeIsLoadable(t *testing.T) {
	t.Parallel()
	for _, transportType := range []string{
		C.V2RayTransportTypeHTTP,
		C.V2RayTransportTypeWebsocket,
		C.V2RayTransportTypeQUIC,
		C.V2RayTransportTypeGRPC,
		C.V2RayTransportTypeHTTPUpgrade,
		C.V2RayTransportTypeXHTTP,
	} {
		t.Run(transportType, func(t *testing.T) {
			t.Parallel()
			var transport V2RayTransportOptions
			require.NoError(t, json.Unmarshal([]byte(`{"type": "`+transportType+`"}`), &transport),
				"a declared transport type must be loadable, or the type is unreachable by config")
			require.Equal(t, transportType, transport.Type)
		})
	}
}
