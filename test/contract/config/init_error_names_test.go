//go:build with_utls

package config_test

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	badjson "github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// An initialisation failure must name the element, not just its index.
//
// # Why this is pinned
//
// Every one of the six Create loops in box.New reported "initialize outbound[0]:" and nothing
// else, even though the element's type and tag were computed a few lines above for its logger
// name. Applications print the core's error text verbatim, and a user with a hundred tagged
// nodes in a subscription cannot act on an index - they need the tag to find the node. The
// upstream prefix is preserved because existing parsers may match it; the type and tag are
// appended before the colon.
func TestInitErrorNamesTheFailingElement(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		configJSON string
		wantErr    string
	}{
		{
			name: "outbound with a tag",
			configJSON: `{
				"outbounds": [
					{"type": "direct", "tag": "direct"},
					{"type": "socks", "tag": "proxy-de-1", "server": "127.0.0.1", "server_port": 1080, "version": "9"}
				]
			}`,
			wantErr: "initialize outbound[1] socks[proxy-de-1]: ",
		},
		{
			name: "outbound without a tag falls back to the index",
			configJSON: `{
				"outbounds": [
					{"type": "socks", "server": "127.0.0.1", "server_port": 1080, "version": "9"}
				]
			}`,
			// With no explicit tag the generated tag is the index, so the tail reads "socks[0]".
			wantErr: "initialize outbound[0] socks[0]: ",
		},
		{
			name: "endpoint",
			configJSON: `{
				"endpoints": [
					{"type": "wireguard", "tag": "wg-de-1", "system": false, "address": ["10.0.0.1/32"]}
				],
				"outbounds": [{"type": "direct", "tag": "direct"}]
			}`,
			wantErr: "initialize endpoint[0] wireguard[wg-de-1]: ",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ctx := include.Context(context.Background())
			var options option.Options
			err := badjson.UnmarshalContext(ctx, []byte(testCase.configJSON), &options)
			require.NoError(t, err)
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			if instance != nil {
				_ = instance.Close()
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), testCase.wantErr,
				"the error must name the type and tag so a user can find the node")
		})
	}
}
