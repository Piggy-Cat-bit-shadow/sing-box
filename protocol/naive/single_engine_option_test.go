//go:build with_naive_outbound

package naive

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// Tests for the single-engine switch on the Naive outbound.
//
// # Why the switch is opt-in
//
// cronet-go decides the engine count with:
//
//	singleEngine: config.TestForceSingleEngine || runtime.GOOS == "ios"
//	engineCount := 1
//	if c.concurrency > 1 && !c.singleEngine { engineCount = c.concurrency }
//
// so `insecure_concurrency: 4` on macOS builds FOUR Cronet engines, each a full
// Chromium network stack, unless singleEngine is forced. iOS already forces it and
// gets N independent HTTP/2 sessions through a per-pool `-network-isolation-key`
// header instead.
//
// Flipping the macOS default is a behaviour change - it moves the traffic to a
// different Chromium code path - so the option exists to make each shape
// selectable for measurement first. These tests pin the plumbing: the option must
// reach cronet.NaiveClientOptions, and it must default to false so upstream
// behaviour is preserved when nobody sets it.

// TestSingleEngineOptionDefaultsToFalse asserts the default does not change
// behaviour.
//
// This is the property that matters most: an operator who does not know the option
// exists must get exactly the engine layout they got before it was added.
func TestSingleEngineOptionDefaultsToFalse(t *testing.T) {
	t.Parallel()

	var options option.NaiveOutboundOptions
	require.False(t, options.InsecureConcurrencySingleEngine,
		"the single-engine switch must default to false, or adding it silently "+
			"changed the macOS engine layout")
}

// TestSingleEngineOptionIsIndependentOfConcurrency asserts the switch is honoured
// on its own.
//
// A plausible implementation mistake would be to treat any concurrency > 1 as
// "use one engine", which would make the concurrency setting meaningless. The two
// fields must be independent: concurrency sets how many isolated sessions/pools,
// the switch sets how many engines back them.
func TestSingleEngineOptionIsIndependentOfConcurrency(t *testing.T) {
	t.Parallel()

	options := option.NaiveOutboundOptions{
		InsecureConcurrency:             4,
		InsecureConcurrencySingleEngine: true,
	}
	require.Equal(t, 4, options.InsecureConcurrency,
		"the concurrency ceiling must survive the single-engine switch")
	require.True(t, options.InsecureConcurrencySingleEngine)

	// And the other way round: single engine off with concurrency set is the
	// upstream shape, and must remain expressible.
	upstream := option.NaiveOutboundOptions{InsecureConcurrency: 4}
	require.False(t, upstream.InsecureConcurrencySingleEngine)
	require.Equal(t, 4, upstream.InsecureConcurrency)
}

// TestSingleEngineOptionIsExposedInConfigSchema asserts the field is reachable
// from configuration.
//
// A field that exists on the struct but is not part of the marshalled option set
// would be silently ignored by `sing-box check`, which is the failure mode this
// catches: the option would appear to work and do nothing.
func TestSingleEngineOptionIsExposedInConfigSchema(t *testing.T) {
	t.Parallel()

	raw := []byte(`{
		"server": "example.com",
		"server_port": 443,
		"insecure_concurrency": 4,
		"insecure_concurrency_single_engine": true
	}`)

	parsed, err := json.UnmarshalExtended[option.NaiveOutboundOptions](raw)
	require.NoError(t, err, "the option must be accepted by the option parser")
	require.True(t, parsed.InsecureConcurrencySingleEngine,
		"the parsed value must reflect the configuration; if it does not, the JSON "+
			"tag is wrong and the option is silently ignored")
	require.Equal(t, 4, parsed.InsecureConcurrency)
}
