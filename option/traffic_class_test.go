package option_test

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// decodeOutbound runs the real configuration decode path, including the outbound registry, because
// the interesting failure modes are about the envelope and the concrete options agreeing on which
// keys belong to whom.
func decodeOutbound(t *testing.T, raw string) option.Outbound {
	t.Helper()
	var out option.Outbound
	require.NoError(t, out.UnmarshalJSONContext(include.Context(t.Context()), []byte(raw)))
	return out
}

// TestTrafficClassAbsentIsUnset pins the compatibility contract: a configuration that does not
// mention traffic_class must decode exactly as before, with no policy attached.
func TestTrafficClassAbsentIsUnset(t *testing.T) {
	out := decodeOutbound(t, `{"type":"selector","tag":"🤖 AI","outbounds":["a"]}`)
	require.Nil(t, out.TrafficClass, "an absent traffic_class must be unset, not default")
}

// TestTrafficClassExplicitDefaultIsDistinguishable is the reason the config type is separate from
// the runtime enum: "unset" and "default" are different intents.
func TestTrafficClassExplicitDefaultIsDistinguishable(t *testing.T) {
	unset := decodeOutbound(t, `{"type":"selector","tag":"🤖 AI","outbounds":["a"]}`)
	explicit := decodeOutbound(t, `{"type":"selector","tag":"🤖 AI","traffic_class":"default","outbounds":["a"]}`)

	require.Nil(t, unset.TrafficClass)
	require.NotNil(t, explicit.TrafficClass, "an explicit default must be recorded as SET")
	require.True(t, explicit.TrafficClass.IsDefault())
}

func TestTrafficClassExplicitValues(t *testing.T) {
	for name, expected := range map[string]trafficclass.Class{
		"default":     trafficclass.ClassDefault,
		"interactive": trafficclass.ClassInteractive,
		"bulk":        trafficclass.ClassBulk,
		"realtime":    trafficclass.ClassRealtime,
	} {
		out := decodeOutbound(t, `{"type":"selector","tag":"t","traffic_class":"`+name+`","outbounds":["a"]}`)
		require.NotNil(t, out.TrafficClass, name)
		require.Equal(t, expected, out.TrafficClass.Class, name)
	}
}

// TestTrafficClassInvalidFailsClosed: a typo must not silently disable the policy.
func TestTrafficClassInvalidFailsClosed(t *testing.T) {
	for _, bad := range []string{"high", "Interactive", "ai", "true", "1", "urgent"} {
		var out option.Outbound
		err := out.UnmarshalJSONContext(include.Context(t.Context()),
			[]byte(`{"type":"selector","tag":"t","traffic_class":"`+bad+`","outbounds":["a"]}`))
		require.Error(t, err, "traffic_class %q must be rejected", bad)
	}
}

// TestTrafficClassIsNotLeakedIntoOptions proves the envelope consumes the key, so a concrete
// options type with strict decoding never sees it. If it leaked, the field would either be stored
// twice or rejected as an unknown key.
func TestTrafficClassIsNotLeakedIntoOptions(t *testing.T) {
	out := decodeOutbound(t, `{"type":"selector","tag":"🤖 AI","traffic_class":"interactive","outbounds":["a","b"]}`)
	selector, isSelector := out.Options.(*option.SelectorOutboundOptions)
	require.True(t, isSelector, "the concrete options must still be built")
	require.Equal(t, []string{"a", "b"}, selector.Outbounds)
}

// TestTrafficClassRoundTrip pins that marshalling preserves the distinction in both directions.
func TestTrafficClassRoundTrip(t *testing.T) {
	// Unset must not emit the key at all, so an old configuration is byte-stable.
	unset := decodeOutbound(t, `{"type":"selector","tag":"t","outbounds":["a"]}`)
	encoded, err := unset.MarshalJSONContext(include.Context(t.Context()))
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "traffic_class",
		"an unset policy must not be serialised, or old configurations change shape")

	// Explicit default must survive as the string "default", not vanish. The comparison is
	// whitespace-insensitive because the encoder chooses its own spacing.
	explicit := decodeOutbound(t, `{"type":"selector","tag":"t","traffic_class":"default","outbounds":["a"]}`)
	encoded, err = explicit.MarshalJSONContext(include.Context(t.Context()))
	require.NoError(t, err)
	require.Contains(t, strings.Join(strings.Fields(string(encoded)), ""), `"traffic_class":"default"`)

	// And a re-decode must agree.
	roundTripped := decodeOutbound(t, string(encoded))
	require.NotNil(t, roundTripped.TrafficClass)
	require.True(t, roundTripped.TrafficClass.IsDefault())
}
