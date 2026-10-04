package option_test

import (
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// decodeRoute runs the real configuration decode path for a route section.
func decodeRoute(t *testing.T, raw string) option.RouteOptions {
	t.Helper()
	var route option.RouteOptions
	require.NoError(t, json.UnmarshalContext(include.Context(t.Context()), []byte(raw), &route))
	return route
}

// TestTrafficSchedulerAbsentIsUnset is the compatibility contract: a configuration that does not
// mention the scheduler must decode and re-encode byte for byte as it did before the field existed.
func TestTrafficSchedulerAbsentIsUnset(t *testing.T) {
	route := decodeRoute(t, `{"final":"direct"}`)
	require.Nil(t, route.TrafficScheduler)

	encoded, err := json.MarshalContext(include.Context(t.Context()), route)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "traffic_scheduler",
		"an absent scheduler must not appear in the encoded configuration, or a configuration that "+
			"does not use the fork extension stops being loadable by official sing-box")
	require.Equal(t, `{"final":"direct"}`, string(encoded))
}

// TestTrafficSchedulerRoundTrip pins that every accepted spelling survives a decode/encode cycle
// with the same VALUE, which is not the same as the same spelling: the number is what has to be
// preserved, because the number is what the shaper uses.
func TestTrafficSchedulerRoundTrip(t *testing.T) {
	for spelling, expected := range map[string]int64{
		`{"traffic_scheduler":{"upload_rate":8388608}}`:       8388608,
		`{"traffic_scheduler":{"upload_rate":"8388608"}}`:     8388608,
		`{"traffic_scheduler":{"upload_rate":"8 MiB/s"}}`:     8 << 20,
		`{"traffic_scheduler":{"upload_rate":"8MiB"}}`:        8 << 20,
		`{"traffic_scheduler":{"upload_rate":"8mib/s"}}`:      8 << 20,
		`{"traffic_scheduler":{"upload_rate":" 8 MiB / s "}}`: 8 << 20,
		`{"traffic_scheduler":{"upload_rate":"8000 KiB/s"}}`:  8000 << 10,
		`{"traffic_scheduler":{"upload_rate":"20 MB/s"}}`:     20_000_000,
		`{"traffic_scheduler":{"upload_rate":"1 GB"}}`:        1_000_000_000,
	} {
		t.Run(spelling, func(t *testing.T) {
			route := decodeRoute(t, spelling)
			require.NotNil(t, route.TrafficScheduler)
			require.EqualValues(t, expected, route.TrafficScheduler.UploadRate.Build())

			encoded, err := json.MarshalContext(include.Context(t.Context()), route)
			require.NoError(t, err)

			var decoded option.RouteOptions
			require.NoError(t, json.UnmarshalContext(include.Context(t.Context()), encoded, &decoded))
			require.NotNil(t, decoded.TrafficScheduler)
			require.Equal(t, route.TrafficScheduler.UploadRate, decoded.TrafficScheduler.UploadRate,
				"the encoded form must decode to the same rate, whatever unit it was written in")
			require.Equal(t, int64(expected), decoded.TrafficScheduler.UploadRate.Build())
		})
	}
}

// TestTrafficSchedulerBitUnitsAreConverted pins that a bitrate spelling means the bitrate. A
// silent 8x error in either direction is the one mistake a rate field cannot make.
func TestTrafficSchedulerBitUnitsAreConverted(t *testing.T) {
	for spelling, expected := range map[string]int64{
		`"16000000bps"`: 2_000_000,
		`"16000kbps"`:   2_000_000,
		`"16Mbps"`:      2_000_000,
		// A bitrate spelling must not be mistaken for a byte rate: treating 16Mbps as 16 MiB/s
		// would shape to 8x the intended rate, which is the one mistake this field cannot make.
		`"16MB/s"`: 16_000_000,
	} {
		route := decodeRoute(t, `{"traffic_scheduler":{"upload_rate":`+spelling+`}}`)
		require.EqualValues(t, expected, route.TrafficScheduler.UploadRate.Build(), spelling)
	}
}

// TestTrafficSchedulerZeroIsInert pins the default-on-nothing contract: zero is a legal value and
// it means no shaping, not "shape to zero".
func TestTrafficSchedulerZeroIsInert(t *testing.T) {
	for _, spelling := range []string{
		`{"traffic_scheduler":{"upload_rate":0}}`,
		`{"traffic_scheduler":{"upload_rate":"0"}}`,
		`{"traffic_scheduler":{}}`,
	} {
		route := decodeRoute(t, spelling)
		require.NotNil(t, route.TrafficScheduler, spelling)
		require.Zero(t, route.TrafficScheduler.UploadRate.Build(), spelling)
	}

	// And a zero rate must not be re-emitted, so a configuration that sets the section but no rate
	// stays as small as it was written.
	route := decodeRoute(t, `{"traffic_scheduler":{}}`)
	encoded, err := json.MarshalContext(include.Context(t.Context()), route)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "upload_rate",
		"an unset rate must be omitted rather than written as zero")
}

// TestTrafficSchedulerRejectsBadValues covers the failures that would otherwise be accepted and
// then ignored, which for a rate limit is worse than a rejection: the configuration would claim a
// policy the process does not apply.
func TestTrafficSchedulerRejectsBadValues(t *testing.T) {
	for name, raw := range map[string]string{
		"negative number":  `{"traffic_scheduler":{"upload_rate":-1}}`,
		"negative string":  `{"traffic_scheduler":{"upload_rate":"-1"}}`,
		"unknown unit":     `{"traffic_scheduler":{"upload_rate":"8 furlongs/s"}}`,
		"no digits":        `{"traffic_scheduler":{"upload_rate":"MiB/s"}}`,
		"empty string":     `{"traffic_scheduler":{"upload_rate":""}}`,
		"bool":             `{"traffic_scheduler":{"upload_rate":true}}`,
		"fractional":       `{"traffic_scheduler":{"upload_rate":1.5}}`,
		"object":           `{"traffic_scheduler":{"upload_rate":{}}}`,
		"number overflow":  `{"traffic_scheduler":{"upload_rate":9223372036854775808}}`,
		"fraction string":  `{"traffic_scheduler":{"upload_rate":"1.5 MB/s"}}`,
		"unit overflow":    `{"traffic_scheduler":{"upload_rate":"9223372036854775807 TiB"}}`,
		"bitrate overflow": `{"traffic_scheduler":{"upload_rate":"99999999999999999 Gbps"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var route option.RouteOptions
			err := json.UnmarshalContext(include.Context(t.Context()), []byte(raw), &route)
			require.Error(t, err, "a value the shaper cannot use must fail the configuration")
		})
	}
}

// TestTrafficSchedulerAcceptsLargeRatesWithoutWrapping is the overflow boundary from the other
// side: a value that fits must be accepted exactly.
func TestTrafficSchedulerAcceptsLargeRatesWithoutWrapping(t *testing.T) {
	route := decodeRoute(t, `{"traffic_scheduler":{"upload_rate":9223372036854775807}}`)
	require.EqualValues(t, 9223372036854775807, route.TrafficScheduler.UploadRate.Build())

	route = decodeRoute(t, `{"traffic_scheduler":{"upload_rate":"8 TiB/s"}}`)
	require.EqualValues(t, 8<<40, route.TrafficScheduler.UploadRate.Build())
}

// TestTrafficSchedulerDoesNotDisturbTheRestOfTheRoute guards the field's placement: it lives on the
// route options, so adding it must not change how any neighbouring key decodes.
func TestTrafficSchedulerDoesNotDisturbTheRestOfTheRoute(t *testing.T) {
	route := decodeRoute(t, `{"final":"proxy","auto_detect_interface":true,`+
		`"traffic_scheduler":{"upload_rate":"8 MiB/s"}}`)
	require.Equal(t, "proxy", route.Final)
	require.True(t, route.AutoDetectInterface)
	require.NotNil(t, route.TrafficScheduler)
	require.EqualValues(t, 8<<20, route.TrafficScheduler.UploadRate.Build())
}
