//go:build with_naive_outbound

package naive

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sagernet/cronet-go"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// Tests for the sing-box -> cronet-go option plumbing.
//
// # What was wrong with the previous tests
//
// The existing single-engine tests asserted only that a Go struct could hold a
// bool:
//
//	options := option.NaiveOutboundOptions{
//	    InsecureConcurrency:             4,
//	    InsecureConcurrencySingleEngine: true,
//	}
//	require.True(t, options.InsecureConcurrencySingleEngine)
//
// That is a test of the struct definition, not of the plumbing. It passes even if
// NewOutbound never reads the field, which is exactly the failure mode worth
// guarding: a configuration option accepted and silently ignored. The chain that
// actually matters is
//
//	option.NaiveOutboundOptions -> cronet.NaiveClientOptions -> engine layout
//
// and only the middle link is reachable without starting a Chromium runtime.
// buildCronetNaiveClientOptions exists so that link can be tested directly.

func testParams(options option.NaiveOutboundOptions) cronetNaiveClientParams {
	return cronetNaiveClientParams{
		serverName: "example.com",
		options:    options,
	}
}

// TestSingleEngineSwitchReachesCronetOptions is the plumbing test that replaces
// "the struct can hold a bool".
//
// It asserts the value arrives at cronet.NaiveClientOptions.TestForceSingleEngine,
// which is the field cronet-go reads when it decides the engine count:
//
//	singleEngine: config.TestForceSingleEngine || runtime.GOOS == "ios"
//	engineCount := 1
//	if c.concurrency > 1 && !c.singleEngine { engineCount = c.concurrency }
func TestSingleEngineSwitchReachesCronetOptions(t *testing.T) {
	t.Parallel()

	built := buildCronetNaiveClientOptions(testParams(option.NaiveOutboundOptions{
		InsecureConcurrency:             4,
		InsecureConcurrencySingleEngine: true,
	}))

	require.Equal(t, 4, built.InsecureConcurrency,
		"insecure_concurrency must reach cronet.NaiveClientOptions.InsecureConcurrency")
	require.True(t, built.TestForceSingleEngine,
		"insecure_concurrency_single_engine must reach "+
			"cronet.NaiveClientOptions.TestForceSingleEngine, which is the field cronet-go "+
			"reads to force one engine")
}

// TestSingleEngineDefaultsToFalseInCronetOptions is the same assertion for the
// default, which is the property that protects existing behaviour: an operator who
// never sets the option must get the previous macOS engine layout.
func TestSingleEngineDefaultsToFalseInCronetOptions(t *testing.T) {
	t.Parallel()

	built := buildCronetNaiveClientOptions(testParams(option.NaiveOutboundOptions{
		InsecureConcurrency: 4,
	}))

	require.False(t, built.TestForceSingleEngine,
		"leaving the switch unset must not force a single engine, or the default "+
			"macOS behaviour of N engines changed silently")
	require.Equal(t, 4, built.InsecureConcurrency)
}

// TestConcurrencyAndSingleEngineAreIndependentThroughTheBuilder asserts the two
// settings do not overwrite one another on the way to Cronet.
//
// A plausible mistake would be to derive one from the other, making
// `insecure_concurrency` meaningless whenever the switch is on.
func TestConcurrencyAndSingleEngineAreIndependentThroughTheBuilder(t *testing.T) {
	t.Parallel()

	for _, concurrency := range []int{0, 1, 2, 4, 16} {
		for _, singleEngine := range []bool{false, true} {
			built := buildCronetNaiveClientOptions(testParams(option.NaiveOutboundOptions{
				InsecureConcurrency:             concurrency,
				InsecureConcurrencySingleEngine: singleEngine,
			}))
			require.Equal(t, concurrency, built.InsecureConcurrency,
				"concurrency %d must pass through unchanged", concurrency)
			require.Equal(t, singleEngine, built.TestForceSingleEngine,
				"the switch %v must pass through unchanged", singleEngine)
		}
	}
}

// TestBuilderCarriesEveryMappedField guards against a field being dropped during a
// future edit: each one is set to a distinctive value and checked.
func TestBuilderCarriesEveryMappedField(t *testing.T) {
	t.Parallel()

	params := cronetNaiveClientParams{
		serverName: "server.example",
		options: option.NaiveOutboundOptions{
			Username:                 "user",
			Password:                 "pass",
			InsecureConcurrency:      3,
			ReceiveWindow:            memoryBytes(t, 70000),
			QUICSessionReceiveWindow: memoryBytes(t, 80000),
			QUIC:                     true,
		},
		extraHeaders:            map[string]string{"X-Test": "abc"},
		trustedRootCertificates: "cert",
		echEnabled:              true,
		echConfigList:           []byte{1, 2, 3},
		echQueryServerName:      "ech.example",
		quicCongestionControl:   cronet.QUICCongestionControlBBR,
	}

	built := buildCronetNaiveClientOptions(params)

	require.Equal(t, "user", built.Username)
	require.Equal(t, "pass", built.Password)
	require.Equal(t, "server.example", built.ServerName)
	require.Equal(t, 3, built.InsecureConcurrency)
	require.EqualValues(t, 70000, built.ReceiveWindow)
	require.EqualValues(t, 80000, built.QUICSessionReceiveWindow)
	require.Equal(t, map[string]string{"X-Test": "abc"}, built.ExtraHeaders)
	require.Equal(t, "cert", built.TrustedRootCertificates)
	require.True(t, built.ECHEnabled)
	require.Equal(t, []byte{1, 2, 3}, built.ECHConfigList)
	require.Equal(t, "ech.example", built.ECHQueryServerName)
	require.True(t, built.QUIC)
	require.Equal(t, cronet.QUICCongestionControlBBR, built.QUICCongestionControl)
}

// ---------------------------------------------------------------------------
// Reserved extra_headers
// ---------------------------------------------------------------------------

// TestReservedExtraHeadersAreRejectedAtConfigurationTime covers the sing-box side
// of the control-header policy.
//
// The configuration must be refused while loading, not at dial time. Padding is
// the catastrophic case: the server enables padding based on the header being
// present and non-empty, while the client always frames its first eight writes, so
// `"extra_headers": {"Padding": ""}` desynchronises the stream from the first frame
// with no diagnosable error.
func TestReservedExtraHeadersAreRejectedAtConfigurationTime(t *testing.T) {
	t.Parallel()

	for _, reserved := range []string{
		"Padding",
		"padding",
		"PADDING",
		"Proxy-Authorization",
		"proxy-authorization",
		"-connect-authority",
		"-force-quic",
		"-network-isolation-key",
	} {
		err := validateReservedExtraHeaders(map[string][]string{reserved: {"x"}})
		require.Error(t, err,
			"extra_headers %q must be rejected; it overrides a Naive control header",
			reserved)
		require.Contains(t, err.Error(), reserved,
			"the error must name the offending header so the operator can fix it")
	}
}

// TestEmptyPaddingHeaderIsRejectedAtConfigurationTime is the specific catastrophic
// configuration, spelled the way a user would write it.
func TestEmptyPaddingHeaderIsRejectedAtConfigurationTime(t *testing.T) {
	t.Parallel()

	err := validateReservedExtraHeaders(map[string][]string{"Padding": {""}})
	require.Error(t, err,
		`extra_headers {"Padding": ""} must be rejected: the server turns padding OFF `+
			`while this client keeps framing, so every byte after CONNECT is `+
			`misinterpreted`)
}

// TestOrdinaryExtraHeadersAreAcceptedThroughTheBuilder is the control. A validator
// that rejected everything would pass the tests above while making the feature
// unusable, and the builder must still carry an allowed set through.
func TestOrdinaryExtraHeadersAreAcceptedThroughTheBuilder(t *testing.T) {
	t.Parallel()

	headers := map[string][]string{
		"X-Test":     {"abc"},
		"User-Agent": {"custom"},
		"Authorize":  {"note this is not Proxy-Authorization"},
		"pad":        {"not a reserved header"},
	}
	require.NoError(t, validateReservedExtraHeaders(headers),
		"ordinary headers must be accepted")

	// And they must survive into the Cronet options.
	flat := make(map[string]string, len(headers))
	for key, values := range headers {
		flat[key] = values[0]
	}
	built := buildCronetNaiveClientOptions(cronetNaiveClientParams{
		options:      option.NaiveOutboundOptions{},
		extraHeaders: flat,
	})
	require.Equal(t, "abc", built.ExtraHeaders["X-Test"])
	require.Len(t, built.ExtraHeaders, len(headers))
}

// TestReservedHeaderPolicyIsSharedWithCronet proves the sing-box validator and the
// cronet-go policy agree, rather than each keeping its own list.
//
// This is the property that prevents the two from drifting: if cronet-go's reserved
// set grows, this test fails without anyone editing sing-box.
func TestReservedHeaderPolicyIsSharedWithCronet(t *testing.T) {
	t.Parallel()

	for _, reserved := range []string{
		"Padding", "padding", "Proxy-Authorization",
		"-connect-authority", "-force-quic", "-network-isolation-key",
	} {
		require.True(t, cronet.IsReservedNaiveHeader(reserved),
			"cronet-go must consider %q reserved", reserved)
		require.Error(t, validateReservedExtraHeaders(map[string][]string{reserved: {"x"}}),
			"sing-box must reject %q, so both layers agree", reserved)
	}
	for _, allowed := range []string{"X-Test", "User-Agent", "Padding-Extra", "pad"} {
		require.False(t, cronet.IsReservedNaiveHeader(allowed),
			"cronet-go must not consider the ordinary header %q reserved", allowed)
		require.NoError(t, validateReservedExtraHeaders(map[string][]string{allowed: {"x"}}),
			"sing-box must accept the ordinary header %q", allowed)
	}
}

// TestReservedValidationErrorIsNotASentinel ensures the error is descriptive rather
// than a bare sentinel, since its whole purpose is to tell the operator what to fix.
func TestReservedValidationErrorIsNotASentinel(t *testing.T) {
	t.Parallel()

	err := validateReservedExtraHeaders(map[string][]string{"Padding": {""}})
	require.Error(t, err)
	require.False(t, errors.Is(err, errReservedHeaderSentinel),
		"the error must carry the header name, not be a bare sentinel")
	require.Contains(t, err.Error(), "extra_headers")
	require.Contains(t, err.Error(), "Padding")
}

// errReservedHeaderSentinel exists only so the test above can assert the returned
// error is not this value; nothing in production uses it.
var errReservedHeaderSentinel = errors.New("reserved header")

// ---------------------------------------------------------------------------
// End-to-end configuration rejection through NewOutbound
// ---------------------------------------------------------------------------

// TestNewOutboundRejectsReservedExtraHeaders is the test that protects the
// production path.
//
// The validator tests above call validateReservedExtraHeaders directly, so they keep
// passing even if NewOutbound stops calling it: removing that call was tried as a
// mutation and went undetected until this test existed. This one goes through the
// real constructor, so the wiring is covered too.
func TestNewOutboundRejectsReservedExtraHeaders(t *testing.T) {
	t.Parallel()

	for _, reserved := range []string{"Padding", "padding", "Proxy-Authorization", "-connect-authority"} {
		headers := badoption.HTTPHeader{reserved: badoption.Listable[string]{""}}
		_, err := NewOutbound(
			context.Background(),
			nil,
			log.NewNOPFactory().Logger(),
			"naive-reserved",
			option.NaiveOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: &option.OutboundTLSOptions{Enabled: true},
				},
				ExtraHeaders: headers,
			},
		)
		require.Error(t, err, "NewOutbound must reject the reserved header %q", reserved)
		require.Contains(t, err.Error(), "extra_headers")
		// The message names the canonical spelling: badoption.HTTPHeader.Build()
		// routes through http.Header.Add, which canonicalises the key, so a
		// configuration written as "padding" is reported as "Padding". Compare
		// case-insensitively, since that is how HTTP treats header names anyway.
		require.Contains(t, strings.ToLower(err.Error()), strings.ToLower(reserved),
			"the configuration error must name %q", reserved)
	}
}

// TestOrdinaryExtraHeadersSurviveCanonicalisation is the control for the test above.
//
// It deliberately does NOT run the whole constructor: with a nil router NewOutbound
// proceeds into dialer.NewDNSQueryOptions and panics on the nil router, which is
// unrelated to the header policy. What matters here is that the canonicalising
// conversion the constructor performs - badoption.HTTPHeader.Build(), which routes
// through http.Header.Add - does not turn an ordinary header into a reserved one.
func TestOrdinaryExtraHeadersSurviveCanonicalisation(t *testing.T) {
	t.Parallel()

	for _, ordinary := range []string{
		"X-Test",
		"User-Agent",
		"Authorize",
		"Padding-Extra",
		"pad",
		"X-connect-authority",
	} {
		headers := badoption.HTTPHeader{ordinary: badoption.Listable[string]{"abc"}}
		// The exact conversion NewOutbound performs before validating.
		require.NoError(t, validateReservedExtraHeaders(headers.Build()),
			"ordinary header %q must survive canonicalisation and be accepted", ordinary)
	}

	// And the canonicalisation itself must be what makes casing irrelevant: a
	// lower-case reserved header must still be caught after Build().
	for _, reserved := range []string{"padding", "proxy-authorization", "-connect-authority"} {
		headers := badoption.HTTPHeader{reserved: badoption.Listable[string]{"x"}}
		require.Error(t, validateReservedExtraHeaders(headers.Build()),
			"reserved header %q must still be rejected after canonicalisation", reserved)
	}
}

// Tests for the sing-box -> cronet-go option plumbing.
//
// # What was wrong with the previous tests
//
// The existing single-engine tests asserted only that a Go struct could hold a
// bool:
//
//	options := option.NaiveOutboundOptions{
//	    InsecureConcurrency:             4,
//	    InsecureConcurrencySingleEngine: true,
//	}
//	require.True(t, options.InsecureConcurrencySingleEngine)
//
// That is a test of the struct definition, not of the plumbing. It passes even if
// NewOutbound never reads the field, which is exactly the failure mode worth
// guarding: a configuration option accepted and silently ignored. The chain that
// actually matters is
//
//	option.NaiveOutboundOptions -> cronet.NaiveClientOptions -> engine layout
//
// and only the middle link is reachable without starting a Chromium runtime.
// buildCronetNaiveClientOptions exists so that link can be tested directly.

// TestSingleEngineSwitchReachesCronetOptions is the plumbing test that replaces
// "the struct can hold a bool".
//
// It asserts the value arrives at cronet.NaiveClientOptions.TestForceSingleEngine,
// which is the field cronet-go reads when it decides the engine count:
//
//	singleEngine: config.TestForceSingleEngine || runtime.GOOS == "ios"
//	engineCount := 1
