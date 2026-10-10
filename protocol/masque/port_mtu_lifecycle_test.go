//go:build with_quic

//
// The production constructor refuses to build without QUIC ("QUIC is not included in this
// build"), so this lifecycle contract is asserted on the build that actually ships it. A test that
// ran untagged would fail for a reason that has nothing to do with the property under test.

package masque

import (
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The tunnel's inner capacity must be answerable BEFORE the tunnel is started
// ---------------------------------------------------------------------------
//
// # Why this is a contract and not an implementation detail
//
// `PortMTU()` used to return `c.device.PortMTU()`, and `c.device` is created in
// `StartStateInitialize`. So between construction and Start the endpoint had a nil device behind that
// call, and it PANICKED.
//
// That window is precisely when the answer is needed. A protocol stacked on top of this tunnel - HY2,
// TUIC, anything that reaches this endpoint through `detour` - has to size its own payload ceiling, and
// it does that at CONSTRUCTION, because nothing orders this endpoint's Start before another outbound's
// construction. An upper protocol asking "how much can you carry" would therefore have taken the whole
// process down, in one of the hardest-to-diagnose ways: a nil-interface panic inside a constructor.
//
// The value is knowable before the device exists, which is why the fix is a read of the configured MTU
// rather than a guard: `c.mtu` is seeded from `options.MTU` (defaulting to `masque.DefaultMTU`) in the
// constructor, and `StartStatePostStart` hands that SAME field to `device.Configuration{MTU: c.mtu}`.
// The device runs at this value for its whole life, so the pre-Start answer and the post-Start answer
// are the same number by construction rather than by coincidence.

// newMTUEndpoint builds a real client endpoint through the production constructor and deliberately does
// NOT start it, which is the state under test.
func newMTUEndpoint(t *testing.T, configuredMTU uint32) *ClientEndpoint {
	t.Helper()
	ctx := newTestRegistryContext(nil)
	endpointOptions := option.MASQUEClientEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     "masque.example",
			ServerPort: 443,
		},
		DialerOptions: option.DialerOptions{
			AbstractDialerOptions: option.AbstractDialerOptions{
				DomainResolver: &option.DomainResolveOptions{Server: "dns-bootstrap"},
			},
		},
		Version: 3,
		Path:    "/",
		// MTU lives on the embedded MASQUEEndpointOptions, so it cannot be set in this literal.
	}
	// The device options carry the MTU; the constructor promotes it onto c.mtu.
	endpointOptions.MASQUEEndpointOptions = option.MASQUEEndpointOptions{MTU: configuredMTU}
	tlsOptions := newBootstrapTLSOptions()
	endpointOptions.TLS = &tlsOptions

	instance, err := NewClientEndpoint(ctx, nil, log.NewNOPFactory().Logger(), "masque-mtu", endpointOptions)
	require.NoError(t, err)
	endpoint, isClient := instance.(*ClientEndpoint)
	require.True(t, isClient, "the constructor must return a client endpoint, got %T", instance)
	return endpoint
}

// TestPortMTUIsAnswerableBeforeStart is the regression guard for the panic.
//
// It must not merely avoid a panic: it must return the value the device will later run at, because a
// number that is safe to read but wrong would be worse - an upper protocol would size itself against a
// fiction, and nothing would report it.
func TestPortMTUIsAnswerableBeforeStart(t *testing.T) {
	for _, configured := range []uint32{0, 1280, 1400, 900} {
		t.Run(mtuCaseName(configured), func(t *testing.T) {
			endpoint := newMTUEndpoint(t, configured)

			require.Nil(t, endpoint.device,
				"the device must not exist yet, or this test proves nothing about the nil window")

			// The call that used to panic.
			var reported uint32
			require.NotPanics(t, func() { reported = endpoint.PortMTU() },
				"PortMTU must be answerable while the device is nil: the upper protocol sizes "+
					"itself before this endpoint is started")

			want := configured
			if want == 0 {
				want = masque.DefaultMTU
			}
			require.Equal(t, want, reported,
				"the pre-Start answer must be the configured capacity: the constructor defaults 0 to "+
					"masque.DefaultMTU and Start hands this same value to the device, so a different "+
					"number here would be a fiction the upper protocol sizes against")

			// And it must be a capacity the endpoint will actually honour, which is what ties the
			// pre-Start answer to the runtime one.
			require.EqualValues(t, want, endpoint.mtu,
				"the reported value and the value Start will configure the device with must be one "+
					"field, not two that can drift")
		})
	}
}

// mtuCaseName turns a configured MTU into a sub-test name, including the zero case.
func mtuCaseName(configured uint32) string {
	if configured == 0 {
		return "configured_0_defaults"
	}
	return "configured_" + itoaTest(configured)
}

func itoaTest(value uint32) string {
	if value == 0 {
		return "0"
	}
	var digits [12]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}
