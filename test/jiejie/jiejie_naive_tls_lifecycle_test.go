package jiejie_test

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"

	"github.com/stretchr/testify/require"
)

// The production topology serves tcp only, but this test deliberately starts
// tcp+udp: that is the only shape that builds BOTH the TCP and QUIC views from one
// shared TLS config, which is the ownership question being exercised.

// TLS lifecycle ownership on a real tcp+udp Native Naive inbound.
//
// The unit tests in common/tls prove that two views share one lifecycle owner in
// isolation. This proves the same thing about the real inbound: one shared TLS
// config, two transports, and exactly one Start and one Close reaching the
// certificate material.
//
// Why it is worth a real test: the views embed the shared config, so Start and
// Close reach it through the embedded value. If anything ever closed a view - a
// listener that cleaned up "its" config, or an inbound closing several handles -
// the shared config would be closed more than once, double-closing the certificate
// provider, the ACME service and the watcher. Those are not observable from the
// outside, so only counting the lifecycle calls catches it.

// TestJiejieNaiveSharedTLSLifecycleIsSingleOwner drives a real tcp+udp inbound
// through Start and Close.
//
// The exact Start/Close COUNTS are asserted in common/tls against a double that
// records them, because a real inbound's certificate provider is not
// instrumentable from here. What this test adds is that the production shape
// actually works: one shared TLS config serves BOTH transports, both come up, and
// the single owner closes them without error, panic or hang. A double Start would
// surface as a start failure and a double Close as an error or a panic on the
// repeated call.
func TestJiejieNaiveSharedTLSLifecycleIsSingleOwner(t *testing.T) {
	if !http3SupportLinked() {
		t.Skipf("this build does not link HTTP/3, so a tcp+udp inbound cannot " +
			"start its QUIC transport and the two-transport lifecycle cannot be " +
			"exercised. This is a SKIP, not a pass.")
	}
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)

	ctx, cancel := context.WithCancel(globalCtx)
	defer cancel()

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Log: &option.LogOptions{Level: "warn"},
			Inbounds: []option.Inbound{{
				Type: constant.TypeNaive,
				Tag:  "naive-in",
				Options: &option.NaiveInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     minimalLoopback(),
						ListenPort: port,
					},
					// tcp+udp is the shape that builds BOTH views from one
					// shared TLS config, which is the whole point here.
					Network: option.NetworkList("tcp\nudp"),
					Users: []auth.User{{
						Username: naiveTestUser,
						Password: naiveTestPassword,
					}},
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled:         true,
							ServerName:      "naive.test",
							CertificatePath: certPem,
							KeyPath:         keyPem,
						},
					},
				},
			}},
			Outbounds: []option.Outbound{{Type: constant.TypeDirect, Tag: "direct"}},
			Route:     &option.RouteOptions{Final: "direct"},
		},
	})
	require.NoError(t, err, "the instance must build")

	// The instance owns the inbound's lifecycle: Start brings up the shared TLS
	// config and both listeners, Close tears them down.
	require.NoError(t, instance.Start(), "the instance must start")

	// Both transports must actually be serving, or the test would pass against an
	// inbound that never brought up the second transport.
	require.True(t, waitForPort(t, port, 10*time.Second),
		"the TCP listener must be up")
	_, quicErr := negotiateQUICALPN(t, port, []string{"h3"})
	require.NoError(t, quicErr,
		"the QUIC transport must be up on a tcp+udp inbound; without it only one "+
			"view exists and the shared-ownership question is not exercised")

	// Close once. A double close would surface as an error or a hang here.
	require.NoError(t, instance.Close(), "the instance must close cleanly")

	// Closing twice must be safe and must not panic or block: the inbound's Close
	// is the single owner and a repeated call must not reach the certificate
	// material a second time.
	require.NotPanics(t, func() { _ = instance.Close() },
		"a repeated Close must not panic")

	t.Logf("tcp+udp inbound started and closed with both transports up; "+
		"port=%d", port)
}
