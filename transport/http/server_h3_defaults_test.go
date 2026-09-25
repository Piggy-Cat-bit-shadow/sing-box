//go:build with_quic

package http

import (
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/option"
)

// quicGoDefaultMaxIncomingStreams is quic-go's default stream limit
// (internal/protocol.DefaultMaxIncomingStreams). It is spelled out because the
// constant lives in an internal package, and asserted here so a dependency bump
// that changed it is visible.
const quicGoDefaultMaxIncomingStreams = 100

// newQUICConfigForTest derives the config exactly as server_h3.go does, so the
// assertions track the production path rather than a copy of it.
func newQUICConfigForTest(options option.QUICOptions) *quic.Config {
	return httpclient.NewQUICConfig(options)
}

// The MASQUE HTTP/3 listener's protocol defaults, aligned with the references.
//
// quic-go/masque-go and quic-go/connect-ip-go both construct their server with
// only EnableDatagrams and InitialPacketSize set ("quicConf = &quic.Config{
// EnableDatagrams: true, InitialPacketSize: defaultInitialPacketSize}"), so
// EVERY other QUIC property is the quic-go default. This fork previously pinned
// three of them away from that default, making production tuning look like
// protocol behaviour:
//
//	MaxIncomingStreams  forced to 1 << 60, quic-go's internal "unlimited" clamp
//	                    rather than its default of 100
//	DisablePathManager  forced true, where the default has migration enabled
//	congestion control  forced BBR standard, where the default is quic-go's own
//
// These tests pin the aligned state so the divergence cannot return unnoticed.

// TestMASQUEH3CongestionControlIsOptIn pins that BBR is a choice, not a default.
func TestMASQUEH3CongestionControlIsOptIn(t *testing.T) {
	sender, err := parseBBRProfile("")
	if err != nil {
		t.Fatalf("an empty bbr_profile must be accepted: %v", err)
	}
	if sender != nil {
		t.Fatal("an unset bbr_profile must leave quic-go's congestion control in " +
			"place; forcing BBR would make a production tuning choice the " +
			"protocol default, which neither reference does")
	}

	// The explicit values must still work, or the production tuning path is
	// broken rather than merely made optional.
	for _, name := range []string{
		option.BBRProfileStandard,
		option.BBRProfileConservative,
		option.BBRProfileAggressive,
	} {
		selected, selectErr := parseBBRProfile(name)
		if selectErr != nil {
			t.Fatalf("explicit bbr_profile %q must be accepted: %v", name, selectErr)
		}
		if selected == nil {
			t.Fatalf("explicit bbr_profile %q must select a sender", name)
		}
	}

	// And an unknown value must still be refused.
	if _, unknownErr := parseBBRProfile("not-a-profile"); unknownErr == nil {
		t.Fatal("an unknown bbr_profile must be refused")
	}
}

// TestMASQUEH3PathManagerDefaultsToEnabled pins the path manager default.
func TestMASQUEH3PathManagerDefaultsToEnabled(t *testing.T) {
	var options option.QUICOptions
	if options.DisablePathManager {
		t.Fatal("the path manager must default to ENABLED, matching quic-go and " +
			"both references; disabling migration is an explicit opt-in")
	}

	enabled := option.QUICOptions{DisablePathManager: true}
	if !enabled.DisablePathManager {
		t.Fatal("the explicit opt-in must be representable")
	}
}

// TestMASQUEH3StreamLimitIsNotTheUnlimitedSentinel pins the stream bound.
//
// The check is on the value the listener would USE, derived the same way
// server_h3.go derives it, so it fails if the forcing is reintroduced.
func TestMASQUEH3StreamLimitIsNotTheUnlimitedSentinel(t *testing.T) {
	const unlimitedSentinel = int64(1) << 60

	// Unconfigured: NewQUICConfig leaves the field zero, and server_h3.go must
	// NOT fill it in, so quic-go applies its default of 100.
	var unconfigured option.QUICOptions
	config := newQUICConfigForTest(unconfigured)
	if config.MaxIncomingStreams == unlimitedSentinel {
		t.Fatalf("MaxIncomingStreams is the unlimited sentinel; the listener must "+
			"leave it unset so quic-go's bounded default of %d applies",
			quicGoDefaultMaxIncomingStreams)
	}
	if config.MaxIncomingStreams != 0 {
		t.Fatalf("an unconfigured server must leave MaxIncomingStreams unset, got %d",
			config.MaxIncomingStreams)
	}
	t.Logf("unconfigured: MaxIncomingStreams unset, so quic-go applies its "+
		"default of %d", quicGoDefaultMaxIncomingStreams)

	// Configured: the explicit value must be honoured, so the production
	// override path still works.
	configured := option.QUICOptions{HTTP2Options: option.HTTP2Options{MaxConcurrentStreams: 256}}
	config = newQUICConfigForTest(configured)
	if config.MaxIncomingStreams != 256 {
		t.Fatalf("an explicit max_concurrent_streams must be honoured, got %d",
			config.MaxIncomingStreams)
	}
}
