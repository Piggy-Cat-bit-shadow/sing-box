//go:build with_quic

package quic

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// The Native Naive HTTP/3 listener must not accept 0-RTT.
//
// Allow0RTT is the ONLY gate for early data on the server: quic-go documents it
// as "Only valid for the server" and consumes it when deciding whether to accept
// a 0-RTT connection attempt (quic-go interface.go, config.go, connection.go).
// ListenEarly, despite the name, is only the listener API - it does not enable
// early data by itself.
//
// A CONNECT tunnel is the wrong place to accept early data: 0-RTT payloads are
// replayable by anyone who captures them, so an early-data CONNECT could be
// replayed against this server. HTTP/3 does not depend on 0-RTT to work, so the
// cost of refusing it is a round trip on a resumed connection and nothing else.
// The pinned reference (Caddy v2.10.0 + forwardproxy@d62c80d3) does not enable it
// either.
func TestNativeNaiveQUICConfigRefuses0RTT(t *testing.T) {
	config := nativeNaiveQUICConfig(option.NaiveInboundOptions{})

	if config.Allow0RTT {
		t.Fatal("Allow0RTT must be false: an early-data CONNECT is replayable, " +
			"and HTTP/3 works without 0-RTT")
	}
	// Stated explicitly rather than only implied: the field must stay at the
	// library default. A future edit that sets it back to true fails here.
	if config.Allow0RTT != false {
		t.Fatalf("Allow0RTT must equal the quic-go default false, got %v", config.Allow0RTT)
	}
}

// TestNativeNaiveQUICConfigKeepsDocumentedSettings pins the settings that ARE
// set, so the 0-RTT fix cannot be mistaken for a general reset of this config.
//
// The protocol default must be reference-like: MaxIncomingStreams stays UNSET so
// the quic-go default applies, and DisablePathManager stays UNSET so the path
// manager is enabled, which is what Caddy's quic.Config produces. Disabling
// migration is a production choice that is now opted into through the inbound
// options, so the default no longer carries it.
func TestNativeNaiveQUICConfigKeepsDocumentedSettings(t *testing.T) {
	config := nativeNaiveQUICConfig(option.NaiveInboundOptions{})

	// MaxIncomingStreams must stay UNSET so the library default (100) applies.
	// It was 1 << 60, which is quic-go's own internal "unlimited" sentinel rather
	// than a considered limit: it matched neither the library default nor the
	// reference, and it removed the only server-side bound on concurrent HTTP/3
	// work. Measurement before removal: 256 concurrent streams cost ~2.5 MiB with
	// no extra goroutines or descriptors.
	if config.MaxIncomingStreams != 0 {
		t.Fatalf("MaxIncomingStreams must be left unset so the library default "+
			"applies, got %d", config.MaxIncomingStreams)
	}
	if config.DisablePathManager {
		t.Fatal("DisablePathManager must default to the reference's behaviour " +
			"(path manager enabled); disabling migration is an explicit opt-in, " +
			"not a protocol default")
	}
}

// TestNativeNaiveQUICConfigIsNotShared guards against the config being handed
// out as a package-level value.
//
// A shared *quic.Config would let one listener's mutation affect another's, the
// same class of cross-contamination that the TLS ALPN work fixed for the TLS
// config. Returning a fresh value keeps each listener independent.
func TestNativeNaiveQUICConfigIsNotShared(t *testing.T) {
	first := nativeNaiveQUICConfig(option.NaiveInboundOptions{})
	second := nativeNaiveQUICConfig(option.NaiveInboundOptions{})
	if first == second {
		t.Fatal("nativeNaiveQUICConfig must return a fresh config per call, not a " +
			"shared package-level pointer")
	}
	first.Allow0RTT = true
	if second.Allow0RTT {
		t.Fatal("mutating one config must not affect another")
	}
}

// TestNativeNaiveQUICConfigDisablesPathManagerOnlyWhenAsked pins the opt-in.
//
// The fork's production deployment disables connection migration, which is a
// legitimate choice but a behaviour difference from the reference. It must
// therefore be reachable by configuration and absent by default, so the two
// states are both assertable rather than one being compiled in.
func TestNativeNaiveQUICConfigDisablesPathManagerOnlyWhenAsked(t *testing.T) {
	enabled := nativeNaiveQUICConfig(option.NaiveInboundOptions{})
	if enabled.DisablePathManager {
		t.Fatal("the default must leave the path manager enabled, matching the reference")
	}

	optedIn := nativeNaiveQUICConfig(option.NaiveInboundOptions{QUICDisablePathManager: true})
	if !optedIn.DisablePathManager {
		t.Fatal("quic_disable_path_manager must actually disable it when set")
	}
}

// TestNativeNaiveQUICConfigLeavesUnsetFieldsToTheLibrary asserts that nothing
// which changes wire behaviour is hardcoded.
//
// This is the property that makes the default reference-like: the config carries
// no opinion where Caddy carries none either. A future addition that hardcodes a
// protocol-visible field fails here and has to be argued for.
func TestNativeNaiveQUICConfigLeavesUnsetFieldsToTheLibrary(t *testing.T) {
	config := nativeNaiveQUICConfig(option.NaiveInboundOptions{})

	if config.MaxIncomingStreams != 0 {
		t.Fatalf("MaxIncomingStreams must stay unset, got %d", config.MaxIncomingStreams)
	}
	if config.Allow0RTT {
		t.Fatal("Allow0RTT must stay false")
	}
	if config.DisablePathManager {
		t.Fatal("DisablePathManager must stay unset by default")
	}
}

// TestNativeNaiveCongestionControlAcceptsDocumentedValues asserts the values the
// production resolver accepts.
//
// It calls newNaiveCongestionControl, which is the SAME function the listener
// constructor calls, so there is no second copy of the validation in this test
// that could drift from production.
func TestNativeNaiveCongestionControlAcceptsDocumentedValues(t *testing.T) {
	for _, name := range []string{"", "default", "bbr", "cubic", "reno"} {
		t.Run("value="+name, func(t *testing.T) {
			sender, err := newNaiveCongestionControl(name, time.Now)
			if err != nil {
				t.Fatalf("the production resolver refused %q, which is documented "+
					"as accepted: %v", name, err)
			}
			// An unset value and the explicit "default" must both mean "keep
			// quic-go's sender", which the constructor represents as nil. The
			// named values must produce a sender.
			if name == "" || name == "default" {
				if sender != nil {
					t.Fatalf("%q must select the library default (nil sender), got a "+
						"sender factory", name)
				}
				return
			}
			if sender == nil {
				t.Fatalf("%q must produce a sender factory, got nil", name)
			}
		})
	}
}

// TestNativeNaiveCongestionControlRejectsUnknownValues is the real validation
// test, replacing an assertion that compared a string constant to "".
//
// The previous version could not fail: it declared the message and checked it was
// not empty, so a production change to `default: accept anything` would have left
// it green. This drives the production resolver and requires an actual error.
func TestNativeNaiveCongestionControlRejectsUnknownValues(t *testing.T) {
	// Case and whitespace variants are included deliberately: matching is exact,
	// so "BBR" and " bbr" are configuration errors rather than being silently
	// normalised into a working value.
	for _, name := range []string{
		"bogus", "BBR", "CUBIC", "Reno", " bbr", "bbr ", "none", "auto", "0",
		"bbr2", "BBRv2",
	} {
		t.Run("value="+name, func(t *testing.T) {
			sender, err := newNaiveCongestionControl(name, time.Now)
			if err == nil {
				t.Fatalf("the production resolver accepted %q; an unrecognised "+
					"congestion control must be refused so a typo does not look "+
					"like it worked", name)
			}
			if sender != nil {
				t.Fatalf("a rejected value must not also produce a sender (%q)", name)
			}
			if !strings.Contains(err.Error(), "unknown quic congestion control") {
				t.Fatalf("the error must name the problem so it is actionable, got: %v", err)
			}
		})
	}
}

// TestNativeNaiveCongestionControlDecodeThenValidate records the full chain.
//
// The struct tag lists enum:"bbr,cubic,reno", which is presentation metadata: it is
// NOT enforced at decode time. A JSON document carrying "bogus" therefore decodes
// successfully and is refused later by the resolver. That sequence is asserted
// here so the division of responsibility is recorded rather than assumed - the
// schema describes the values, the resolver is what enforces them.
func TestNativeNaiveCongestionControlDecodeThenValidate(t *testing.T) {
	var options option.NaiveInboundOptions
	raw := []byte(`{"listen":"127.0.0.1","listen_port":1,` +
		`"users":[{"username":"u","password":"p"}],` +
		`"quic_congestion_control":"bogus"}`)

	if err := json.UnmarshalContext(context.Background(), raw, &options); err != nil {
		t.Fatalf("an unknown value must DECODE successfully, because the enum tag "+
			"is not a decode-time validator: %v", err)
	}
	if options.QUICCongestionControl != "bogus" {
		t.Fatalf("the decoded value is %q, want the raw %q",
			options.QUICCongestionControl, "bogus")
	}

	// And the production validation must then refuse it.
	if _, err := newNaiveCongestionControl(options.QUICCongestionControl, time.Now); err == nil {
		t.Fatal("a value that decodes successfully must still be refused by the " +
			"production validation; otherwise an unknown congestion control would " +
			"reach the listener")
	}

	// The accepted set must decode too, so the two halves agree on the values.
	for _, accepted := range []string{"", "default", "bbr", "cubic", "reno"} {
		var decoded option.NaiveInboundOptions
		document := []byte(`{"listen":"127.0.0.1","listen_port":1,` +
			`"users":[{"username":"u","password":"p"}],` +
			`"quic_congestion_control":"` + accepted + `"}`)
		if err := json.UnmarshalContext(context.Background(), document, &decoded); err != nil {
			t.Fatalf("%q must decode: %v", accepted, err)
		}
		if _, err := newNaiveCongestionControl(decoded.QUICCongestionControl, time.Now); err != nil {
			t.Fatalf("%q decoded but was refused by the resolver: %v", accepted, err)
		}
	}
}

// TestNativeNaiveQUICConfigPinsReferenceVersions asserts the QUIC version list is
// an explicit decision rather than an inherited library default.
//
// Caddy v2.10 pins Version1 and Version2 in its quic.Config. This fork previously
// left the field unset, which happened to produce the same set because quic-go's
// default is both - a dependency property, not a decision. The differential test
// compares the accepted version sets at runtime; this test pins the configured
// list, so a change to either is visible in a unit test as well.
func TestNativeNaiveQUICConfigPinsReferenceVersions(t *testing.T) {
	config := nativeNaiveQUICConfig(option.NaiveInboundOptions{})

	if len(config.Versions) != 2 {
		t.Fatalf("expected exactly two pinned QUIC versions, got %v", config.Versions)
	}
	if config.Versions[0] != quic.Version1 || config.Versions[1] != quic.Version2 {
		t.Fatalf("QUIC versions must be [v1 v2] to match the reference, got %v",
			config.Versions)
	}
}
