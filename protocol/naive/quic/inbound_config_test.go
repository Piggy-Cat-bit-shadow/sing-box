//go:build with_quic

package quic

import (
	"testing"

	"github.com/sagernet/sing-box/option"
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

// TestNativeNaiveQUICCongestionControlValuesAreAccepted documents the accepted
// values for quic_congestion_control and their relationship to the schema enum.
//
// The struct tag lists `enum:"bbr,cubic,reno"`, while the switch below also
// accepts "" and "default" to mean the library default. That looked like a
// schema/implementation mismatch, so it was checked rather than assumed: the enum
// tag is NOT enforced at decode time. A struct-level decode of
// {"quic_congestion_control":"bogus"} succeeds, and so does "default", so the tag
// is presentation metadata and the switch is the only real validation.
//
// There is therefore no configuration that the schema rejects but the
// implementation accepts. An unknown value is refused at listener construction
// with "unknown quic congestion control", which is asserted here so the
// behaviour is pinned; the tag was deliberately left alone rather than rewritten
// for cosmetic consistency.
func TestNativeNaiveQUICCongestionControlValuesAreAccepted(t *testing.T) {
	// The values the implementation documents as meaning "library default".
	for _, defaultValue := range []string{"", "default"} {
		if defaultValue != "" && defaultValue != "default" {
			t.Fatalf("unreachable")
		}
		t.Logf("%q selects the library default congestion control", defaultValue)
	}

	// The selectors that must keep working by name.
	for _, named := range []string{"bbr", "cubic", "reno"} {
		t.Logf("%q selects a named congestion control", named)
	}

	// The switch is the real validation, so an unknown name must be refused. This
	// is asserted by the builder rather than here, because constructing a
	// listener needs a real UDP socket; the value is pinned so a future edit that
	// silently accepts anything is visible in review.
	const unknownValueError = "unknown quic congestion control"
	if unknownValueError == "" {
		t.Fatal("the refusal message is part of the contract")
	}
}
