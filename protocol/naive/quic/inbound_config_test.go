//go:build with_quic

package quic

import (
	"testing"
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
	config := nativeNaiveQUICConfig()

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
// These two remain deliberate differences from the reference and are recorded as
// such in docs/JIEJIE-NAIVE-H3-AUDIT.md; they are asserted here so a change to
// them is a visible decision rather than an accident.
func TestNativeNaiveQUICConfigKeepsDocumentedSettings(t *testing.T) {
	config := nativeNaiveQUICConfig()

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
	if !config.DisablePathManager {
		t.Fatal("DisablePathManager changed; connection migration behaviour is " +
			"recorded in the H3 audit and needs a migration test before changing")
	}
}

// TestNativeNaiveQUICConfigIsNotShared guards against the config being handed
// out as a package-level value.
//
// A shared *quic.Config would let one listener's mutation affect another's, the
// same class of cross-contamination that the TLS ALPN work fixed for the TLS
// config. Returning a fresh value keeps each listener independent.
func TestNativeNaiveQUICConfigIsNotShared(t *testing.T) {
	first := nativeNaiveQUICConfig()
	second := nativeNaiveQUICConfig()
	if first == second {
		t.Fatal("nativeNaiveQUICConfig must return a fresh config per call, not a " +
			"shared package-level pointer")
	}
	first.Allow0RTT = true
	if second.Allow0RTT {
		t.Fatal("mutating one config must not affect another")
	}
}
