package interop

import (
	"errors"
	"testing"
)

// The live matrix.
//
// One top-level test per scenario, rather than one test with subtests, so that
// the DEFAULT (gated-off) run reports one SKIP per scenario, each carrying the
// enable instructions. A single parent test would report a single skip and hide
// how many scenarios exist — and the count is the thing a maintainer needs in
// order to know what they are about to run.
//
// Every test here is compiled and registered in the default build. Only the body
// is gated. That is deliberate: a test that vanished behind a build tag would
// make `go test -list .` report an incomplete inventory of the stand.

// TestLiveInteropRealityClassical covers VLESS over REALITY with the hybrid key
// share stripped, which only an older reference accepts. See the scenario note.
func TestLiveInteropRealityClassical(t *testing.T) {
	runLiveScenarioForName(t, "reality-classical")
}

// TestLiveInteropRealityHybrid covers VLESS over REALITY with the X25519MLKEM768
// hybrid key share required, which is what a current reference demands.
func TestLiveInteropRealityHybrid(t *testing.T) {
	runLiveScenarioForName(t, "reality-hybrid")
}

// TestLiveInteropRealityFirefox covers the Firefox fingerprint with no explicit
// key_share, which is the configuration `fingerprint: firefox` alone produces.
// Per the scenario note it measures the pinned uTLS Firefox preset against a
// reference's hybrid-share requirement, not this fork's REALITY code.
func TestLiveInteropRealityFirefox(t *testing.T) {
	runLiveScenarioForName(t, "reality-firefox")
}

// TestLiveInteropRealitySafari covers the Safari fingerprint with no explicit
// key_share, which is the configuration `fingerprint: safari` alone produces.
func TestLiveInteropRealitySafari(t *testing.T) {
	runLiveScenarioForName(t, "reality-safari")
}

// TestLiveInteropRealityEncryption covers the VLESS application-layer
// post-quantum encryption over REALITY.
func TestLiveInteropRealityEncryption(t *testing.T) {
	runLiveScenarioForName(t, "reality-encryption")
}

// TestLiveInteropRealityEncryptionVision covers Vision running on top of the
// encryption layer, which is the combination that needs the layer's connection
// registry entry to exist at all.
func TestLiveInteropRealityEncryptionVision(t *testing.T) {
	runLiveScenarioForName(t, "reality-encryption-vision")
}

// TestLiveInteropRealityXHTTPStreamOne covers the XHTTP transport alone in
// stream-one mode, the mode REALITY resolves to.
func TestLiveInteropRealityXHTTPStreamOne(t *testing.T) {
	runLiveScenarioForName(t, "reality-xhttp-stream-one")
}

// TestLiveInteropRealityEncryptionVisionXHTTPStreamOne is the priority scenario:
// every layer at once, over REALITY, in stream-one mode.
func TestLiveInteropRealityEncryptionVisionXHTTPStreamOne(t *testing.T) {
	runLiveScenarioForName(t, "reality-encryption-vision-xhttp-stream-one")
}

// TestLiveInteropRealityXHTTPPacketUp covers XHTTP packet-up.
func TestLiveInteropRealityXHTTPPacketUp(t *testing.T) {
	runLiveScenarioForName(t, "reality-xhttp-packet-up")
}

// TestLiveInteropRealityXHTTPStreamUp covers XHTTP stream-up.
func TestLiveInteropRealityXHTTPStreamUp(t *testing.T) {
	runLiveScenarioForName(t, "reality-xhttp-stream-up")
}

// TestLiveInteropRealityXHTTPAuto covers XHTTP auto, which must resolve to
// stream-one in front of REALITY.
func TestLiveInteropRealityXHTTPAuto(t *testing.T) {
	runLiveScenarioForName(t, "reality-xhttp-auto")
}

// TestLiveInteropTLSXHTTPH3StreamOne covers XHTTP over HTTP/3, which cannot use
// REALITY and is additionally opt-in (see the H3 gate).
func TestLiveInteropTLSXHTTPH3StreamOne(t *testing.T) {
	runLiveScenarioForName(t, "tls-xhttp-h3-stream-one")
}

// runLiveScenarioForName applies every gate, then runs one scenario end to end.
//
// The gates are applied in the order a maintainer would have to satisfy them: the
// live gate, the scenario's own opt-in, the build's capabilities, the reference's
// version, and finally the key material the reference owns. Each one SKIPS rather
// than fails because none of them is evidence about the protocol, and the
// remaining code — the part that can actually fail — is only reached when a real
// reference is about to be exercised.
func runLiveScenarioForName(t *testing.T, name string) {
	t.Helper()
	scenario, err := ScenarioByName(name)
	if err != nil {
		t.Fatalf("%v", err)
	}
	binary := requireLiveInterop(t, scenario)
	if reason := KnownGapGateReason(scenario); reason != "" {
		t.Skip(reason)
	}
	if scenario.H3 {
		if reason := H3GateReason(); reason != "" {
			t.Skip(reason)
		}
	}
	version := ReferenceVersion(binary)
	if supported, reason := RealityKeyShareSupport(version, scenario.KeyShare); !supported {
		t.Skip("reference interop scenario " + scenario.Name + " is not compatible with this reference: " + reason)
	}
	var encryption EncryptionKeyMaterial
	if scenario.EncryptionEnabled() {
		encryption, err = ReferenceEncryptionKeyMaterial(scenario, binary)
		if err != nil {
			if errors.Is(err, ErrNoReferenceKeyMaterial) {
				t.Skipf("reference interop scenario %s needs key material only the reference can produce: %v\n"+
					"Provision a matched pair (the reference's own generator prints one) and export both halves:\n"+
					"  xray vlessenc\n"+
					"  export %s='<the encryption string it printed>'\n"+
					"  export %s='<the decryption string it printed>'\n"+
					"or leave XRAY_BINARY pointing at a reference that has a key generator.",
					scenario.Name, err, EncryptionEnvClient, EncryptionEnvServer)
			}
			t.Fatalf("obtain encryption key material: %v", err)
		}
		t.Logf("scenario %s: %s, client spec appearance %q (the scenario declares %q)",
			scenario.Name, encryption.Explain(), EncryptionSpecPrefix(encryption.ClientSpec),
			scenario.EncryptionAppearance+"."+scenario.EncryptionRTT)
	}

	created := newStand(t, scenario, binary, version, encryption)
	created.start(t)
	created.runSubtests(t)
}
