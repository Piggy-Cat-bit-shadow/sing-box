package interop

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	badjson "github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// The tests that run everywhere.
//
// These are the half of the stand that works in an environment with no reference
// binary and no network, and they are not a consolation prize: they are the only
// thing that can prove the configurations handed to the reference are the
// configurations the scenario describes. A live run proves the wire format; these
// prove the file. Without them a wire failure would be unattributable, because
// nothing would have established what was sent.

// validationInput builds a generator input for a scenario without starting
// anything.
//
// Ports are fixed rather than reserved: nothing binds them, and a fixed value
// makes a generated artifact reproducible from the test source alone, which is
// what a maintainer wants when they re-run a reference by hand.
func validationInput(t *testing.T, scenario Scenario) Input {
	t.Helper()
	dir := t.TempDir()
	publicKey, privateKey, err := GenerateRealityKeyPair()
	require.NoError(t, err)
	input := Input{
		Scenario:          scenario,
		ArtifactDir:       dir,
		ServerAddress:     "127.0.0.1",
		ServerPort:        24443,
		ClientAddress:     "127.0.0.1",
		ClientPort:        24080,
		TargetAddress:     "127.0.0.1",
		TargetPort:        24081,
		ServerName:        "interop.local",
		CamouflageAddress: "127.0.0.1:24444",
		RealityPublicKey:  publicKey,
		RealityPrivateKey: privateKey,
		ShortID:           GenerateShortID(),
		UUID:              "b831381d-6324-4d53-ad4f-8cda48b30811",
		TLSCertFile:       filepath.Join(dir, "camouflage.crt"),
		TLSKeyFile:        filepath.Join(dir, "camouflage.key"),
		ClientLogPath:     filepath.Join(dir, "box-client.log"),
		ServerLogPath:     filepath.Join(dir, "xray-server.log"),
	}
	if scenario.EncryptionEnabled() {
		material, err := NewSyntheticEncryptionKeyMaterial(scenario)
		require.NoError(t, err)
		input.Encryption = material
	}
	return input
}

// TestGeneratedClientConfigJSONShape asserts the emitted JSON literally, key by
// key.
//
// It walks a generic map rather than the option types on purpose. The option
// parser would accept `keyShare` only if the parser also spelled it that way, so
// parsing proves "the parser and the generator agree"; walking the raw JSON
// proves "the file says key_share", which is what the reference on the other end
// of a socket actually reads.
func TestGeneratedClientConfigJSONShape(t *testing.T) {
	t.Parallel()
	for _, scenario := range Scenarios() {
		scenario := scenario
		t.Run(scenario.Name, func(t *testing.T) {
			t.Parallel()
			input := validationInput(t, scenario)
			pair, err := input.Generate()
			require.NoError(t, err)

			root := decodeJSONObject(t, pair.ClientConfig)
			inbounds := jsonArrayAt(t, root, "inbounds")
			require.Len(t, inbounds, 1)
			inbound := asObject(t, inbounds[0], "inbounds[0]")
			require.Equal(t, "mixed", jsonStringAt(t, inbound, "type"))
			require.Equal(t, float64(input.ClientPort), jsonNumberAt(t, inbound, "listen_port"))

			outbounds := jsonArrayAt(t, root, "outbounds")
			require.Len(t, outbounds, 1)
			outbound := asObject(t, outbounds[0], "outbounds[0]")
			require.Equal(t, "vless", jsonStringAt(t, outbound, "type"))
			require.Equal(t, clientOutboundTag, jsonStringAt(t, outbound, "tag"))
			require.Equal(t, input.UUID, jsonStringAt(t, outbound, "uuid"))
			require.Equal(t, float64(input.ServerPort), jsonNumberAt(t, outbound, "server_port"))

			// Vision is expressed only as `flow`, and only when the scenario has it.
			if scenario.Vision {
				require.Equal(t, "xtls-rprx-vision", jsonStringAt(t, outbound, "flow"))
			} else {
				require.NotContains(t, outbound, "flow")
			}

			// The encryption string is the CLIENT half of the matched pair.
			if scenario.EncryptionEnabled() {
				require.Equal(t, input.Encryption.ClientSpec, jsonStringAt(t, outbound, "encryption"))
			} else {
				require.NotContains(t, outbound, "encryption")
			}

			if scenario.Transport == TransportXHTTP {
				transport := asObject(t, outbound["transport"], "outbounds[0].transport")
				require.Equal(t, "xhttp", jsonStringAt(t, transport, "type"))
				require.Equal(t, input.path(), jsonStringAt(t, transport, "path"))
				if scenario.XHTTPMode == "" {
					require.NotContains(t, transport, "mode")
				} else {
					require.Equal(t, scenario.XHTTPMode, jsonStringAt(t, transport, "mode"))
				}
			} else {
				require.NotContains(t, outbound, "transport")
			}

			switch {
			case scenario.Reality:
				tlsBlock := asObject(t, outbound["tls"], "outbounds[0].tls")
				require.Equal(t, true, tlsBlock["enabled"])
				require.Equal(t, input.ServerName, jsonStringAt(t, tlsBlock, "server_name"))
				utlsBlock := asObject(t, tlsBlock["utls"], "outbounds[0].tls.utls")
				require.Equal(t, true, utlsBlock["enabled"])
				// Asserted against the scenario's RESOLVED fingerprint, so a
				// scenario that names one and a generator that emits another
				// cannot both pass. The default itself is pinned separately by
				// TestScenarioFingerprintDefaultIsPinned, so this comparison
				// cannot become a tautology.
				require.Equal(t, scenario.ClientFingerprint(), jsonStringAt(t, utlsBlock, "fingerprint"))
				reality := asObject(t, tlsBlock["reality"], "outbounds[0].tls.reality")
				require.Equal(t, true, reality["enabled"])
				require.Equal(t, input.RealityPublicKey, jsonStringAt(t, reality, "public_key"))
				require.Equal(t, input.ShortID, jsonStringAt(t, reality, "short_id"))
				// The empty policy must stay ABSENT, not serialize as an empty
				// string: "as the fingerprint carries it" and "explicitly empty"
				// are different instructions to the core.
				if scenario.KeyShare == "" {
					require.NotContains(t, reality, "key_share")
				} else {
					require.Equal(t, scenario.KeyShare, jsonStringAt(t, reality, "key_share"))
				}
			case scenario.PlainTLS:
				tlsBlock := asObject(t, outbound["tls"], "outbounds[0].tls")
				require.Equal(t, true, tlsBlock["enabled"])
				require.Equal(t, input.ServerName, jsonStringAt(t, tlsBlock, "server_name"))
				require.NotContains(t, tlsBlock, "utls")
				require.NotContains(t, tlsBlock, "reality")
				if scenario.H3 {
					require.Equal(t, []any{"h3"}, jsonArrayAt(t, tlsBlock, "alpn"))
				} else {
					require.NotContains(t, tlsBlock, "alpn")
				}
			default:
				require.NotContains(t, outbound, "tls")
			}
		})
	}
}

// TestGeneratedClientConfigRoundTripsThroughTheOptionParser is the "it is a
// valid config" half: the same bytes, through this repository's own parser.
func TestGeneratedClientConfigRoundTripsThroughTheOptionParser(t *testing.T) {
	t.Parallel()
	for _, scenario := range Scenarios() {
		scenario := scenario
		t.Run(scenario.Name, func(t *testing.T) {
			t.Parallel()
			if scenario.Transport == TransportXHTTP {
				if reason := XHTTPOptionLayerSkipReason(); reason != "" {
					t.Skip(reason)
				}
			}
			input := validationInput(t, scenario)
			pair, err := input.Generate()
			require.NoError(t, err)

			parsed, err := badjson.UnmarshalExtendedContext[option.Options](RegistryContext(), pair.ClientConfig)
			require.NoError(t, err, "the generated client config must parse with this repository's parser")
			require.Len(t, parsed.Outbounds, 1)
			require.Equal(t, "vless", parsed.Outbounds[0].Type)
			require.Equal(t, clientOutboundTag, parsed.Outbounds[0].Tag)
			vless, isVLESS := parsed.Outbounds[0].Options.(*option.VLESSOutboundOptions)
			require.True(t, isVLESS, "the outbound options must be VLESS, got %T", parsed.Outbounds[0].Options)
			require.Equal(t, input.UUID, vless.UUID)
			require.Equal(t, scenario.Flow(), vless.Flow)
			if scenario.EncryptionEnabled() {
				require.Equal(t, input.Encryption.ClientSpec, vless.Encryption)
			} else {
				require.Empty(t, vless.Encryption)
			}
			if scenario.Transport == TransportXHTTP {
				require.NotNil(t, vless.Transport)
				require.Equal(t, C.V2RayTransportTypeXHTTP, vless.Transport.Type)
				require.Equal(t, scenario.XHTTPMode, vless.Transport.XHTTPOptions.Mode)
				require.Equal(t, input.path(), vless.Transport.XHTTPOptions.Path)
			} else {
				require.Nil(t, vless.Transport)
			}
			if scenario.Reality {
				require.NotNil(t, vless.TLS)
				require.NotNil(t, vless.TLS.Reality)
				require.True(t, vless.TLS.Reality.Enabled)
				require.Equal(t, input.RealityPublicKey, vless.TLS.Reality.PublicKey)
				require.Equal(t, input.ShortID, vless.TLS.Reality.ShortID)
				require.Equal(t, scenario.KeyShare, vless.TLS.Reality.KeyShare)
				require.NotNil(t, vless.TLS.UTLS)
				// The round trip is the half that matters for the fingerprint:
				// the reference never sees it, so if the parser does not carry
				// the scenario's name through, the live test silently exercises
				// the default and reports a pass for a preset it never used.
				require.Equal(t, scenario.ClientFingerprint(), vless.TLS.UTLS.Fingerprint)
			}
			// The route must point at the tunnel; a config that parses but routes
			// directly would make every round trip succeed against the target
			// without ever touching the reference.
			require.NotNil(t, parsed.Route)
			require.Equal(t, clientOutboundTag, parsed.Route.Final)
		})
	}
}

// TestGeneratedServerConfigJSONShape asserts the reference's own schema.
//
// Xray's schema is not this fork's: snake_case becomes camelCase, the transport
// moves under streamSettings, and the encryption spec's server half moves to
// `settings.decryption`. Those are exactly the seams where an interop stand
// silently tests the client against itself, so each one is asserted by name.
func TestGeneratedServerConfigJSONShape(t *testing.T) {
	t.Parallel()
	for _, scenario := range Scenarios() {
		scenario := scenario
		t.Run(scenario.Name, func(t *testing.T) {
			t.Parallel()
			input := validationInput(t, scenario)
			pair, err := input.Generate()
			require.NoError(t, err)

			root := decodeJSONObject(t, pair.ServerConfig)
			inbounds := jsonArrayAt(t, root, "inbounds")
			require.Len(t, inbounds, 1)
			inbound := asObject(t, inbounds[0], "inbounds[0]")
			require.Equal(t, "vless", jsonStringAt(t, inbound, "protocol"))
			require.Equal(t, float64(input.ServerPort), jsonNumberAt(t, inbound, "port"))

			settings := asObject(t, inbound["settings"], "inbounds[0].settings")
			if scenario.EncryptionEnabled() {
				require.Equal(t, input.Encryption.ServerSpec, jsonStringAt(t, settings, "decryption"))
			} else {
				require.Equal(t, "none", jsonStringAt(t, settings, "decryption"))
			}
			clients := jsonArrayAt(t, settings, "clients")
			require.Len(t, clients, 1)
			client := asObject(t, clients[0], "inbounds[0].settings.clients[0]")
			require.Equal(t, input.UUID, jsonStringAt(t, client, "id"))
			if scenario.Vision {
				require.Equal(t, "xtls-rprx-vision", jsonStringAt(t, client, "flow"))
			} else {
				require.NotContains(t, client, "flow")
			}

			streamSettings := asObject(t, inbound["streamSettings"], "inbounds[0].streamSettings")
			switch {
			case scenario.Reality:
				require.Equal(t, "reality", jsonStringAt(t, streamSettings, "security"))
			case scenario.PlainTLS:
				require.Equal(t, "tls", jsonStringAt(t, streamSettings, "security"))
			default:
				require.Equal(t, "none", jsonStringAt(t, streamSettings, "security"))
			}
			if scenario.Transport == TransportXHTTP {
				require.Equal(t, "xhttp", jsonStringAt(t, streamSettings, "network"))
				xhttp := asObject(t, streamSettings["xhttpSettings"], "streamSettings.xhttpSettings")
				require.Equal(t, input.path(), jsonStringAt(t, xhttp, "path"))
				if scenario.XHTTPMode == "" {
					require.NotContains(t, xhttp, "mode")
				} else {
					require.Equal(t, scenario.XHTTPMode, jsonStringAt(t, xhttp, "mode"))
				}
			} else {
				require.Equal(t, "tcp", jsonStringAt(t, streamSettings, "network"))
				require.NotContains(t, streamSettings, "xhttpSettings")
			}
			if scenario.Reality {
				// The REALITY private key lives ONLY in the reference config; a
				// private key leaking into the client half would still "work"
				// because REALITY would authenticate, which is why it is asserted
				// here by name.
				reality := asObject(t, streamSettings["realitySettings"], "streamSettings.realitySettings")
				require.Equal(t, input.RealityPrivateKey, jsonStringAt(t, reality, "privateKey"))
				require.Equal(t, input.CamouflageAddress, jsonStringAt(t, reality, "dest"))
				require.Equal(t, []any{input.ServerName}, jsonArrayAt(t, reality, "serverNames"))
				require.Equal(t, []any{input.ShortID}, jsonArrayAt(t, reality, "shortIds"))
				require.NotContains(t, streamSettings, "tlsSettings")
			}
			if scenario.PlainTLS {
				tlsSettings := asObject(t, streamSettings["tlsSettings"], "streamSettings.tlsSettings")
				certificates := jsonArrayAt(t, tlsSettings, "certificates")
				require.Len(t, certificates, 1)
				certificate := asObject(t, certificates[0], "streamSettings.tlsSettings.certificates[0]")
				require.Equal(t, input.TLSCertFile, jsonStringAt(t, certificate, "certificateFile"))
				require.Equal(t, input.TLSKeyFile, jsonStringAt(t, certificate, "keyFile"))
				if scenario.H3 {
					require.Equal(t, []any{"h3"}, jsonArrayAt(t, tlsSettings, "alpn"))
				}
				require.NotContains(t, streamSettings, "realitySettings")
			}
			require.NotContains(t, inbound, "realitySettings",
				"REALITY settings belong under streamSettings in Xray's schema")

			// The freedom outbound's explicit loopback allow. A current reference blackholes a
			// private destination by default, and the stand's destination is loopback by design, so
			// its absence would turn every scenario into "the tunnel came up and nothing answered".
			outbounds := jsonArrayAt(t, root, "outbounds")
			require.Len(t, outbounds, 1)
			outbound := asObject(t, outbounds[0], "outbounds[0]")
			require.Equal(t, "freedom", jsonStringAt(t, outbound, "protocol"))
			freedom := asObject(t, outbound["settings"], "outbounds[0].settings")
			finalRules := jsonArrayAt(t, freedom, "finalRules")
			require.Len(t, finalRules, 1)
			finalRule := asObject(t, finalRules[0], "outbounds[0].settings.finalRules[0]")
			require.Equal(t, "allow", jsonStringAt(t, finalRule, "action"))
			require.Equal(t, []any{"127.0.0.0/8", "::1/128"}, jsonArrayAt(t, finalRule, "ip"),
				"the allow must cover every loopback destination the stand can use")
		})
	}
}

// TestGeneratedKeyMaterialIsMatched proves the two files are a PAIR: the public
// key the client carries is the one derived from the private key the server
// carries, for both layers.
func TestGeneratedKeyMaterialIsMatched(t *testing.T) {
	t.Parallel()
	for _, scenario := range Scenarios() {
		scenario := scenario
		if !scenario.Reality {
			continue
		}
		t.Run(scenario.Name, func(t *testing.T) {
			t.Parallel()
			input := validationInput(t, scenario)
			pair, err := input.Generate()
			require.NoError(t, err)

			clientRoot := decodeJSONObject(t, pair.ClientConfig)
			clientOutbound := asObject(t, jsonArrayAt(t, clientRoot, "outbounds")[0], "outbounds[0]")
			clientReality := asObject(t, asObject(t, clientOutbound["tls"], "tls")["reality"], "tls.reality")
			clientPublicKey := jsonStringAt(t, clientReality, "public_key")

			derivedPublicKey, err := deriveRealityPublicKey(input.RealityPrivateKey)
			require.NoError(t, err)
			require.Equal(t, derivedPublicKey, clientPublicKey,
				"the client's REALITY public key must be the public half of the server's private key")

			serverRoot := decodeJSONObject(t, pair.ServerConfig)
			serverInbound := asObject(t, jsonArrayAt(t, serverRoot, "inbounds")[0], "inbounds[0]")
			serverReality := asObject(t,
				asObject(t, serverInbound["streamSettings"], "streamSettings")["realitySettings"],
				"streamSettings.realitySettings")
			require.Equal(t, input.RealityPrivateKey, jsonStringAt(t, serverReality, "privateKey"))
			require.NotEqual(t, clientPublicKey, jsonStringAt(t, serverReality, "privateKey"))

			if scenario.EncryptionEnabled() {
				// The synthetic pair is an X25519 key pair of its OWN, independent
				// of the REALITY pair — the two layers share nothing, which is the
				// point of them being separate layers. So the check derives the
				// public half from the ENCRYPTION private key and requires it to be
				// the key the client spec carries: getting the two halves the wrong
				// way round is the single most likely mistake in a generator, and
				// against a real reference it would surface only as an opaque
				// decryption failure.
				encryptionPrivateKey := lastSpecSegment(t, input.Encryption.ServerSpec)
				encryptionPublicKey, err := deriveRealityPublicKey(encryptionPrivateKey)
				require.NoError(t, err)
				require.Equal(t,
					"mlkem768x25519plus."+scenario.EncryptionAppearance+"."+scenario.EncryptionRTT+"."+encryptionPublicKey,
					input.Encryption.ClientSpec)
				require.Equal(t, lastSpecSegment(t, input.Encryption.ClientSpec), encryptionPublicKey)
			}
		})
	}
}

// TestGeneratedConfigsAreWrittenToDiskAndAreInspectable pins the requirement that
// a human can open and reuse the pair by hand: the files exist, they contain
// exactly the bytes the caller was handed, and both are JSON a person can read.
func TestGeneratedConfigsAreWrittenToDiskAndAreInspectable(t *testing.T) {
	t.Parallel()
	for _, scenario := range Scenarios() {
		scenario := scenario
		t.Run(scenario.Name, func(t *testing.T) {
			t.Parallel()
			input := validationInput(t, scenario)
			pair, err := input.Generate()
			require.NoError(t, err)

			for _, file := range []struct {
				path     string
				expected []byte
			}{
				{pair.ClientConfigPath, pair.ClientConfig},
				{pair.ServerConfigPath, pair.ServerConfig},
			} {
				require.FileExists(t, file.path)
				onDisk, err := os.ReadFile(file.path)
				require.NoError(t, err)
				require.Equal(t, file.expected, onDisk)
				require.True(t, strings.HasSuffix(string(onDisk), "\n"), "a config file should end with a newline")
				var generic any
				require.NoError(t, json.Unmarshal(onDisk, &generic), "%s must be valid JSON", file.path)
				require.True(t, strings.Contains(file.path, scenario.Name),
					"the file name must name the scenario so the artifact directory is self-describing")
			}
			require.Equal(t, filepath.Join(input.ArtifactDir, "client-"+scenario.Name+".json"), pair.ClientConfigPath)
			require.Equal(t, filepath.Join(input.ArtifactDir, "server-"+scenario.Name+".json"), pair.ServerConfigPath)
		})
	}
}

// TestScenarioMatrixCoversTheRequiredCombinations pins the coverage the stand
// claims. A scenario silently dropped from the table is the failure mode a
// matrix-shaped task is most exposed to.
func TestScenarioMatrixCoversTheRequiredCombinations(t *testing.T) {
	t.Parallel()
	required := []string{
		"reality-classical",
		"reality-hybrid",
		"reality-firefox",
		"reality-safari",
		"reality-encryption",
		"reality-encryption-vision",
		"reality-xhttp-stream-one",
		"reality-encryption-vision-xhttp-stream-one",
		"reality-xhttp-packet-up",
		"reality-xhttp-stream-up",
		"reality-xhttp-auto",
		"tls-xhttp-h3-stream-one",
	}
	names := ScenarioNames()
	for _, name := range required {
		require.Contains(t, names, name)
	}
	require.Len(t, names, len(required))
	for _, scenario := range Scenarios() {
		require.NotEmpty(t, scenario.Note, "scenario %s must record what a maintainer needs to know", scenario.Name)
	}
}

// TestKnownGapScenariosAreDeclaredAndCarryTheirReason ties the gate to the table.
//
// A scenario that reproduces a known limitation must DECLARE it: the register
// test that gates the cause lives in another module, so the scenario is the only
// place a maintainer sees "this failure is expected" next to the reproduction.
func TestKnownGapScenariosAreDeclaredAndCarryTheirReason(t *testing.T) {
	t.Parallel()
	declared := make(map[string]bool)
	for _, scenario := range Scenarios() {
		if scenario.KnownGap == "" {
			continue
		}
		declared[scenario.Name] = true
		require.NotEmpty(t, scenario.Fingerprint,
			"scenario %s declares a known gap, so it must name the fingerprint it is about", scenario.Name)
		require.NotEqual(t, DefaultClientFingerprint, scenario.ClientFingerprint(),
			"scenario %s declares a known gap on the DEFAULT fingerprint, which would mean the "+
				"stand's own baseline is broken rather than one selectable preset", scenario.Name)
		require.NotEmpty(t, KnownGapGateReason(scenario))
	}
	require.Equal(t,
		map[string]bool{"reality-firefox": true, "reality-safari": true},
		declared,
		"the set of scenarios that reproduce a known dependency limitation changed; if a "+
			"dependency fix landed, delete the entry and run the scenario for real")
}

// TestScenarioFingerprintDefaultIsPinned keeps the assertion in
// TestGeneratedRealityClientConfigJSONShape from degenerating into a tautology.
//
// That test compares the generated JSON against scenario.ClientFingerprint(),
// which is the right OBJECT to compare (a scenario that names one fingerprint
// and a generator that emits another must not both pass) but would also pass if
// the default silently changed to something else. The literal for the default
// therefore lives here, in one place, where changing it is a deliberate edit.
func TestScenarioFingerprintDefaultIsPinned(t *testing.T) {
	t.Parallel()
	require.Equal(t, "chrome", DefaultClientFingerprint)
	require.Equal(t, "chrome", Scenario{}.ClientFingerprint())

	// The axis must be reachable from the table, not merely from the struct:
	// a fingerprint nobody can select is a field, not a scenario dimension.
	byName := make(map[string]string)
	for _, scenario := range Scenarios() {
		byName[scenario.Name] = scenario.ClientFingerprint()
	}
	require.Equal(t, "firefox", byName["reality-firefox"])
	require.Equal(t, "safari", byName["reality-safari"])
	require.Equal(t, "chrome", byName["reality-hybrid"])
}

// TestGenerateRejectsInvalidScenarios pins the generator's fail-closed behaviour.
// A generator that emitted a half-configured scenario would move the failure to
// the reference, where it reads as a protocol error.
func TestGenerateRejectsInvalidScenarios(t *testing.T) {
	t.Parallel()
	base := Scenarios()[0]

	t.Run("encryption without key material", func(t *testing.T) {
		t.Parallel()
		scenario := base
		scenario.Name = "missing-encryption-material"
		scenario.EncryptionAppearance = EncryptionAppearanceNative
		scenario.EncryptionRTT = EncryptionRTTZero
		input := validationInput(t, scenario)
		// The scenario asks for the layer; the input forgot to bring the matched
		// pair. Emitting the config anyway would produce a client that cannot
		// handshake and a reference that cannot decrypt, which is a failure at the
		// far end of a socket instead of in the generator.
		input.Encryption = EncryptionKeyMaterial{}
		_, err := input.Generate()
		require.Error(t, err)
	})

	t.Run("unknown xhttp mode", func(t *testing.T) {
		t.Parallel()
		scenario := base
		scenario.Name = "bad-mode"
		scenario.Transport = TransportXHTTP
		scenario.XHTTPMode = "not-a-mode"
		_, err := validationInput(t, scenario).Generate()
		require.Error(t, err)
	})

	t.Run("xhttp mode without the transport", func(t *testing.T) {
		t.Parallel()
		scenario := base
		scenario.Name = "mode-without-transport"
		scenario.XHTTPMode = XHTTPModeStreamOne
		_, err := validationInput(t, scenario).Generate()
		require.Error(t, err)
	})

	t.Run("h3 packet-up is refused", func(t *testing.T) {
		t.Parallel()
		scenario := base
		scenario.Name = "h3-packet-up"
		scenario.Reality = false
		scenario.PlainTLS = true
		scenario.H3 = true
		scenario.Transport = TransportXHTTP
		scenario.XHTTPMode = XHTTPModePacketUp
		_, err := validationInput(t, scenario).Generate()
		require.Error(t, err)
	})

	t.Run("reality without a key pair", func(t *testing.T) {
		t.Parallel()
		scenario := base
		scenario.Name = "reality-without-keys"
		input := validationInput(t, scenario)
		input.RealityPrivateKey = ""
		input.RealityPublicKey = ""
		_, err := input.Generate()
		require.Error(t, err)
	})
}

// TestEncryptionSpecRejectsHalfConfiguration covers the scenario-level helper
// directly, because it is what decides whether the layer is in play at all.
func TestEncryptionSpecRejectsHalfConfiguration(t *testing.T) {
	t.Parallel()
	_, err := Scenario{Name: "appearance-only", EncryptionAppearance: EncryptionAppearanceNative}.EncryptionSpec()
	require.Error(t, err)
	_, err = Scenario{Name: "rtt-only", EncryptionRTT: EncryptionRTTZero}.EncryptionSpec()
	require.Error(t, err)
	_, err = Scenario{
		Name:                 "unknown-appearance",
		EncryptionAppearance: "plaid",
		EncryptionRTT:        EncryptionRTTZero,
	}.EncryptionSpec()
	require.Error(t, err)
	spec, err := Scenario{
		Name:                 "1rtt",
		EncryptionAppearance: EncryptionAppearanceRandom,
		EncryptionRTT:        EncryptionRTTOne,
	}.EncryptionSpec()
	require.NoError(t, err)
	require.Equal(t, "random.1rtt", spec)
}

// TestReferenceVersionGateIsCorrect is the pure-function half of the classical/
// hybrid split.
//
// It runs by default, with no reference installed, and it is the only test that
// can: the split is a claim about which reference versions accept which greeting,
// and encoding it in a skip decision means it must be right even when nothing is
// installed to check it against.
func TestReferenceVersionGateIsCorrect(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		version   string
		keyShare  string
		supported bool
	}{
		{"26.9.8", RealityKeyShareClassical, false},
		{"26.9.8", RealityKeyShareHybrid, true},
		{"26.8.0", RealityKeyShareClassical, true},
		{"26.8.0", RealityKeyShareHybrid, false},
		{"1.8.24", RealityKeyShareClassical, true},
		{"1.8.24", RealityKeyShareHybrid, false},
		{"27.0.0", RealityKeyShareClassical, false},
		{"27.0.0", RealityKeyShareHybrid, true},
		{"", RealityKeyShareClassical, true},
		{"", RealityKeyShareHybrid, true},
		{"25.8.3", "", true},
		{"27.1.2", "", true},
	} {
		supported, reason := RealityKeyShareSupport(testCase.version, testCase.keyShare)
		require.Equal(t, testCase.supported, supported,
			"version %q key_share %q", testCase.version, testCase.keyShare)
		if !supported {
			require.NotEmpty(t, reason, "an unsupported combination must explain itself")
		}
	}
	require.Equal(t, -1, compareVersions("26.8.0", "26.9.8"))
	require.Equal(t, 0, compareVersions("26.9.8", "26.9.8"))
	require.Equal(t, 1, compareVersions("27.0.0", "26.9.8"))
	require.Equal(t, "25.8.3", parseReferenceVersion("Xray 25.8.3 (go1.24.0 linux/amd64)"))
	require.Equal(t, "26.9.8", parseReferenceVersion("26.9.8"))
	require.Equal(t, "", parseReferenceVersion("no version here"))
}

// TestVlessEncOutputParsing pins the key-material parser, which is the one piece
// of the live path that can be exercised without a reference binary: its output
// shape is a property of the installed build, so it has to tolerate both the
// documented JSON and the line form the shipping generator actually prints.
func TestVlessEncOutputParsing(t *testing.T) {
	t.Parallel()
	clientSpec, serverSpec, err := parseVlessEncOutput(`{"encryption":"enc","decryption":"dec"}`)
	require.NoError(t, err)
	require.Equal(t, "enc", clientSpec)
	require.Equal(t, "dec", serverSpec)

	clientSpec, serverSpec, err = parseVlessEncOutput("banner line\n" +
		"{\n  \"decryption\": \"dec2\",\n  \"encryption\": \"enc2\"\n}\ntrailing line\n")
	require.NoError(t, err)
	require.Equal(t, "enc2", clientSpec)
	require.Equal(t, "dec2", serverSpec)

	_, _, err = parseVlessEncOutput(`{"encryption":"enc"}`)
	require.Error(t, err)

	// The shape the SHIPPING generator prints: no JSON at all, two complete pairs under their own
	// headers, and the instruction not to mix them. This is the shape that made the encryption
	// scenarios skip with `invalid character 'C' looking for beginning of value`, which reads as a
	// harness problem only because it is one.
	clientSpec, serverSpec, err = parseVlessEncOutput(
		"Choose one Authentication to use, do not mix them. Ephemeral key exchange is Post-Quantum safe anyway.\n" +
			"\n" +
			"Authentication: X25519, not Post-Quantum\n" +
			"\"decryption\": \"mlkem768x25519plus.native.600s.x25519-decryption\"\n" +
			"\"encryption\": \"mlkem768x25519plus.native.0rtt.x25519-encryption\"\n" +
			"\n" +
			"Authentication: ML-KEM-768, Post-Quantum\n" +
			"\"decryption\": \"mlkem768x25519plus.native.600s.mlkem-decryption\"\n" +
			"\"encryption\": \"mlkem768x25519plus.native.0rtt.mlkem-encryption\"\n")
	require.NoError(t, err)
	require.Equal(t, "mlkem768x25519plus.native.0rtt.x25519-encryption", clientSpec,
		"the returned pair is one block's, not one half of each")
	require.Equal(t, "mlkem768x25519plus.native.600s.x25519-decryption", serverSpec)

	// A decryptor from one block and an encryptor from the other are two different key materials.
	// Returning them as a pair would move the failure to the reference, where it surfaces as an
	// opaque decryption error, so the split has to be an error here instead.
	_, _, err = parseVlessEncOutput(
		"Authentication: X25519, not Post-Quantum\n" +
			"\"encryption\": \"mlkem768x25519plus.native.0rtt.only-an-encryptor\"\n" +
			"\n" +
			"Authentication: ML-KEM-768, Post-Quantum\n" +
			"\"decryption\": \"mlkem768x25519plus.native.600s.only-a-decryptor\"\n")
	require.Error(t, err)

	// The unquoted spelling of the same shape, which costs nothing to accept.
	clientSpec, serverSpec, err = parseVlessEncOutput("encryption=enc3\ndecryption=dec3\n")
	require.NoError(t, err)
	require.Equal(t, "enc3", clientSpec)
	require.Equal(t, "dec3", serverSpec)

	_, _, err = parseVlessEncOutput("no json at all")
	require.Error(t, err)
}

// TestGateMessagesExplainHowToEnable is the regression guard for the only text a
// maintainer sees when nothing runs.
//
// The default run produces ten SKIP lines; if those lines do not name both halves
// of the gate and the exact command, the stand is effectively undiscoverable.
func TestGateMessagesExplainHowToEnable(t *testing.T) {
	t.Parallel()
	buildTagReason := LiveInteropGateReason(false, "")
	require.Contains(t, buildTagReason, LiveInteropBuildTag)
	require.Contains(t, buildTagReason, LiveInteropEnvVar+"=1")
	require.Contains(t, buildTagReason, "XRAY_BINARY")
	require.Contains(t, buildTagReason, "liveinterop")
	require.Contains(t, buildTagReason, "./interop/")

	envReason := LiveInteropGateReason(true, "")
	require.Contains(t, envReason, LiveInteropEnvVar+" is not set to 1")
	require.Contains(t, envReason, LiveInteropEnableCommand)

	require.Empty(t, LiveInteropGateReason(true, "1"))
	// Any value other than "1" is off; a half-truth such as "yes" must not enable
	// a suite that spawns processes.
	require.NotEmpty(t, LiveInteropGateReason(true, "yes"))

	require.Contains(t, H3GateReason(), H3EnableEnvVar+"=1")
	require.Contains(t, H3GateReason(), LiveInteropEnvVar+"=1")
	require.Contains(t, H3GateReason(), LiveInteropBuildTag)

	// The known-gap gate. Its whole job is to keep an expected-to-fail scenario
	// out of the default matrix while leaving the reproduction reachable, so the
	// properties worth pinning are: it is closed by default, it names the
	// environment variable that opens it, it repeats the limitation it is gating,
	// and it points at the test that fails when the limitation changes. A skip
	// that lost any of those is a skip that reads as "nothing to see here".
	gapScenario := Scenario{Name: "reality-gap", Fingerprint: "firefox", KnownGap: "a named limitation"}
	require.Contains(t, KnownGapGateReason(gapScenario), KnownGapEnableEnvVar+"=1")
	require.Contains(t, KnownGapGateReason(gapScenario), "EXPECTED TO FAIL")
	require.Contains(t, KnownGapGateReason(gapScenario), gapScenario.KnownGap)
	require.Contains(t, KnownGapGateReason(gapScenario), "reality_fingerprint_register_test.go")
	require.Empty(t, KnownGapGateReason(Scenario{Name: "no-gap"}))

	reason := LiveInteropCapabilityReason(Scenario{Name: "x", Transport: TransportXHTTP, H3: true})
	if buildHasUTLS && buildHasXHTTP && buildHasQUIC {
		require.Empty(t, reason)
	} else {
		require.Contains(t, reason, "this build lacks")
	}
}

// TestBoxConstructionAcceptsGeneratedConfigs is the strongest check available
// without a reference: the generated client config must survive box.New with the
// registries this binary actually has.
//
// It is skipped, not failed, when the build lacks the tags a scenario needs,
// because the failure would otherwise be "unknown transport type: xhttp" — a
// build configuration message masquerading as an interop result.
func TestBoxConstructionAcceptsGeneratedConfigs(t *testing.T) {
	t.Parallel()
	for _, scenario := range Scenarios() {
		scenario := scenario
		t.Run(scenario.Name, func(t *testing.T) {
			t.Parallel()
			if reason := LiveInteropCapabilityReason(scenario); reason != "" {
				t.Skip(reason)
			}
			if scenario.Transport == TransportXHTTP {
				if reason := XHTTPOptionLayerSkipReason(); reason != "" {
					t.Skip(reason)
				}
			}
			input := validationInput(t, scenario)
			pair, err := input.Generate()
			require.NoError(t, err)
			parsed, err := badjson.UnmarshalExtendedContext[option.Options](RegistryContext(), pair.ClientConfig)
			require.NoError(t, err)
			instance, err := box.New(box.Options{
				Context: RegistryContext(),
				Options: parsed,
			})
			require.NoError(t, err, "box.New must accept %s", pair.ClientConfigPath)
			require.NoError(t, instance.Close())
		})
	}
}

// TestOptionLayerHandlesTheXHTTPTransport guards the one production defect this
// stand found in this repository rather than in the reference: the option layer
// could not load an `xhttp` transport from JSON at all.
//
// It passes both BEFORE and AFTER the fix, which is the point. Before, it pinned
// the exact `unknown transport type: xhttp` rejection so a different failure
// could not hide behind it. Now it reports that the gap is closed and the xhttp
// scenarios are being parsed for real. A test that merely asserted "the config
// does not parse" would pass vacuously on any unrelated breakage, and one that
// asserted the rejection would have failed the moment the case was added.
func TestOptionLayerHandlesTheXHTTPTransport(t *testing.T) {
	t.Parallel()
	// The control first. If the same config shape with a transport the option
	// layer knows does not parse, then the xhttp probe below is measuring
	// something else entirely and its result means nothing.
	require.NoError(t, NonXHTTPTransportParseError(),
		"the control probe must parse, otherwise the xhttp probe is failing for an unrelated reason")

	parseErr := XHTTPTransportParseError()
	if parseErr == nil {
		t.Log("the option layer accepts an `xhttp` transport: the xhttp scenarios round-trip " +
			"through the parser and through box.New, and nothing skips on this probe")
		return
	}
	require.Contains(t, parseErr.Error(), "unknown transport type: xhttp",
		"the option layer rejected the xhttp transport for a reason other than the pinned gap; "+
			"this is a NEW failure and must be investigated rather than attributed to the known one")
	t.Logf("KNOWN GAP (pinned): %v\n"+
		"option.V2RayTransportOptions.UnmarshalJSON has no xhttp case; a JSON config selecting "+
		"`type: xhttp` is rejected before box.New. Reported to the option/** owner.", parseErr)
}

// lastSpecSegment returns the final dot-separated segment of an encryption spec,
// which is its key material.
func lastSpecSegment(t *testing.T, spec string) string {
	t.Helper()
	segments := strings.Split(spec, ".")
	require.GreaterOrEqual(t, len(segments), 4, "an encryption spec must be method.appearance.rtt.key..., got %q", spec)
	return segments[len(segments)-1]
}

// deriveRealityPublicKey recomputes the X25519 public half of a base64url
// private key, the same way both implementations do.
func deriveRealityPublicKey(privateKey string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		return "", err
	}
	parsed, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(parsed.PublicKey().Bytes()), nil
}

// The generic-JSON helpers below keep the shape assertions readable without
// pulling in a JSON-path dependency: go.mod is frozen for this task.
func decodeJSONObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	return decoded
}

func asObject(t *testing.T, value any, path string) map[string]any {
	t.Helper()
	object, isObject := value.(map[string]any)
	require.True(t, isObject, "%s must be a JSON object, got %T", path, value)
	return object
}

func jsonArrayAt(t *testing.T, object map[string]any, key string) []any {
	t.Helper()
	value, loaded := object[key]
	require.True(t, loaded, "%s must be present", key)
	array, isArray := value.([]any)
	require.True(t, isArray, "%s must be a JSON array, got %T", key, value)
	return array
}

func jsonStringAt(t *testing.T, object map[string]any, key string) string {
	t.Helper()
	value, loaded := object[key]
	require.True(t, loaded, "%s must be present", key)
	text, isString := value.(string)
	require.True(t, isString, "%s must be a JSON string, got %T", key, value)
	return text
}

func jsonNumberAt(t *testing.T, object map[string]any, key string) float64 {
	t.Helper()
	value, loaded := object[key]
	require.True(t, loaded, "%s must be present", key)
	number, isNumber := value.(float64)
	require.True(t, isNumber, "%s must be a JSON number, got %T", key, value)
	return number
}
