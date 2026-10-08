package interop

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// Key material for the two layers that need a matched pair across the two
// implementations.
//
// # REALITY
//
// REALITY is asymmetric and the two sides need different halves of one X25519
// pair: the reference server carries the private key, this fork's client carries
// the public key. Generating the pair here, in one place, is what makes the two
// generated files a *pair* rather than two configs that merely look similar; the
// validation tests derive the public half back out of the private half and
// compare it with what the client file says, so a swap (private in the client)
// cannot pass.
//
// # VLESS encryption
//
// The encryption layer's keys are NOT symmetric with REALITY's and, more
// importantly, the client half of this fork cannot mint a pair the reference
// would accept: the server half (`decryption`) lives only in the reference. So
// there are two providers, and which one is in use is recorded on the material
// itself:
//
//   - the REFERENCE provider reads a matched pair from the environment, or asks
//     the reference binary to mint one (`xray vlessenc`). This is the only
//     material a live run may use.
//   - the SYNTHETIC provider mints an X25519 pair in Go. It exists so the
//     configuration generator and its validation tests can run in an
//     environment with no reference binary at all. It is deliberately unable to
//     masquerade as live material: LiveUsable() is false, and the live harness
//     refuses it.
//
// The second provider is the reason this package is useful here at all, and the
// distinction between the two is the reason it is not lying.

// EncryptionKeySource identifies where a pair of encryption specs came from.
type EncryptionKeySource string

const (
	// EncryptionKeySourceEnv is a pair supplied by the operator through
	// XRAY_VLESS_ENCRYPTION / XRAY_VLESS_DECRYPTION.
	EncryptionKeySourceEnv EncryptionKeySource = "env"
	// EncryptionKeySourceReference is a pair minted by the reference binary.
	EncryptionKeySourceReference EncryptionKeySource = "reference vlessenc"
	// EncryptionKeySourceSynthetic is a Go-minted pair for config validation
	// only. It must never reach a live reference.
	EncryptionKeySourceSynthetic EncryptionKeySource = "synthetic (NOT live-usable)"
)

// The two environment variables carrying a matched encryption pair. They hold
// whole spec strings, not bare keys, because the appearance and RTT mode are part
// of the reference's own choice and the two strings must agree on both.
const (
	EncryptionEnvClient = "XRAY_VLESS_ENCRYPTION"
	EncryptionEnvServer = "XRAY_VLESS_DECRYPTION"
)

// ErrNoReferenceKeyMaterial reports that no pair of encryption specs usable
// against a real reference could be obtained. The live harness turns this into a
// SKIP with the exact remedy, never into a failure: an operator who has not
// provisioned key material has not found a bug in this fork.
var ErrNoReferenceKeyMaterial = E.New("no reference VLESS encryption key material available")

// EncryptionKeyMaterial is a matched pair of encryption specs: the client
// `encryption` string and the reference `decryption` string.
type EncryptionKeyMaterial struct {
	ClientSpec string
	ServerSpec string
	Source     EncryptionKeySource
}

// LiveUsable reports whether this material may be used against a real reference
// binary. Synthetic material is config-validation material and nothing else.
func (m EncryptionKeyMaterial) LiveUsable() bool {
	return m.Source == EncryptionKeySourceEnv || m.Source == EncryptionKeySourceReference
}

// Explain returns a one-line provenance note for logs and failure messages.
func (m EncryptionKeyMaterial) Explain() string {
	return "encryption key material: " + string(m.Source)
}

// EncryptionSpecPrefix returns the `<method>.<appearance>.<rtt>` prefix of a
// spec string, without the key material.
//
// The live runner logs this because the reference is the authority on which
// appearance and RTT it minted: a scenario NAMED `native.0rtt` that the
// reference answered with a different mode would otherwise be silently
// mislabelled in a passing run, and the label is the only record of what was
// actually verified.
func EncryptionSpecPrefix(spec string) string {
	parts := strings.SplitN(spec, ".", 4)
	if len(parts) < 4 {
		return spec
	}
	return strings.Join(parts[:3], ".")
}

// GenerateRealityKeyPair mints one X25519 pair in the base64url-without-padding
// form both implementations use for REALITY keys, and returns
// (publicKey, privateKey).
func GenerateRealityKeyPair() (string, string, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", E.Cause(err, "generate REALITY X25519 key")
	}
	return base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
		nil
}

// GenerateShortID returns a REALITY short id. 16 lowercase hex characters is the
// form this repository's own REALITY tests use and the form Xray's documentation
// shows; the server accept-list contains exactly this value, so a client that
// sends a different one is answered by the camouflage site, which is the failure
// mode this stand is meant to expose rather than to hide.
func GenerateShortID() string {
	return "0123456789abcdef"
}

// NewSyntheticEncryptionKeyMaterial builds a self-consistent X25519 pair for the
// scenario's declared appearance and RTT, for config validation only.
//
// The X25519 form is used rather than ML-KEM-768 because a 32-byte key is short
// enough to read in a generated file and a diff; the live provider passes the
// reference's own string through verbatim, whatever size it is.
func NewSyntheticEncryptionKeyMaterial(scenario Scenario) (EncryptionKeyMaterial, error) {
	spec, err := scenario.EncryptionSpec()
	if err != nil {
		return EncryptionKeyMaterial{}, err
	}
	if spec == "" {
		return EncryptionKeyMaterial{}, E.New("scenario ", scenario.Name, " does not enable the encryption layer")
	}
	publicKey, privateKey, err := GenerateRealityKeyPair()
	if err != nil {
		return EncryptionKeyMaterial{}, err
	}
	return EncryptionKeyMaterial{
		ClientSpec: "mlkem768x25519plus." + spec + "." + publicKey,
		ServerSpec: "mlkem768x25519plus." + spec + "." + privateKey,
		Source:     EncryptionKeySourceSynthetic,
	}, nil
}

// ReferenceEncryptionKeyMaterial obtains a matched pair that a live run may use:
// the environment first, then the reference binary's own key generator.
//
// The environment wins because it is the only source that survives a reference
// build without a key-gen subcommand, and because an operator who has already
// minted a pair should not have the harness mint a second one behind their back.
// A HALF-set environment is an error rather than a fallback: picking one string
// from the environment and the other from a freshly minted pair would produce
// two specs that cannot possibly agree, and the failure would surface as an
// opaque decryption error at the reference.
func ReferenceEncryptionKeyMaterial(scenario Scenario, referenceBinary string) (EncryptionKeyMaterial, error) {
	if !scenario.EncryptionEnabled() {
		return EncryptionKeyMaterial{}, E.New("scenario ", scenario.Name, " does not enable the encryption layer")
	}
	clientSpec := strings.TrimSpace(os.Getenv(EncryptionEnvClient))
	serverSpec := strings.TrimSpace(os.Getenv(EncryptionEnvServer))
	switch {
	case clientSpec != "" && serverSpec != "":
		return EncryptionKeyMaterial{
			ClientSpec: clientSpec,
			ServerSpec: serverSpec,
			Source:     EncryptionKeySourceEnv,
		}, nil
	case clientSpec != "" || serverSpec != "":
		return EncryptionKeyMaterial{}, E.Cause(ErrNoReferenceKeyMaterial,
			"only one of ", EncryptionEnvClient, " and ", EncryptionEnvServer, " is set; "+
				"a matched pair is required")
	}
	if referenceBinary == "" {
		return EncryptionKeyMaterial{}, E.Cause(ErrNoReferenceKeyMaterial,
			"set ", EncryptionEnvClient, " and ", EncryptionEnvServer,
			", or point XRAY_BINARY at a reference binary with a key generator")
	}
	material, err := vlessEncFromReference(referenceBinary)
	if err != nil {
		return EncryptionKeyMaterial{}, E.Cause(ErrNoReferenceKeyMaterial, err)
	}
	return material, nil
}

// vlessEncFromReference asks the reference binary to mint a matched pair.
//
// The output of the reference's key generator is taken VERBATIM for both specs.
// Re-deriving the appearance/RTT prefix locally would defeat the purpose: the
// reference is the authority on what it will accept, and a scenario that claims
// `native.0rtt` while the reference minted something else would be asserting a
// coincidence.
//
// The parser is deliberately tolerant of surrounding prose because the exact
// output shape is a property of the installed reference build, and a harness
// that only understands one formatting of it would fail for a reason that has
// nothing to do with the protocol.
func vlessEncFromReference(referenceBinary string) (EncryptionKeyMaterial, error) {
	command := exec.Command(referenceBinary, "vlessenc")
	output, err := command.CombinedOutput()
	if err != nil {
		return EncryptionKeyMaterial{}, E.Cause(err, "run `", referenceBinary, " vlessenc`")
	}
	clientSpec, serverSpec, err := parseVlessEncOutput(string(output))
	if err != nil {
		return EncryptionKeyMaterial{}, E.Cause(err, "parse `", referenceBinary, " vlessenc` output")
	}
	return EncryptionKeyMaterial{
		ClientSpec: clientSpec,
		ServerSpec: serverSpec,
		Source:     EncryptionKeySourceReference,
	}, nil
}

// parseVlessEncOutput pulls the encryption/decryption pair out of the reference
// generator's output.
//
// Two shapes are understood, because the shape is a property of the installed
// reference build and a harness that understands only one of them skips the
// encryption scenarios for a reason that has nothing to do with the protocol:
//
//   - a JSON object, or an object embedded in surrounding prose, which is the
//     shape the documentation shows; and
//   - the `"decryption": "..."` / `"encryption": "..."` lines the shipping
//     generator actually prints, under an `Authentication: ...` header.
//
// The second shape is why this function must not simply take the first
// `encryption` and the first `decryption` it can find. The generator prints TWO
// complete pairs - one authenticated with X25519, one with ML-KEM-768 - and says
// in as many words to choose one and not mix them. Both are internally matched
// and either is accepted by the reference, but a pair assembled from one half of
// each would describe two different key materials, and the failure would surface
// as an opaque decryption error at the reference. The line scanner therefore
// pairs the halves of ONE block.
func parseVlessEncOutput(raw string) (string, string, error) {
	type pair struct {
		Encryption string `json:"encryption"`
		Decryption string `json:"decryption"`
	}
	candidates := []string{strings.TrimSpace(raw)}
	if start, end := strings.Index(raw, "{"), strings.LastIndex(raw, "}"); start >= 0 && end > start {
		candidates = append(candidates, raw[start:end+1])
	}
	var lastErr error
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		var parsed pair
		if err := json.Unmarshal([]byte(candidate), &parsed); err != nil {
			lastErr = err
			continue
		}
		if parsed.Encryption == "" || parsed.Decryption == "" {
			lastErr = E.New("output is missing `encryption` or `decryption`")
			continue
		}
		return parsed.Encryption, parsed.Decryption, nil
	}
	if encryption, decryption, found := parseVlessEncSpecLines(raw); found {
		return encryption, decryption, nil
	}
	if lastErr == nil {
		lastErr = E.New("no JSON object found in output")
	}
	return "", "", lastErr
}

// parseVlessEncSpecLines returns the first COMPLETE pair of spec lines from ONE block.
//
// A non-blank line that is not a spec line ends the block in progress - the `Authentication: ...`
// headers and the banner do exactly that - so a build that prints the two authentication modes as
// separate blocks cannot have its halves crossed, and a lone `encryption` line with no partner is
// reported as "no pair" rather than silently paired with the next block's `decryption`.
func parseVlessEncSpecLines(raw string) (string, string, bool) {
	var encryption, decryption string
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, isSpecLine := parseVlessEncSpecLine(line)
		if !isSpecLine {
			encryption, decryption = "", ""
			continue
		}
		switch key {
		case "encryption":
			encryption = value
		case "decryption":
			decryption = value
		default:
			encryption, decryption = "", ""
			continue
		}
		if encryption != "" && decryption != "" {
			return encryption, decryption, true
		}
	}
	return "", "", false
}

// parseVlessEncSpecLine recognises `"encryption": "<spec>"`, and the unquoted
// `encryption: <spec>` / `encryption=<spec>` spellings, which cost nothing to accept.
//
// A spec is one whitespace-free token, and that is what distinguishes it from the prose around it:
// `Authentication: X25519, not Post-Quantum` also has a colon, and pairing the word after it with a
// real spec would produce a key the reference cannot parse.
func parseVlessEncSpecLine(line string) (string, string, bool) {
	separator := strings.IndexAny(line, ":=")
	if separator < 0 {
		return "", "", false
	}
	key := strings.Trim(strings.TrimSpace(line[:separator]), `"'`)
	value := strings.Trim(strings.TrimSpace(line[separator+1:]), `"',`)
	value = strings.TrimSpace(value)
	if key == "" || value == "" || strings.ContainsAny(value, " \t") {
		return "", "", false
	}
	return strings.ToLower(key), value, true
}
