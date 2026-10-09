// Package interop is a repeatable reference-interop stand for the three
// capabilities this fork added on top of upstream sing-box and has never
// verified against a reference implementation: the REALITY hybrid/classical
// key_share policy, the VLESS application-layer post-quantum encryption layer,
// and the XHTTP client transport (including Vision over both).
//
// # Why the stand exists at all
//
// Everything in that list is unit-tested, and a suite of mocks can agree with
// itself about a wire format and still be wrong. The only artefact that can
// falsify the wire format is a real peer: a reference Xray-core binary on the
// other end of a socket. Nothing in this package stubs that peer — the
// generator emits a real Xray configuration, the orchestration starts the real
// binary, and the live tests move real bytes through it.
//
// # Why the live half is gated twice
//
// This environment has no external network and no container runtime, so the
// live half cannot run here and must never be mistaken for having run. It is
// therefore behind BOTH a build tag (`liveinterop`) and an environment
// variable (`RUN_LIVE_XRAY_INTEROP=1`), and when either is missing every live
// test skips with the exact command that would enable it. The generator and its
// validation tests — the half that CAN run anywhere — are not gated at all, so
// `go test ./interop/` is always meaningful: it proves the configurations we
// hand the reference are the configurations we intended.
//
// # The honest status line
//
// REFERENCE INTEROP: HARNESS ONLY — NOT RUN. See README.md.
package interop

import (
	E "github.com/sagernet/sing/common/exceptions"
)

// Scenario names one client↔reference combination. Each field is deliberately
// independent rather than an enum of pre-baked combinations: the point of the
// stand is the cross product (REALITY × encryption × Vision × transport), and a
// matrix expressed as one flag per axis is the only form in which a missing cell
// is visible.
type Scenario struct {
	// Name is the stable identifier used in test names, artifact file names and
	// failure messages. It is the handle a maintainer greps for in CI.
	Name string

	// Reality selects a REALITY security layer. Every scenario in this stand
	// except the plain-TLS H3 one sets it, because REALITY is what this fork's
	// compatibility work was about.
	Reality bool

	// KeyShare is the REALITY `key_share` policy: "classical", "hybrid", or ""
	// for "as the configured fingerprint carries it". The empty value is a real
	// case, not an absent one: it is the default and it must serialize as an
	// absent field, so the validation tests assert exactly that.
	//
	// The two explicit values map to two different reference versions and cannot
	// both be satisfied by one binary: `classical` is only accepted by Xray
	// below v26.9.8 and `hybrid` is required by v26.9.8 and later. Which
	// scenario runs is therefore decided against the reference's own version
	// string, and the impossible one skips with that reason rather than failing
	// as if the client were broken.
	KeyShare string

	// EncryptionAppearance is the encryption layer's wire appearance:
	// "native", "xorpub" or "random". Empty leaves the layer off.
	EncryptionAppearance string
	// EncryptionRTT is "0rtt" or "1rtt". Empty leaves the layer off.
	EncryptionRTT string

	// Vision adds `flow: xtls-rprx-vision`. It is only meaningful with a TLS or
	// REALITY layer beneath, which every scenario here has.
	Vision bool

	// Transport is the V2Ray transport type: "" (plain TCP) or "xhttp". Only
	// xhttp is exercised, because it is the transport this fork added; the
	// pre-existing ones are not in question.
	Transport string

	// XHTTPMode is the XHTTP mode: "auto", "packet-up", "stream-up" or
	// "stream-one". Empty with Transport == "xhttp" means the transport default.
	XHTTPMode string

	// Fingerprint is the uTLS fingerprint the client presents, spelled the way
	// the configuration spells it. Empty means the stand's default,
	// DefaultClientFingerprint, which is what every scenario used before this
	// axis existed.
	//
	// It is a scenario field rather than a constant because the fingerprint
	// decides the ClientHello, and the ClientHello is what a REALITY reference
	// verifies: a reference that requires the post-quantum hybrid key share is
	// satisfiable by some presets and not by others, so "which fingerprint" is
	// part of the scenario rather than a property of the stand.
	Fingerprint string

	// KnownGap, when non-empty, says this scenario reproduces a limitation that is
	// known to be unfixed in the PINNED dependency, so it is expected to FAIL
	// against a reference that exercises the gap. It states the limitation and
	// what it costs a user; the gate that decides whether the scenario runs reads
	// this field (see KnownGapGateReason).
	//
	// The alternative — leaving the scenario in the default matrix — makes a leg
	// red for a reason no code in this repository can fix, which is how a real
	// regression gets ignored. The alternative in the other direction — deleting
	// it — throws away the only executable reproduction of the gap.
	KnownGap string

	// PlainTLS selects an ordinary TLS security layer instead of REALITY. Only
	// HTTP/3 needs it: REALITY is a TCP construction, so an H3 scenario cannot
	// carry it and the client replaces a REALITY ALPN of ["h3"] with ["h2"].
	PlainTLS bool

	// H3 declares that the client is expected to speak XHTTP over HTTP/3. It is
	// a separate flag from PlainTLS so that a future REALITY-over-QUIC variant
	// does not silently inherit the TLS certificate wiring.
	H3 bool

	// Note records what a maintainer must know before trusting a failure in this
	// scenario. It is intentionally prose: a scenario whose failure is expected
	// on a given reference version is a near-miss for a false bug report.
	Note string
}

// EncryptionEnabled reports whether the VLESS encryption layer is configured.
func (s Scenario) EncryptionEnabled() bool {
	return s.EncryptionAppearance != "" || s.EncryptionRTT != ""
}

// DefaultClientFingerprint is the uTLS fingerprint a scenario gets when it does
// not name one.
//
// It is a constant with a test that pins it, rather than an inline literal at
// the point of use, because the value is a claim about what every pre-existing
// scenario exercises: changing it would silently move the whole matrix onto a
// different ClientHello.
const DefaultClientFingerprint = "chrome"

// ClientFingerprint resolves the uTLS fingerprint the scenario configures.
func (s Scenario) ClientFingerprint() string {
	if s.Fingerprint == "" {
		return DefaultClientFingerprint
	}
	return s.Fingerprint
}

// EncryptionSpec builds the `<appearance>.<rtt>` prefix of the encryption
// string. It returns an error for a half-configured layer, because a scenario
// with an RTT but no appearance (or the reverse) would produce a config that the
// client parser rejects for a reason that has nothing to do with the reference.
func (s Scenario) EncryptionSpec() (string, error) {
	if !s.EncryptionEnabled() {
		return "", nil
	}
	if s.EncryptionAppearance == "" {
		return "", E.New("scenario ", s.Name, ": encryption RTT set without an appearance")
	}
	if s.EncryptionRTT == "" {
		return "", E.New("scenario ", s.Name, ": encryption appearance set without an RTT")
	}
	switch s.EncryptionAppearance {
	case EncryptionAppearanceNative, EncryptionAppearanceXorPub, EncryptionAppearanceRandom:
	default:
		return "", E.New("scenario ", s.Name, ": unknown encryption appearance ", s.EncryptionAppearance)
	}
	switch s.EncryptionRTT {
	case EncryptionRTTZero, EncryptionRTTOne:
	default:
		return "", E.New("scenario ", s.Name, ": unknown encryption RTT ", s.EncryptionRTT)
	}
	return s.EncryptionAppearance + "." + s.EncryptionRTT, nil
}

// EncryptionAppearance enumerates the encryption layer's wire appearances, in
// the vocabulary of protocol/vless/encryption.
const (
	EncryptionAppearanceNative = "native"
	EncryptionAppearanceXorPub = "xorpub"
	EncryptionAppearanceRandom = "random"
)

// EncryptionRTT enumerates the encryption layer's round-trip modes.
const (
	EncryptionRTTZero = "0rtt"
	EncryptionRTTOne  = "1rtt"
)

// XHTTP mode names, kept local so a scenario table cannot drift from the strings
// the transport actually switches on.
const (
	XHTTPModeAuto      = "auto"
	XHTTPModePacketUp  = "packet-up"
	XHTTPModeStreamUp  = "stream-up"
	XHTTPModeStreamOne = "stream-one"
)

// TransportXHTTP is the transport type string registered by
// transport/v2rayxhttp. Duplicated here on purpose: the generator must emit the
// JSON spelling, and a rename in the transport should break these tests rather
// than pass unnoticed.
const TransportXHTTP = "xhttp"

// RealityKeyShareClassical and RealityKeyShareHybrid mirror
// constant.RealityKeyShare*; they are spelled out so the generated JSON is
// asserted against literals rather than against the constant the implementation
// also reads.
const (
	RealityKeyShareClassical = "classical"
	RealityKeyShareHybrid    = "hybrid"
)

// Scenarios is the matrix the stand covers, in the order the tests run. The
// order is the priority order: the combination scenario is last because it is
// the one the fork's own engineering report names as the largest gap, and a
// maintainer reading a failing run top-to-bottom should reach it last, after the
// layers it composes have each passed alone.
func Scenarios() []Scenario {
	return []Scenario{
		{
			Name:     "reality-classical",
			Reality:  true,
			KeyShare: RealityKeyShareClassical,
			Note: "REALITY with the hybrid key share stripped from the ClientHello. " +
				"ONLY a reference Xray below v26.9.8 accepts this; on v26.9.8 and later the " +
				"server answers with the camouflage site and the client reports a REALITY " +
				"verification failure. The test skips on a newer reference, and the skip " +
				"message says why.",
		},
		{
			Name:     "reality-hybrid",
			Reality:  true,
			KeyShare: RealityKeyShareHybrid,
			Note: "REALITY with X25519MLKEM768 required. Requires a reference Xray at or above " +
				"v26.9.8, which is the release that made the hybrid share mandatory. The test " +
				"skips on an older reference.",
		},
		{
			Name:        "reality-firefox",
			Reality:     true,
			Fingerprint: "firefox",
			KnownGap: "the pinned metacubex/utls v1.8.7 resolves `firefox` to Firefox 120, whose " +
				"ClientHello carries no X25519MLKEM768 key share. A REALITY reference at or " +
				"after Xray v26.9.8 requires that share, so the server answers with the " +
				"camouflage site and the client reports a verification failure that is " +
				"indistinguishable from a wrong public key. Workaround: `fingerprint: chrome`. " +
				"Fixed by the three upstream commits recorded in " +
				"docs/fork/utls-firefox148-safari263.patch",
			Note: "REALITY with the Firefox fingerprint and NO explicit key_share, which is the " +
				"configuration a user gets from `fingerprint: firefox` alone. It is the " +
				"fingerprint axis rather than a new protocol combination: the preset decides " +
				"whether the greeting carries X25519MLKEM768, and a reference at or above " +
				"v26.9.8 requires that share. A failure here is a statement about the pinned " +
				"uTLS preset, not about this fork's REALITY code, which is why the test " +
				"records the preset the pinned module resolves the name to.",
		},
		{
			Name:        "reality-safari",
			Reality:     true,
			Fingerprint: "safari",
			KnownGap: "the pinned metacubex/utls v1.8.7 resolves `safari` to Safari 16.0, whose " +
				"ClientHello carries no X25519MLKEM768 key share, with the same consequence " +
				"as reality-firefox. Workaround: `fingerprint: chrome`. Fixed by the same " +
				"three upstream commits",
			Note: "REALITY with the Safari fingerprint and no explicit key_share. The same " +
				"fingerprint axis as reality-firefox and the same reference requirement; it is " +
				"a separate scenario because the two names resolve to two different presets in " +
				"the pinned uTLS module and one of them can carry the hybrid share while the " +
				"other cannot.",
		},
		{
			Name:    "reality-encryption",
			Reality: true,
			// No explicit key_share: this scenario is the assertion that an absent
			// policy stays absent on the wire, and that the Chrome fingerprint then
			// carries the hybrid share on its own.
			EncryptionAppearance: EncryptionAppearanceNative,
			EncryptionRTT:        EncryptionRTTZero,
			Note: "REALITY plus the VLESS application-layer encryption. The reference's " +
				"decryption key must come from the reference itself (see keymaterial.go); a " +
				"synthetic key pair is enough to validate the config but not to run live.",
		},
		{
			Name:                 "reality-encryption-vision",
			Reality:              true,
			KeyShare:             RealityKeyShareHybrid,
			EncryptionAppearance: EncryptionAppearanceNative,
			EncryptionRTT:        EncryptionRTTZero,
			Vision:               true,
			Note: "The encryption layer with `flow: xtls-rprx-vision` on top. Vision finds " +
				"the TLS-shaped connection beneath it through the layer's registry entry; " +
				"without the encryption layer this combination has no registered connection " +
				"type to hand Vision and fails in the client, before the reference sees " +
				"anything.",
		},
		{
			Name:      "reality-xhttp-stream-one",
			Reality:   true,
			KeyShare:  RealityKeyShareHybrid,
			Transport: TransportXHTTP,
			XHTTPMode: XHTTPModeStreamOne,
			Note: "REALITY resolves the XHTTP client to HTTP/2 regardless of the configured " +
				"ALPN, which is what Xray does. No encryption and no Vision, so this is the " +
				"transport alone.",
		},
		{
			Name:                 "reality-encryption-vision-xhttp-stream-one",
			Reality:              true,
			KeyShare:             RealityKeyShareHybrid,
			EncryptionAppearance: EncryptionAppearanceNative,
			EncryptionRTT:        EncryptionRTTZero,
			Vision:               true,
			Transport:            TransportXHTTP,
			XHTTPMode:            XHTTPModeStreamOne,
			Note: "THE PRIORITY SCENARIO: every layer at once. Vision over XHTTP can only " +
				"work at all because the encryption layer registers a TLS-shaped connection " +
				"underneath it; the ordering of the layers is therefore part of what this " +
				"scenario asserts, not an implementation detail.",
		},
		{
			Name:      "reality-xhttp-packet-up",
			Reality:   true,
			KeyShare:  RealityKeyShareHybrid,
			Transport: TransportXHTTP,
			XHTTPMode: XHTTPModePacketUp,
			Note: "XHTTP packet-up: a long GET download stream plus one sequenced POST per " +
				"uplink write.",
		},
		{
			Name:      "reality-xhttp-stream-up",
			Reality:   true,
			KeyShare:  RealityKeyShareHybrid,
			Transport: TransportXHTTP,
			XHTTPMode: XHTTPModeStreamUp,
			Note: "XHTTP stream-up: one streamed upload POST plus a separate long GET " +
				"download stream.",
		},
		{
			Name:      "reality-xhttp-auto",
			Reality:   true,
			KeyShare:  RealityKeyShareHybrid,
			Transport: TransportXHTTP,
			XHTTPMode: XHTTPModeAuto,
			Note: "XHTTP mode `auto` resolves to stream-one in front of REALITY, matching " +
				"Xray. Asserting it against the reference is what keeps that resolution " +
				"honest; the mode the client picks is observable from the reference log.",
		},
		{
			Name:      "tls-xhttp-h3-stream-one",
			PlainTLS:  true,
			Transport: TransportXHTTP,
			XHTTPMode: XHTTPModeStreamOne,
			H3:        true,
			Note: "XHTTP over HTTP/3 needs ordinary TLS: REALITY is a TCP construction and " +
				"the client rewrites a REALITY ALPN of [\"h3\"] to [\"h2\"]. This scenario is " +
				"additionally gated by INTEROP_ENABLE_H3 because XHTTP-over-H3 support in the " +
				"reference binary is a property of which Xray build is installed, and a " +
				"harness cannot probe a QUIC listener's readiness with a TCP connect.",
		},
	}
}

// ScenarioByName returns the scenario with the given name.
func ScenarioByName(name string) (Scenario, error) {
	for _, scenario := range Scenarios() {
		if scenario.Name == name {
			return scenario, nil
		}
	}
	return Scenario{}, E.New("unknown interop scenario: ", name)
}

// ScenarioNames returns the scenario names, for -run filters and logs.
func ScenarioNames() []string {
	all := Scenarios()
	names := make([]string, 0, len(all))
	for _, scenario := range all {
		names = append(names, scenario.Name)
	}
	return names
}

// Flow returns the VLESS flow the scenario configures, empty when Vision is off.
func (s Scenario) Flow() string {
	if s.Vision {
		return "xtls-rprx-vision"
	}
	return ""
}
