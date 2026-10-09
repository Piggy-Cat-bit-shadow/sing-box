//go:build with_utls

package tls

import (
	"net"
	"sort"
	"testing"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// The REALITY fingerprint register.
//
// # What it measures
//
// A REALITY reference at or after Xray v26.9.8 (this fork's compatibility target — see
// docs/fork/reality-interop-fix-report.md) derives the REALITY auth key from the X25519MLKEM768
// hybrid key share and answers a greeting that does not carry one with the camouflage site. The
// client's symptom is a verification failure, which is the same symptom a wrong public key
// produces. Whether a given `utls.fingerprint` can therefore complete a REALITY handshake at all
// is decided by the PRESET the pinned uTLS module resolves the name to — a property of a
// dependency, not of this repository, and one that no test of this fork's own REALITY code can
// see.
//
// The live matrix measures the consequence end to end (test/interop: reality-firefox and
// reality-safari fail against Xray v26.9.30 while reality-hybrid, which is Chrome, passes). This
// file measures the CAUSE, locally and deterministically, so the failure can be attributed without
// a reference binary, and so a change in the dependency is reported here rather than discovered by
// a user.
//
// # Why a register and not a skip
//
// Measured on the pin (github.com/metacubex/utls v1.8.7), every fingerprint except Chrome resolves
// to a pre-ML-KEM preset: Firefox 120, Safari 16.0, Edge 85, iOS 14, QQBrowser 11.1. Those names
// are ACCEPTED by the configuration parser and by this client, and they cannot complete a REALITY
// handshake against a current reference. A skip would read as "not applicable"; the truth is "known
// broken, with a named cause and a named fix".
//
// The register is therefore a two-way gate, in the same shape as the libbox ABI register:
//
//   - if a preset GAINS the hybrid share — most directly by moving the pin to a revision that
//     carries refraction-networking/utls fc716b2+ddebe39+aa6edf4 (Firefox 148, Safari 26.3) — then
//     this test fails, and the failure message is the instruction to delete the entry and re-run
//     the live fingerprint scenarios;
//   - if a preset LOSES a share that an entry claims, this test fails as well, because that would
//     mean a fingerprint this fork tells users to use is not the greeting they would get.
//
// Every name the configuration accepts must appear here, and that property is enforced against the
// table itself (uTLSFingerprints) rather than against a copy of it, so a name added to the client
// cannot be exercised by users and by nothing else.

// fingerprintHybridShare classifies what a fingerprint name resolves to.
type fingerprintHybridShare int

const (
	// fingerprintCarriesHybrid: the preset always builds an X25519MLKEM768 share.
	fingerprintCarriesHybrid fingerprintHybridShare = iota
	// fingerprintLacksHybrid: the preset never builds one.
	fingerprintLacksHybrid
	// fingerprintVaries: the name does not resolve to one fixed preset, so neither
	// answer is a property of the name.
	fingerprintVaries
)

// fingerprintRegisterEntry is the declared state of one accepted fingerprint name.
type fingerprintRegisterEntry struct {
	// preset is "<Client>/<Version>" as the PINNED uTLS reports it. It is a literal
	// on purpose: it is a claim about a dependency, and the test below is the thing
	// that notices when the dependency stops agreeing with it.
	preset string
	// hybrid is what the greeting carries.
	hybrid fingerprintHybridShare
	// tls13 is whether the preset offers TLS 1.3 at all. A preset that does not
	// cannot carry REALITY for a reason that has nothing to do with the hybrid
	// share, and the failure message must not blame the wrong one.
	tls13 bool
	// note is why the entry is what it is.
	note string
}

// realityFingerprintRegister is the declared state of every `utls.fingerprint` name.
//
// The Chrome spellings are one entry each rather than an alias of one another because the
// configuration accepts each of them by name, and a test that collapsed them would not be checking
// that the alias still resolves to the same preset.
var realityFingerprintRegister = map[string]fingerprintRegisterEntry{
	"":                           {preset: "Chrome/133", hybrid: fingerprintCarriesHybrid, tls13: true, note: "the documented default"},
	"chrome":                     {preset: "Chrome/133", hybrid: fingerprintCarriesHybrid, tls13: true},
	"chrome_psk":                 {preset: "Chrome/133", hybrid: fingerprintCarriesHybrid, tls13: true},
	"chrome_psk_shuffle":         {preset: "Chrome/133", hybrid: fingerprintCarriesHybrid, tls13: true},
	"chrome_padding_psk_shuffle": {preset: "Chrome/133", hybrid: fingerprintCarriesHybrid, tls13: true},
	"chrome_pq":                  {preset: "Chrome/133", hybrid: fingerprintCarriesHybrid, tls13: true},
	"chrome_pq_psk":              {preset: "Chrome/133", hybrid: fingerprintCarriesHybrid, tls13: true},
	"firefox": {
		preset: "Firefox/120", hybrid: fingerprintLacksHybrid, tls13: true,
		note: "Firefox 120 predates ML-KEM. Upstream adds Firefox 148 in fc716b2+ddebe39; " +
			"the pin does not carry it and neither does metacubex/utls v1.8.8, the newest " +
			"released version of the module",
	},
	"safari": {
		preset: "Safari/16.0", hybrid: fingerprintLacksHybrid, tls13: true,
		note: "Safari 16.0 predates ML-KEM. Upstream adds Safari 26.3 in aa6edf4; the pin " +
			"does not carry it",
	},
	"edge": {
		preset: "Edge/85", hybrid: fingerprintLacksHybrid, tls13: true,
		note: "Edge/85 is pinned by uTLS itself (its comment: \"HelloEdge_106 seems to be " +
			"incompatible with this library\"), so this is a limitation of the dependency " +
			"rather than a missing backport",
	},
	"ios": {
		preset: "iOS/14", hybrid: fingerprintLacksHybrid, tls13: true,
		note: "iOS 14 predates ML-KEM; no newer iOS preset exists in the pin",
	},
	"qq": {
		preset: "QQBrowser/11.1", hybrid: fingerprintLacksHybrid, tls13: true,
		note: "QQBrowser 11.1 predates ML-KEM; no newer preset exists in the pin",
	},
	"android": {
		preset: "Android/11", hybrid: fingerprintLacksHybrid, tls13: false,
		note: "Android/11 does not offer TLS 1.3, so it cannot carry REALITY for a reason " +
			"independent of the hybrid share",
	},
	"360": {
		preset: "360Browser/7.5", hybrid: fingerprintLacksHybrid, tls13: false,
		note: "360Browser/7.5 offers only the NIST curves and no key share, so it cannot " +
			"carry REALITY for a reason independent of the hybrid share",
	},
	"random": {
		preset: "one of the modern pool", hybrid: fingerprintVaries, tls13: true,
		note: "resolved once per process from modernFingerprints, four of whose five " +
			"members lack the hybrid share — so a `random` REALITY client can only " +
			"complete a handshake against a current reference when the draw was Chrome",
	},
	"randomized": {
		preset: "Randomized/0", hybrid: fingerprintVaries, tls13: true,
		note: "a generated spec, not a preset: the hybrid share is prepended with the " +
			"dependency's own KeyShare_Append_RandomGroups weight, so this name is not a " +
			"compatibility claim in either direction",
	},
}

// realityReferenceHybridShareFloor is the reference release that made the hybrid key share
// mandatory. It is a literal here because it is the fact the whole register is about, and a test
// that read it from the code under test could not report it as evidence.
const realityReferenceHybridShareFloor = "v26.9.8"

// TestRealityFingerprintRegisterIsExhaustive ties the register to the table the client actually
// reads.
//
// Without this, the register could be complete for today and silently miss a name added tomorrow:
// the name would be accepted by the configuration, exercised by users, and classified by nothing.
func TestRealityFingerprintRegisterIsExhaustive(t *testing.T) {
	t.Parallel()
	var accepted []string
	for name := range uTLSFingerprints {
		accepted = append(accepted, name)
	}
	var registered []string
	for name := range realityFingerprintRegister {
		registered = append(registered, name)
	}
	sort.Strings(accepted)
	sort.Strings(registered)
	require.Equal(t, accepted, registered,
		"every accepted utls.fingerprint name must be classified in realityFingerprintRegister")

	// The table must also agree with the resolver for every name, so a name cannot be
	// registered against a preset the client does not actually send.
	for name, entry := range realityFingerprintRegister {
		id, err := uTLSClientHelloID(name)
		require.NoErrorf(t, err, "registered name %q must resolve", name)
		if entry.hybrid == fingerprintVaries {
			continue
		}
		require.Equal(t, entry.preset, id.Client+"/"+id.Version,
			"the register's preset for %q must be the preset the client resolves", name)
	}
}

// TestRealityFingerprintGreetingMatchesTheRegister is the measurement half: what each accepted
// name actually builds.
func TestRealityFingerprintGreetingMatchesTheRegister(t *testing.T) {
	t.Parallel()
	for name, entry := range realityFingerprintRegister {
		name, entry := name, entry
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			id, err := uTLSClientHelloID(name)
			require.NoError(t, err)
			greeting := buildGreetingForID(t, id)

			require.Equal(t, entry.tls13, greeting.tls13,
				"the register's TLS 1.3 claim for %q is measured, not assumed", name)

			switch entry.hybrid {
			case fingerprintCarriesHybrid:
				require.True(t, greeting.hybrid,
					"%s claims %s carries X25519MLKEM768; if the pin moved, delete this "+
						"entry's exception and re-run the live fingerprint scenarios "+
						"(test/interop, reality-firefox / reality-safari)", name, entry.preset)
				require.Less(t, greeting.hybridIndex, greeting.classicalIndex,
					"%s must present X25519MLKEM768 BEFORE X25519: a reference reads the "+
						"FIRST share, so the order is part of the claim", name)
			case fingerprintLacksHybrid:
				require.False(t, greeting.hybrid,
					"%s claims %s does NOT carry X25519MLKEM768, and it now does: that is "+
						"the dependency change this register exists to catch. Delete the "+
						"entry from the incompatible set below and re-run the live "+
						"fingerprint scenarios", name, entry.preset)
			case fingerprintVaries:
				// Nothing to assert about a name that resolves to a different preset
				// each process; the register's job is to say so rather than to claim
				// either answer.
			}
		})
	}
}

// TestRealityFingerprintIncompatibleSetIsDeclared names the consequence of the register: which
// accepted fingerprints cannot complete a REALITY handshake against a reference at or after the
// release that made the hybrid share mandatory.
//
// It is derived from the register rather than restated, so an entry that changes its hybrid answer
// moves this set in the same edit — which is the point: the two cannot drift apart in silence.
func TestRealityFingerprintIncompatibleSetIsDeclared(t *testing.T) {
	t.Parallel()
	var incompatible, notTLS13 []string
	for name, entry := range realityFingerprintRegister {
		if entry.hybrid == fingerprintCarriesHybrid {
			continue
		}
		if !entry.tls13 {
			notTLS13 = append(notTLS13, name)
			continue
		}
		incompatible = append(incompatible, name)
	}
	sort.Strings(incompatible)
	sort.Strings(notTLS13)

	// The set is the deliverable of the uTLS go/no-go, so it is pinned by name: a
	// change to it is a change to what the release claims about REALITY, and it must
	// be made deliberately rather than by a dependency bump.
	require.Equal(t,
		[]string{"edge", "firefox", "ios", "qq", "random", "randomized", "safari"},
		incompatible,
		"the set of accepted fingerprints that cannot present X25519MLKEM768, and therefore "+
			"cannot complete a REALITY handshake against a reference at or after %s, changed. "+
			"See docs/fork/utls-fingerprint-decision.md",
		realityReferenceHybridShareFloor)
	require.Equal(t, []string{"360", "android"}, notTLS13,
		"the fingerprints that cannot carry REALITY because they do not offer TLS 1.3 changed")

	// `random` is worth stating as a number rather than as prose: the draw decides,
	// so the exposure is a probability, and it is the reason `random` is in the set.
	var hybridlessModern int
	for _, id := range modernFingerprints {
		if !buildGreetingForID(t, id).hybrid {
			hybridlessModern++
		}
	}
	require.Equal(t, 4, hybridlessModern,
		"modernFingerprints must still contain exactly one preset that carries the hybrid share, "+
			"or the `random` entry's note is wrong")
}

// fingerprintGreeting is the measured shape of a built greeting.
type fingerprintGreeting struct {
	hybrid         bool
	hybridIndex    int
	classicalIndex int
	tls13          bool
}

// buildGreetingForID builds the greeting a preset produces, without any I/O.
func buildGreetingForID(t *testing.T, id utls.ClientHelloID) fingerprintGreeting {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	uConn := utls.UClient(clientConn, &utls.Config{
		ServerName:         "www.example.com",
		InsecureSkipVerify: true,
	}, id)
	require.NoError(t, uConn.BuildHandshakeState())

	greeting := fingerprintGreeting{hybridIndex: -1, classicalIndex: -1}
	for _, version := range uConn.HandshakeState.Hello.SupportedVersions {
		if version == utls.VersionTLS13 {
			greeting.tls13 = true
		}
	}
	for _, extension := range uConn.Extensions {
		shares, isShares := extension.(*utls.KeyShareExtension)
		if !isShares {
			continue
		}
		for index, share := range shares.KeyShares {
			switch share.Group {
			case utls.X25519MLKEM768:
				greeting.hybrid = true
				if greeting.hybridIndex < 0 {
					greeting.hybridIndex = index
				}
			case utls.X25519:
				if greeting.classicalIndex < 0 {
					greeting.classicalIndex = index
				}
			}
		}
	}
	return greeting
}
