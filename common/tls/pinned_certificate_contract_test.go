package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Certificate pinning must accept exactly the certificates and public keys it was told to, and
// reject everything else.
//
// # Why this is tested at the verifier
//
// Every TLS engine - std, uTLS, system, Apple, Windows, and the server side - funnels its pinning
// decision through VerifyPinnedCertificate or through the same hashing. Testing the verifier is
// therefore the one place that covers all of them; the per-engine tests (windows_client_test.go)
// prove each engine actually reaches it.
//
// # What the failure modes are
//
// A pin that accepts too much is a silent downgrade: the connection succeeds against a certificate
// the operator did not authorise. A pin that accepts too little is an outage. Both directions are
// asserted here, for both the whole-certificate hash and the SPKI hash.

// buildPinnedFixture builds a self-signed certificate and returns its DER, its SHA-256, and the
// SHA-256 of its SubjectPublicKeyInfo - the three things pinning compares.
func buildPinnedFixture(t *testing.T) (der []byte, certHash []byte, publicKeyHash []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pinned.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"pinned.example"},
	}
	der, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(parsed.PublicKey)
	require.NoError(t, err)
	certSum := sha256.Sum256(der)
	spkiSum := sha256.Sum256(spki)
	return der, certSum[:], spkiSum[:]
}

// TestPinnedCertificateAcceptsTheMatchingCertificate is the positive case: the right hash passes.
func TestPinnedCertificateAcceptsTheMatchingCertificate(t *testing.T) {
	der, certHash, publicKeyHash := buildPinnedFixture(t)

	require.NoError(t, VerifyPinnedCertificate([][]byte{certHash}, nil, [][]byte{der}),
		"the certificate's own SHA-256 must be accepted")
	require.NoError(t, VerifyPinnedCertificate(nil, [][]byte{publicKeyHash}, [][]byte{der}),
		"the certificate's own public key SHA-256 must be accepted")
}

// TestPinnedCertificateRejectsAMismatchedHash is the security half.
//
// A hash that does not describe this certificate must fail, even when it is well-formed and the
// wrong pin would otherwise look like a valid configuration.
func TestPinnedCertificateRejectsAMismatchedHash(t *testing.T) {
	der, _, _ := buildPinnedFixture(t)
	_, otherCertHash, otherPublicKeyHash := buildPinnedFixture(t)

	require.Error(t, VerifyPinnedCertificate([][]byte{otherCertHash}, nil, [][]byte{der}),
		"a certificate hash belonging to a DIFFERENT certificate must be rejected; accepting it is "+
			"the silent downgrade pinning exists to prevent")
	require.Error(t, VerifyPinnedCertificate(nil, [][]byte{otherPublicKeyHash}, [][]byte{der}),
		"a public key hash belonging to a different certificate must be rejected")
}

// TestPinnedCertificateAcceptsAnyOfSeveralHashes covers rotation.
//
// Pinning a set is how a certificate is rotated without an outage: the old and the new pin are both
// listed while both are valid. Any one match must be enough.
func TestPinnedCertificateAcceptsAnyOfSeveralHashes(t *testing.T) {
	der, certHash, _ := buildPinnedFixture(t)
	_, otherCertHash, _ := buildPinnedFixture(t)

	require.NoError(t, VerifyPinnedCertificate([][]byte{otherCertHash, certHash}, nil, [][]byte{der}),
		"a match anywhere in the pinned set must be accepted, or rotation could not be staged")
}

// TestPinnedCertificateRejectsEmptyAndMalformedInput covers the shapes that must not be treated as
// "no pin configured", because that would verify nothing.
func TestPinnedCertificateRejectsEmptyAndMalformedInput(t *testing.T) {
	der, certHash, _ := buildPinnedFixture(t)

	require.Error(t, VerifyPinnedCertificate([][]byte{certHash}, nil, nil),
		"no peer certificate is a failure, not a pass")
	require.Error(t, VerifyPinnedCertificate([][]byte{certHash}, nil, [][]byte{}),
		"an empty certificate chain is a failure")

	// A hash of the right length but wrong value, and one of the wrong length.
	require.Error(t, VerifyPinnedCertificate([][]byte{make([]byte, sha256.Size)}, nil, [][]byte{der}),
		"an all-zero hash must not match")
	require.Error(t, VerifyPinnedCertificate([][]byte{[]byte("too short")}, nil, [][]byte{der}),
		"a malformed pin must not match")
	require.Error(t, VerifyPinnedCertificate([][]byte{}, nil, [][]byte{der}),
		"an empty pin list with no public key pins must not verify a certificate")
}

// TestPinnedCertificateRejectsGarbageCertificate covers a peer that sends something that is not a
// certificate at all: the whole-certificate hash may still be compared, but the SPKI path must not
// panic or succeed.
func TestPinnedCertificateRejectsGarbageCertificate(t *testing.T) {
	_, _, publicKeyHash := buildPinnedFixture(t)
	require.Error(t, VerifyPinnedCertificate(nil, [][]byte{publicKeyHash}, [][]byte{[]byte("not a certificate")}),
		"a payload that cannot be parsed as a certificate must fail the public key comparison")
}
