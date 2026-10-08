package interop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Certificates for the two places the stand needs one.
//
// A REALITY scenario needs a TLS server for the handshake to be FORWARDED to: a
// REALITY server that cannot authenticate a client proxies the ClientHello to
// its `dest` and relays whatever comes back, so the stand must own a `dest` or
// the unauthenticated path has nowhere to go and the camouflage behaviour cannot
// be exercised at all. That is the local camouflage server.
//
// A plain-TLS scenario (only HTTP/3, since REALITY is TCP-only) needs a
// certificate the reference can present, and the same file has to be readable by
// the reference process. So the certificate is written to disk once and both
// sides are pointed at it.
//
// The certificate is self-signed and short-lived. That is not a shortcut: REALITY
// authenticates with its own key exchange and never validates this chain, and
// the H3 client sets `insecure` because pinning a per-run certificate would test
// the stand's file plumbing rather than the transport.

// certificateValidity is one day: long enough that a kept artifact can be
// replayed by hand the next morning, short enough that a leaked file from a test
// run is worthless.
const certificateValidity = 24 * time.Hour

// GenerateSelfSignedCertificate mints an ECDSA P-256 certificate for the given
// server name, with 127.0.0.1 and ::1 in the SANs so a loopback replay by hand
// works without editing the file.
func GenerateSelfSignedCertificate(serverName string) (certificatePEM []byte, keyPEM []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, E.Cause(err, "generate certificate key")
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, E.Cause(err, "generate certificate serial")
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{serverName},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, E.Cause(err, "create self-signed certificate")
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, E.Cause(err, "marshal certificate key")
	}
	certificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certificatePEM, keyPEM, nil
}

// WriteSelfSignedCertificate writes a fresh pair into dir and returns the two
// file paths. The names are fixed rather than random so a kept artifact reads
// predictably and the reference config never contains a temp-file suffix a
// maintainer has to reconstruct.
func WriteSelfSignedCertificate(dir string, serverName string) (certificateFile string, keyFile string, err error) {
	certificatePEM, keyPEM, err := GenerateSelfSignedCertificate(serverName)
	if err != nil {
		return "", "", err
	}
	certificateFile = filepath.Join(dir, "camouflage.crt")
	keyFile = filepath.Join(dir, "camouflage.key")
	// 0o600 on the key: it is a real private key even though it is throwaway, and
	// a harness that writes world-readable keys teaches the wrong habit.
	if err = os.WriteFile(certificateFile, certificatePEM, 0o644); err != nil {
		return "", "", E.Cause(err, "write certificate")
	}
	if err = os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return "", "", E.Cause(err, "write certificate key")
	}
	return certificateFile, keyFile, nil
}
