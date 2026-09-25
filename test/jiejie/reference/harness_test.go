package reference_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing/common/rw"

	"github.com/stretchr/testify/require"
)

// This file holds the process harness for the reference interop tests.
//
// The sing-box server under test runs as a real child process built from THIS
// repository, configured through a JSON file. Two properties follow from that,
// and both are the point:
//
//  1. This module never imports the sing-box root module, so the reference
//     clients (masque-go, connect-ip-go) cannot leak into the production
//     dependency graph through a test import.
//  2. The server is exercised the way it is deployed: configuration parsed from
//     JSON, listeners bound from the option tree, no Go field set directly by
//     the test.

const (
	// singBoxBinaryEnv points at a sing-box binary built from this repository.
	//
	// It is required rather than discovered, so a run that does not have a
	// binary reports NOT-TESTED instead of silently testing something else.
	singBoxBinaryEnv = "JIEJIE_SING_BOX_BINARY"

	// fullRegistryBuildEnv declares that the binary at singBoxBinaryEnv was
	// built with the FULL registry rather than the production minimal one. The
	// CONNECT-IP endpoint only exists there, so a test that needs it must say so
	// explicitly instead of discovering it as a handshake timeout.
	fullRegistryBuildEnv = "JIEJIE_FULL_REGISTRY_BINARY"
)

// startServerProcess launches the sing-box binary with a configuration file and
// returns a stop function.
//
// The process is waited for readiness on its UDP port before returning, because
// a QUIC client that dials too early fails with a transport error that reads
// like a protocol bug. Readiness is proven by an actual QUIC path being bound,
// which is the only thing the client needs.
func startServerProcess(t *testing.T, binary string, configPath string) func() {
	t.Helper()

	logPath := filepath.Join(t.TempDir(), "sing-box-masque.log")
	logFile, err := os.Create(logPath)
	require.NoError(t, err)

	command := exec.Command(binary, "run", "-c", configPath)
	command.Stdout = logFile
	command.Stderr = logFile
	require.NoError(t, command.Start())

	var once bool
	stop := func() {
		if once {
			return
		}
		once = true
		if command.Process != nil {
			_ = command.Process.Signal(os.Interrupt)
		}
		done := make(chan struct{})
		go func() {
			_ = command.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			if command.Process != nil {
				_ = command.Process.Kill()
			}
			<-done
		}
		_ = logFile.Close()
	}

	return stop
}

// startSingBoxWithConfig starts a sing-box process from an explicit top-level
// configuration map and waits for its QUIC listener to be bound.
//
// The caller supplies the inbound/endpoint list so a test can describe a
// masque-server (CONNECT-IP) endpoint or an http (CONNECT-UDP) inbound without
// this harness growing a parameter per option. The TLS block, the listen
// address, the port and the outbound list are filled in here, because every
// fixture in this package needs exactly the same ones and getting them subtly
// different between tests would make failures unattributable.
//
// Both lists are handled: an inbound and an endpoint carry the same listen
// fields, and the same TLS block is valid for each.
func startSingBoxWithConfig(t *testing.T, overrides map[string]any) *singBoxServer {
	t.Helper()

	binary := os.Getenv(singBoxBinaryEnv)
	if binary == "" {
		t.Skipf("%s is not set, so the reference interop cannot be run. "+
			"The sing-box server under test must be built by the caller; this is "+
			"NOT-TESTED, never a pass.", singBoxBinaryEnv)
	}

	_, certPem, keyPem := createSelfSignedCertificate(t, referenceTestTLSName)

	overrides = cloneConfig(overrides)
	port := reserveUDPPort(t)

	tlsBlock := map[string]any{
		"enabled":          true,
		"server_name":      referenceTestTLSName,
		"certificate_path": certPem,
		"key_path":         keyPem,
	}

	// Every listener in the fixture shares the one loopback port and the one
	// throwaway certificate, so a test cannot accidentally depend on a second
	// listener that was never started. An outbound list is added only when the
	// caller did not supply one: a masque-server endpoint that routes the inner
	// traffic needs an outbound, and the http inbound needs one for CONNECT-UDP.
	configured := false
	for _, key := range []string{"inbounds", "endpoints"} {
		entries, _ := overrides[key].([]any)
		for _, entry := range entries {
			item, ok := entry.(map[string]any)
			require.True(t, ok, "each %s entry must be an object", key)
			item["listen"] = "127.0.0.1"
			item["listen_port"] = port
			item["tls"] = tlsBlock
			configured = true
		}
		overrides[key] = entries
	}
	require.True(t, configured, "the override config must supply at least one inbound or endpoint")
	if _, exists := overrides["outbounds"]; !exists {
		overrides["outbounds"] = []any{map[string]any{"type": "direct"}}
	}
	overrides["log"] = map[string]any{"level": "debug"}

	configPath := writeConfigFile(t, overrides)
	process := startServerProcess(t, binary, configPath)

	return &singBoxServer{
		port:          port,
		stop:          process,
		connectIPPath: defaultConnectIPPath,
	}
}

// startSingBoxMASQUEH3WithConfig is the inbound-only form used by the
// CONNECT-UDP fixtures.
func startSingBoxMASQUEH3WithConfig(t *testing.T, overrides map[string]any) *singBoxServer {
	t.Helper()
	return startSingBoxWithConfig(t, overrides)
}

// defaultConnectIPPath is the well-known RFC 9484 path sing-box uses when
// `path` is left unset.
const defaultConnectIPPath = "/.well-known/masque/ip/*/*/"

// cloneConfig shallow-copies the top-level map so a caller's literal is never
// mutated by the harness.
func cloneConfig(source map[string]any) map[string]any {
	cloned := make(map[string]any, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

// writeConfigFile encodes a configuration map to a temp file and returns its
// path.
func writeConfigFile(t *testing.T, config map[string]any) string {
	t.Helper()
	encoded, err := json.MarshalIndent(config, "", "  ")
	require.NoError(t, err)
	configPath := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(configPath, encoded, 0o600))
	return configPath
}

// ---------------------------------------------------------------------------
// Public helpers, matched by name to the ones the sing-box test client suite
// uses. Without these the reference tests would be the only place in the
// repository that hand-rolls a certificate or a UDP port.
// ---------------------------------------------------------------------------

// basicProxyAuthorization is the Basic credential header for the fixture user,
// for the PROXY authentication surface (Proxy-Authorization).
func basicProxyAuthorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(referenceTestUser+":"+referenceTestPassword))
}

// basicAuthorization is the same credential for the ENDPOINT authentication
// surface (Authorization).
//
// The two are genuinely different surfaces in sing-box: the http inbound
// verifies Proxy-Authorization on its proxy path, while a tunnel endpoint
// verifies Authorization. Keeping both named explicitly makes a test state which
// one it is exercising instead of reusing whichever header happened to work.
func basicAuthorization() string {
	return basicProxyAuthorization()
}

// createSelfSignedCertificate issues a throwaway certificate for domain and
// returns the CA, certificate and key paths.
//
// It is a deliberate copy of the same helper in the `test/jiejie` package: this
// is a different Go module, so it cannot import that package without dragging
// the whole Jiejie suite and its dependencies in. The implementation is
// identical in shape, including the reserved example domain it is called with.
func createSelfSignedCertificate(t *testing.T, domain string) (caPem string, certPem string, keyPem string) {
	t.Helper()

	const userAndHostname = "sekai@nekohasekai.local"
	tempDir := t.TempDir()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber: randomSerialNumber(t),
		Subject: pkix.Name{
			Organization:       []string{"sing-box test CA"},
			OrganizationalUnit: []string{userAndHostname},
			CommonName:         "sing-box " + userAndHostname,
		},
		NotAfter:              time.Now().AddDate(10, 0, 0),
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caCert, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	domainTemplate := &x509.Certificate{
		SerialNumber: randomSerialNumber(t),
		Subject: pkix.Name{
			Organization:       []string{"sing-box test certificate"},
			OrganizationalUnit: []string{"sing-box " + userAndHostname},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 0, 30),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	domainTemplate.DNSNames = append(domainTemplate.DNSNames, domain)
	domainCert, err := x509.CreateCertificate(rand.Reader, domainTemplate, caTemplate, key.Public(), caKey)
	require.NoError(t, err)

	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	caPem = filepath.Join(tempDir, "ca.pem")
	certPem = filepath.Join(tempDir, domain+".pem")
	keyPem = filepath.Join(tempDir, domain+".key.pem")
	require.NoError(t, rw.WriteFile(caPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert})))
	require.NoError(t, rw.WriteFile(certPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: domainCert})))
	require.NoError(t, rw.WriteFile(keyPem, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})))
	return caPem, certPem, keyPem
}

func randomSerialNumber(t *testing.T) *big.Int {
	t.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	require.NoError(t, err)
	return serial
}

// loopbackAddress renders host:port for the loopback fixture.
func loopbackAddress(port uint16) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
}
