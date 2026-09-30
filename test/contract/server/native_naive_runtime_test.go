package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	badjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/rw"

	"github.com/stretchr/testify/require"
)

// fixtureCertificates generates a throwaway CA and leaf certificate and returns their
// paths.
//
// The production fixture deliberately points its TLS paths at /tmp placeholder
// locations, because it must not carry real key material. Construction reads the
// certificate, so a test that builds the inbound must supply real files at those
// paths rather than weakening the fixture. The fixture's own bytes are never
// modified: only the in-memory copy this test decodes is redirected.
func fixtureCertificates(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sing-box contract test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	require.NoError(t, err)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "naive contract test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"naive.contract.test", "localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, leafKey.Public(), caKey)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	chain := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	require.NoError(t, rw.WriteFile(certPath, chain))
	require.NoError(t, rw.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})))
	return certPath, keyPath
}

// This file proves the server profile can actually BUILD the Native Naive
// inbound, not merely resolve its type name.
//
// # Why presence-of-a-type is not enough
//
// TestRegistryProvidesNativeNaiveInbound asserts that the registry resolves the
// `naive` type. That is a real check, but it is one step short of what production
// needs: a type can resolve while CONSTRUCTION still fails, and that would surface as
// a startup failure on the VPS rather than as a test failure here - which is the same
// shape of gap that let the shipped `.6` binary ship broken.
//
// Native Naive is the NaiveProxy server for this deployment, reached at TCP/443
// through Nginx Stream by SNI. "The binary can build this inbound" is therefore a
// production property, asserted here through the real registry and the real config
// decoder rather than through a hand-built options literal.

// mustMarshal marshals a value or fails the test.
func mustMarshal(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return encoded
}

// loadFixtureInboundJSON returns the raw JSON of the fixture's named inbound.
func loadFixtureInboundJSON(t *testing.T, tag string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "release", "jiejie-production-topology.json")
	content, err := os.ReadFile(path)
	require.NoError(t, err, "read production fixture")

	var envelope struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	require.NoError(t, json.Unmarshal(content, &envelope), "parse production fixture")

	for _, raw := range envelope.Inbounds {
		var header struct {
			Tag string `json:"tag"`
		}
		require.NoError(t, json.Unmarshal(raw, &header))
		if header.Tag == tag {
			return raw
		}
	}
	t.Fatalf("%s must declare an inbound tagged %q", path, tag)
	return nil
}

// buildFixtureInbound constructs the named inbound through the shipped registry,
// taking the same path the config loader takes: decode into the concrete options
// type, then construct.
func buildFixtureInbound(t *testing.T, tag string) adapter.Inbound {
	t.Helper()

	raw := loadFixtureInboundJSON(t, tag)

	registry := include.InboundRegistry()
	options, loaded := registry.CreateOptions("naive")
	require.True(t, loaded, "the registry must provide the naive inbound type")

	// The registry-aware context is what resolves `"type": "naive"` to its concrete
	// options type, so this is the same decoding path `sing-box check` uses.
	// The config loader strips the scheduler-level keys (`type`, `tag`) before
	// decoding the remainder into the options type, so this does the same rather
	// than passing them through.
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &fields), "parse the fixture inbound")
	delete(fields, "type")
	delete(fields, "tag")

	// Construction loads the TLS certificate, and the fixture intentionally points at
	// placeholder paths so that it never carries key material. Point this in-memory
	// copy at freshly generated files instead of weakening the fixture on disk.
	certPath, keyPath := fixtureCertificates(t)
	var tlsOptions map[string]json.RawMessage
	if rawTLS, hasTLS := fields["tls"]; hasTLS {
		require.NoError(t, json.Unmarshal(rawTLS, &tlsOptions))
		tlsOptions["certificate_path"] = mustMarshal(t, certPath)
		tlsOptions["key_path"] = mustMarshal(t, keyPath)
		fields["tls"] = mustMarshal(t, tlsOptions)
	} else {
		t.Fatalf("the production naive inbound must serve TLS; none found in the fixture")
	}
	optionsJSON, err := json.Marshal(fields)
	require.NoError(t, err)

	ctx := include.Context(context.Background())
	require.NoError(t,
		badjson.UnmarshalContext(ctx, optionsJSON, options),
		"the fixture's naive inbound must decode into the concrete options type")

	// The router is nil: NewInbound stores it and wraps it in the UoT router, and
	// construction neither dials nor resolves. What is under test is that
	// construction SUCCEEDS with the shipped registry.
	instance, err := registry.Create(
		context.Background(), nil, log.NewNOPFactory().Logger(), tag, "naive", options)
	require.NoError(t, err,
		"the server registry must be able to CONSTRUCT the production Native "+
			"Naive inbound; a decode-only check would miss a constructor that fails")
	require.NotNil(t, instance)
	return instance
}

// TestServerBuildsNativeNaiveInbound builds the fixture's `naive-in` through
// the shipped registry and starts it.
//
// This is the assertion that fails at the level an operator experiences the problem -
// "the binary cannot run my configuration" - rather than only at the level the
// registry reports.
func TestServerBuildsNativeNaiveInbound(t *testing.T) {
	instance := buildFixtureInbound(t, "naive-in")
	defer instance.Close()

	require.Equal(t, "naive", instance.Type(),
		"the constructed inbound must report the naive type")
	require.Equal(t, "naive-in", instance.Tag())

	// Start binds the real listener. A stub, or an inbound whose constructor
	// half-succeeded, fails here rather than only under `run`.
	require.NoError(t, instance.Start(adapter.StartStateStart),
		"the Native Naive inbound must start; construction alone would not prove the "+
			"listener path is intact")

	// Close must release it cleanly. A leak at this point would be a leaked listener
	// on the production port, which is exactly what a schema-only test cannot see.
	require.NoError(t, instance.Close())
}

// TestServerNativeNaiveInboundKeepsProductionShape pins the options that reach
// the constructor, so a fixture edit cannot quietly weaken what this profile builds
// while every other test still passes.
func TestServerNativeNaiveInboundKeepsProductionShape(t *testing.T) {
	raw := loadFixtureInboundJSON(t, "naive-in")

	var shape struct {
		Type       string          `json:"type"`
		Network    string          `json:"network"`
		ListenPort json.RawMessage `json:"listen_port"`
		Users      []struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"users"`
		Masquerade *struct {
			Type string `json:"type"`
		} `json:"masquerade"`
	}
	require.NoError(t, json.Unmarshal(raw, &shape))

	require.Equal(t, "naive", shape.Type)

	// TCP-only. UoT is carried INSIDE the HTTP/2 CONNECT, so no UDP listener may be
	// added here: UDP/443 belongs to MASQUE.
	require.Equal(t, "tcp", shape.Network,
		"the production naive inbound must stay TCP-only: its UoT runs inside the "+
			"CONNECT tunnel, and a UDP listener here would contend with MASQUE on UDP/443")

	require.NotEmpty(t, shape.Users,
		"the production naive inbound must require authentication; without users, "+
			"anyone reaching TCP/443 could open a tunnel")
	for _, user := range shape.Users {
		require.NotEmpty(t, user.Username, "a naive user has an empty username")
		require.NotEmpty(t, user.Password, "a naive user has an empty password")
	}

	require.NotNil(t, shape.Masquerade,
		"the production naive inbound must declare a masquerade: unauthenticated and "+
			"non-CONNECT traffic must be served something rather than looking like a "+
			"dead port")
}

// TestServerNaiveOptionsCarryForkFeatures pins that the fork-specific Naive
// work is still compiled into this profile's options type.
//
// The capabilities below are why this inbound is a maintained production capability
// rather than a stock registration. Asserting them here means a future "minimal
// build" change that silently drops one fails CI instead of being discovered on the
// VPS.
//
// This is a cheap structural assertion, deliberately kept in the fast job. The
// behavioural coverage - UoT, padding, masquerade, target ACL, ALPN isolation,
// receive windows, lifecycle and half-close - remains in protocol/naive and the
// jiejie suite, which the deep check runs.
func TestServerNaiveOptionsCarryForkFeatures(t *testing.T) {
	options, loaded := include.InboundRegistry().CreateOptions("naive")
	require.True(t, loaded)

	// The concrete options type must be the fork's, which carries fields a stock
	// Naive inbound does not have. If the fork options were replaced by an upstream
	// one, this type assertion fails and the fork's extended configuration surface
	// would have silently disappeared from the production profile.
	naiveOptions, isNaiveOptions := options.(*option.NaiveInboundOptions)
	require.True(t, isNaiveOptions,
		"the naive registry entry must expose the fork's inbound options type, got %T",
		options)
	require.NotNil(t, naiveOptions)

	// The fork fields this profile depends on must exist on that type. These compile
	// only if the fields are present, which is the point: dropping any of them from
	// the options type breaks the build of this test rather than silently changing
	// what the production profile can express.
	// Referencing these fields IS the assertion: they compile only while the fork's
	// extended configuration surface exists on the options type. A nil value here is
	// correct - this options value was allocated fresh, so unset means unset.
	_ = naiveOptions.Masquerade
	_ = naiveOptions.Users

	// The HTTP/2 resource controls live in the embedded HTTP2Options. Referencing the
	// fields is the assertion: if the fork's HTTP2Options were dropped from the naive
	// options type, this test would not compile.
	require.Nil(t, naiveOptions.HTTP2Options.StreamReceiveWindow,
		"stream_receive_window must default to unset, which keeps the upstream "+
			"net/http2 default rather than inventing a window")
	require.Nil(t, naiveOptions.HTTP2Options.ConnectionReceiveWindow)
	_ = naiveOptions.HTTP2Options.MaxConcurrentStreams
	_ = naiveOptions.HTTP2Options.IdleTimeout
}
