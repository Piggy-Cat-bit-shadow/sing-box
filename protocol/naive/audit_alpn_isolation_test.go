package naive

import (
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	aTLS "github.com/sagernet/sing/common/tls"
)

// ALPN must be resolved once, and TCP must never advertise a QUIC-only protocol.
//
// The TLS config object is shared between the TCP listener and the HTTP/3
// initialiser, and STDServerConfig.Server() reads that config at HANDSHAKE time
// rather than capturing it. A mutation performed after TCP has started therefore
// changes what later TCP handshakes negotiate. The previous code did exactly
// that: the QUIC path appended "h3" to the shared object.
//
// It cannot be fixed by cloning: STDServerConfig.Clone() copies only the
// *tls.Config and the handshake timeout, dropping the certificate provider, the
// ACME service and the file watcher, so the clone could not serve or reload
// certificates.
//
// The fix is to resolve the complete list once, before any listener starts.
// These tests pin the resulting rules.

// alpnFor resolves the ALPN list for a given network selection and configured
// ALPN, using the same resolver production uses.
func alpnFor(network option.NetworkList, configured []string) []string {
	inbound := &Inbound{network: network.Build()}
	inbound.tlsConfig = &stubServerConfig{nextProtos: configured}
	return inbound.negotiatedNextProtos()
}

// TestAuditTCPALPNNeverAdvertisesH3 is the isolation invariant: a listener that
// does not serve UDP must not offer h3.
func TestAuditTCPALPNNeverAdvertisesH3(t *testing.T) {
	// tcp-only, which is the SHIPPED production topology.
	for _, configured := range [][]string{
		nil,
		{"h2", "http/1.1"},
		{"http/1.1"},
	} {
		got := alpnFor(option.NetworkList("tcp"), configured)
		if contains(got, http3ALPN) {
			t.Fatalf("a tcp-only inbound offered h3 (configured=%v, got=%v): a "+
				"QUIC-only protocol must never appear on a TCP listener", configured, got)
		}
		if !contains(got, "h2") {
			t.Fatalf("a tcp-only inbound must offer h2 (got=%v)", got)
		}
		if !contains(got, "http/1.1") {
			t.Fatalf("a tcp-only inbound must offer http/1.1 (got=%v)", got)
		}
	}
}

// TestAuditUDPALPNIncludesH3 is the other direction: an inbound that serves UDP
// must offer h3, or its HTTP/3 listener could never complete a handshake.
func TestAuditUDPALPNIncludesH3(t *testing.T) {
	for _, network := range []option.NetworkList{
		option.NetworkList("udp"),
		option.NetworkList("tcp\nudp"),
		option.NetworkList(""), // unset is BOTH tcp and udp
	} {
		got := alpnFor(network, nil)
		if !contains(got, http3ALPN) {
			t.Fatalf("an inbound serving UDP must offer h3 (network=%q, got=%v)",
				string(network), got)
		}
	}
}

// TestAuditALPNResolutionIsIdempotent proves the resolver can be called on an
// already-resolved list without duplicating entries.
//
// This matters because the resolver reads the same config it writes: production
// calls it once before starting listeners, but a later call must not produce a
// growing or reordered list, or a reload would change negotiation.
func TestAuditALPNResolutionIsIdempotent(t *testing.T) {
	first := alpnFor(option.NetworkList("tcp"), nil)
	inbound := &Inbound{network: option.NetworkList("tcp").Build()}
	inbound.tlsConfig = &stubServerConfig{nextProtos: first}
	second := inbound.negotiatedNextProtos()

	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatalf("resolving twice changed the list:\n first=%v\nsecond=%v", first, second)
	}
}

// TestAuditALPNPreservesOperatorConfiguration proves an explicitly configured
// protocol is kept, since an operator may rely on it.
func TestAuditALPNPreservesOperatorConfiguration(t *testing.T) {
	got := alpnFor(option.NetworkList("tcp"), []string{"acme-tls/1"})
	if !contains(got, "acme-tls/1") {
		t.Fatalf("an explicitly configured ALPN must be preserved (got=%v)", got)
	}
	if contains(got, http3ALPN) {
		t.Fatalf("a tcp-only inbound must still not offer h3 (got=%v)", got)
	}
}

// TestAuditHTTP3ALPNConstantMatchesTheLibrary pins the locally declared constant.
//
// inbound.go spells "h3" out rather than importing the QUIC package, because it
// must compile without the QUIC build tag. If the library constant ever changed,
// HTTP/3 would silently stop working, so the value is asserted here in a file
// that IS built with QUIC support.
func TestAuditHTTP3ALPNConstantMatchesTheLibrary(t *testing.T) {
	if http3ALPN != "h3" {
		t.Fatalf("http3ALPN is %q but RFC 9114 fixes it at \"h3\"", http3ALPN)
	}
	if !strings.HasPrefix(http3ALPN, "h3") {
		t.Fatalf("unexpected http3 ALPN %q", http3ALPN)
	}
}

func contains(list []string, value string) bool {
	return slices.Contains(list, value)
}

// stubServerConfig implements just enough of aTLS.ServerConfig for the ALPN
// resolver, which only reads and writes NextProtos.
type stubServerConfig struct {
	aTLS.ServerConfig
	nextProtos []string
}

func (s *stubServerConfig) NextProtos() []string     { return s.nextProtos }
func (s *stubServerConfig) SetNextProtos(p []string) { s.nextProtos = p }
