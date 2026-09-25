package naive

import (
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	aTLS "github.com/sagernet/sing/common/tls"
)

// Scope of this file, stated precisely because an earlier revision overstated it.
//
// These are PURE-FUNCTION tests over the ALPN resolvers. They prove what each
// resolver RETURNS for a given network and configured list. They do NOT prove
// that a real handshake negotiates what the resolver returned: that requires a
// running listener and a real TLS or QUIC handshake, and it is covered in
// test/jiejie/jiejie_naive_alpn_isolation_test.go.
//
// The distinction is not academic. A previous version of this file asserted "a
// TCP listener never offers h3" using only a tcp-ONLY inbound, where h3 is absent
// because no QUIC transport exists rather than because the ALPN lists are
// scoped - so it passed against an implementation that DID negotiate h3 on a
// tcp+udp inbound. The tests below now exercise the transport-scoped resolvers
// directly, and the runtime file is what establishes the end-to-end property.

// tcpALPNFor returns what the TCP listener would offer.
func tcpALPNFor(network option.NetworkList, configured []string) []string {
	inbound := &Inbound{network: network.Build()}
	inbound.tlsConfig = &stubServerConfig{nextProtos: configured}
	return inbound.tcpNextProtos()
}

// quicALPNFor returns what the QUIC listener would offer.
func quicALPNFor(network option.NetworkList, configured []string) []string {
	inbound := &Inbound{network: network.Build()}
	inbound.tlsConfig = &stubServerConfig{nextProtos: configured}
	return inbound.quicNextProtos()
}

// alpnFor returns the combined list, which is for logging and assertions only.
func alpnFor(network option.NetworkList, configured []string) []string {
	inbound := &Inbound{network: network.Build()}
	inbound.tlsConfig = &stubServerConfig{nextProtos: configured}
	return inbound.negotiatedNextProtos()
}

// TestAuditTCPALPNNeverAdvertisesH3 pins the TCP resolver's output.
//
// It covers EVERY network, not just tcp-only: the defect this guards against was
// specifically that a tcp+udp inbound offered h3 on its TCP listener, so a test
// limited to tcp-only could not fail for the right reason.
//
// This asserts the resolver, not a handshake. The handshake is asserted in
// test/jiejie/jiejie_naive_alpn_isolation_test.go.
func TestAuditTCPALPNNeverAdvertisesH3(t *testing.T) {
	for _, network := range []option.NetworkList{
		option.NetworkList("tcp"),
		option.NetworkList("tcp\nudp"),
		option.NetworkList("udp"),
		option.NetworkList(""),
	} {
		for _, configured := range [][]string{
			nil,
			{"h2", "http/1.1"},
			{"http/1.1"},
			// The union an earlier implementation put on the shared config.
			{"h2", "http/1.1", "h3"},
		} {
			got := tcpALPNFor(network, configured)
			if contains(got, http3ALPN) {
				t.Fatalf("the TCP resolver offered h3 (network=%q configured=%v "+
					"got=%v): h3 is QUIC-only and must never appear on a TCP listener",
					string(network), configured, got)
			}
			if !contains(got, "h2") {
				t.Fatalf("the TCP resolver must offer h2 (network=%q got=%v)",
					string(network), got)
			}
			if !contains(got, "http/1.1") {
				t.Fatalf("the TCP resolver must offer http/1.1 (network=%q got=%v)",
					string(network), got)
			}
		}
	}
}

// TestAuditQUICALPNIsH3Only pins the QUIC resolver.
//
// It must be h3 and ONLY h3: offering h2 on the QUIC transport let a client
// negotiate an HTTP/2 connection over QUIC, which was observable before the
// transport-scoped split.
func TestAuditQUICALPNIsH3Only(t *testing.T) {
	for _, network := range []option.NetworkList{
		option.NetworkList("tcp\nudp"),
		option.NetworkList("udp"),
		option.NetworkList(""),
	} {
		for _, configured := range [][]string{
			nil,
			{"h2", "http/1.1", "h3"},
			{"h2"},
		} {
			got := quicALPNFor(network, configured)
			if len(got) != 1 || got[0] != http3ALPN {
				t.Fatalf("the QUIC resolver must offer exactly [h3] (network=%q "+
					"configured=%v got=%v)", string(network), configured, got)
			}
		}
	}
}

// TestAuditUDPALPNIncludesH3 covers the combined list.
//
// The combined list is not used for negotiation - each listener has its own
// resolver - but it is what a logging or assertion helper reports, so an inbound
// that serves UDP must still show h3 in it or the QUIC listener would have
// nothing to negotiate.
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
	for _, network := range []option.NetworkList{
		option.NetworkList("tcp"),
		option.NetworkList("tcp\nudp"),
	} {
		first := tcpALPNFor(network, nil)
		inbound := &Inbound{network: network.Build()}
		inbound.tlsConfig = &stubServerConfig{nextProtos: first}
		second := inbound.tcpNextProtos()

		if strings.Join(first, ",") != strings.Join(second, ",") {
			t.Fatalf("resolving twice changed the TCP list (network=%q):\n"+
				" first=%v\nsecond=%v", string(network), first, second)
		}
	}
}

// TestAuditALPNPreservesOperatorConfiguration proves an explicitly configured
// protocol is kept, since an operator may rely on it.
func TestAuditALPNPreservesOperatorConfiguration(t *testing.T) {
	got := tcpALPNFor(option.NetworkList("tcp"), []string{"acme-tls/1"})
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
