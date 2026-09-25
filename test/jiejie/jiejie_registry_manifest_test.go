package jiejie_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/include"

	"github.com/stretchr/testify/require"
)

// The production registry must provide exactly what the production topology uses.
//
// This is derived from release/jiejie-production-topology.json rather than from a
// hand-maintained list, so the check cannot drift: adding a protocol to the
// fixture without registering it fails here, and the failure names the missing
// type instead of surfacing later as a runtime "unknown inbound type".
//
// The same fixture is consulted by the dependency audit in CI, but that audit
// only checks which PACKAGES are linked. This checks that every TYPE the
// configuration names is resolvable through the registry, which is a different
// question and the one that decides whether the server can start at all.

// productionTopology is the subset of the fixture this audit needs.
type productionTopology struct {
	Inbounds []struct {
		Type   string `json:"type"`
		Tag    string `json:"tag"`
		Detour string `json:"detour"`
	} `json:"inbounds"`
	Outbounds []struct {
		Type string `json:"type"`
		Tag  string `json:"tag"`
	} `json:"outbounds"`
	DNS struct {
		Servers []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		} `json:"servers"`
	} `json:"dns"`
	Route struct {
		Rules []struct {
			Outbound string `json:"outbound"`
		} `json:"rules"`
		Final string `json:"final"`
	} `json:"route"`
}

func loadProductionTopology(t *testing.T) productionTopology {
	t.Helper()
	path := filepath.Join("..", "..", "release", "jiejie-production-topology.json")
	content, err := os.ReadFile(path)
	require.NoError(t, err, "the production topology must be readable")
	var topology productionTopology
	require.NoError(t, json.Unmarshal(content, &topology),
		"the production topology must be valid JSON")
	return topology
}

// TestJiejieRegistryProvidesEveryFixtureInbound proves each inbound type the
// fixture declares can actually be constructed.
func TestJiejieRegistryProvidesEveryFixtureInbound(t *testing.T) {
	topology := loadProductionTopology(t)
	registry := include.InboundRegistry()
	require.NotEmpty(t, topology.Inbounds, "the fixture must declare inbounds")

	for _, inbound := range topology.Inbounds {
		_, loaded := registry.CreateOptions(inbound.Type)
		require.True(t, loaded,
			"the fixture declares inbound type %q (tag %q) but the registry does "+
				"not provide it; the server would fail to start",
			inbound.Type, inbound.Tag)
	}
}

// TestJiejieRegistryProvidesEveryFixtureOutbound proves each outbound type,
// including the ones only named from route rules, is registered.
func TestJiejieRegistryProvidesEveryFixtureOutbound(t *testing.T) {
	topology := loadProductionTopology(t)
	registry := include.OutboundRegistry()

	declared := make(map[string]string)
	for _, outbound := range topology.Outbounds {
		declared[outbound.Tag] = outbound.Type
	}
	require.NotEmpty(t, declared, "the fixture must declare outbounds")

	for _, outbound := range topology.Outbounds {
		_, loaded := registry.CreateOptions(outbound.Type)
		require.True(t, loaded,
			"the fixture declares outbound type %q (tag %q) but the registry does "+
				"not provide it", outbound.Type, outbound.Tag)
	}

	// Route rules and `final` address outbounds by TAG, so every referenced tag
	// must exist. A typo here is a configuration error rather than a missing
	// registration, but both mean the server cannot route.
	for _, rule := range topology.Route.Rules {
		if rule.Outbound == "" {
			continue
		}
		_, exists := declared[rule.Outbound]
		require.True(t, exists,
			"a route rule routes to outbound %q, which the fixture does not "+
				"declare", rule.Outbound)
	}
	if topology.Route.Final != "" {
		_, exists := declared[topology.Route.Final]
		require.True(t, exists,
			"route.final names outbound %q, which the fixture does not declare",
			topology.Route.Final)
	}
}

// TestJiejieRegistryProvidesEveryFixtureDNSTransport proves each DNS server type
// is registered.
//
// A DNS transport is resolved when the DNS router initialises, so a missing one
// prevents startup rather than degrading resolution.
func TestJiejieRegistryProvidesEveryFixtureDNSTransport(t *testing.T) {
	topology := loadProductionTopology(t)
	registry := include.DNSTransportRegistry()
	require.NotEmpty(t, topology.DNS.Servers, "the fixture must declare DNS servers")

	for _, server := range topology.DNS.Servers {
		_, loaded := registry.CreateOptions(server.Type)
		require.True(t, loaded,
			"the fixture declares DNS transport type %q (tag %q) but the registry "+
				"does not provide it", server.Type, server.Tag)
	}
}

// TestJiejieRegistryResolvesEveryInboundDetour proves the ShadowTLS chain is
// constructible end to end.
//
// The fixture routes shadowtls-in through `detour: ss2022-in`, and a detour is
// resolved through the INBOUND registry. A detour naming an unregistered inbound
// is only discovered at start time, and the resulting error does not say which
// piece of the chain is absent.
func TestJiejieRegistryResolvesEveryInboundDetour(t *testing.T) {
	topology := loadProductionTopology(t)
	registry := include.InboundRegistry()

	tags := make(map[string]string)
	for _, inbound := range topology.Inbounds {
		tags[inbound.Tag] = inbound.Type
	}

	detours := 0
	for _, inbound := range topology.Inbounds {
		if inbound.Detour == "" {
			continue
		}
		detours++
		detourType, exists := tags[inbound.Detour]
		require.True(t, exists,
			"inbound %q detours to %q, which the fixture does not declare",
			inbound.Tag, inbound.Detour)
		_, loaded := registry.CreateOptions(detourType)
		require.True(t, loaded,
			"inbound %q detours to %q of type %q, which the registry does not "+
				"provide; the ShadowTLS chain would not construct",
			inbound.Tag, inbound.Detour, detourType)
		t.Logf("detour chain: %s (%s) -> %s (%s)",
			inbound.Tag, inbound.Type, inbound.Detour, detourType)
	}
	require.Positive(t, detours,
		"the fixture is expected to declare at least one inbound detour; finding "+
			"none means this test silently verified nothing")
}

// TestJiejieRegistryAuditFindsTheExpectedSet pins the exact registry contents.
//
// The audit above proves nothing is MISSING. This proves nothing unexpected was
// added either: a protocol registered for a topology that does not use it is dead
// weight in a production binary, and the minimal registry's whole purpose is to
// avoid that. A new registration must be a deliberate decision, so it fails here
// first.
func TestJiejieRegistryAuditFindsTheExpectedSet(t *testing.T) {
	// THIS TEST IS ONLY VALID UNDER THE PRODUCTION MINIMAL TAG SET.
	//
	// It asserts that the registry contains nothing the production topology does
	// not use, which is a statement about the jiejie_server_minimal registry. The
	// QUIC/H3 tag set deliberately omits that tag so protocol/naive/quic is
	// linked, so under those tags the full registry is present and this test
	// fails on types like "cloudflared" that the minimal registry correctly
	// excludes. Measured: it passes under
	// with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0 and fails
	// under with_quic,badlinkname,tfogo_checklinkname0.
	//
	// That failure is a property of the tag set, not a regression, and it is
	// worth stating because combining the two tag sets in one `go test` run looks
	// like a full-coverage idea and is not one: the registry audit and the H3
	// tests are mutually exclusive. CI runs them in separate steps for this
	// reason.
	requireJiejieMinimalRegistry(t)

	topology := loadProductionTopology(t)

	// Every registered inbound type must be one the fixture actually uses.
	usedInboundTypes := make(map[string]bool)
	for _, inbound := range topology.Inbounds {
		usedInboundTypes[inbound.Type] = true
	}

	inboundRegistry := include.InboundRegistry()
	for _, inboundType := range inboundRegistry.OptionTypes() {
		require.True(t, usedInboundTypes[inboundType],
			"the registry provides inbound type %q, which the production topology "+
				"does not use; a production-only binary should not carry it",
			inboundType)
	}

	usedOutboundTypes := make(map[string]bool)
	for _, outbound := range topology.Outbounds {
		usedOutboundTypes[outbound.Type] = true
	}
	outboundRegistry := include.OutboundRegistry()
	for _, outboundType := range outboundRegistry.OptionTypes() {
		require.True(t, usedOutboundTypes[outboundType],
			"the registry provides outbound type %q, which the production "+
				"topology does not use", outboundType)
	}

	usedDNSTypes := make(map[string]bool)
	for _, server := range topology.DNS.Servers {
		usedDNSTypes[server.Type] = true
	}
	dnsRegistry := include.DNSTransportRegistry()
	for _, dnsType := range dnsRegistry.OptionTypes() {
		if _, used := usedDNSTypes[dnsType]; used {
			continue
		}
		// A DNS transport may be present for one of two reasons, and only one of
		// them is over-registration:
		//
		//   1. a BOOT DEPENDENCY - box.go unconditionally creates this transport
		//      as a fallback, so the binary cannot start without it even though no
		//      configured server uses it; or
		//   2. dead weight - registered but neither configured nor required.
		//
		// "local" is case 1 and is asserted as such rather than exempted: the
		// check below names the exact call site, so if box.go ever stops needing
		// it this test fails and the transport can be pruned.
		if isBootDependencyDNSType(t, dnsType) {
			continue
		}
		t.Fatalf("the registry provides DNS transport type %q, which the "+
			"production topology does not use and which is not a boot dependency",
			dnsType)
	}
}

// isBootDependencyDNSType reports whether a DNS transport is created
// unconditionally by box.go rather than by configuration.
//
// box.go initialises the DNS transport manager with a fallback that creates a
// C.DNSTypeLocal transport:
//
//	dnsTransportManager.Initialize(func() (adapter.DNSTransport, error) {
//	    return dnsTransportRegistry.CreateDNSTransport(ctx, ..., "local",
//	        C.DNSTypeLocal, &option.LocalDNSServerOptions{})
//	})
//
// Omitting that transport makes every start fail with "default DNS server
// fallback: transport type not found: local". The dependency is asserted from the
// source rather than hardcoded, so removing the fallback from box.go makes this
// audit notice that "local" has become prunable.
func isBootDependencyDNSType(t *testing.T, dnsType string) bool {
	t.Helper()
	if dnsType != "local" {
		return false
	}
	source, err := os.ReadFile(filepath.Join("..", "..", "box.go"))
	require.NoError(t, err, "box.go must be readable to verify the boot dependency")
	require.Contains(t, string(source), "C.DNSTypeLocal",
		"\"local\" is only justified as a boot dependency while box.go creates a "+
			"C.DNSTypeLocal fallback transport; that call is gone, so the "+
			"registration can be pruned")
	t.Log("dns transport \"local\" is present as a BOOT DEPENDENCY: box.go " +
		"unconditionally creates it as the DNS fallback")
	return true
}

// registryIsJiejieMinimal reports whether the jiejie_server_minimal tag was used
// for this build.
//
// It is detected through the registry itself rather than through build tags,
// because Go does not expose the tag set to a test at run time. The cloudflared
// inbound is registered only by the full registry, so its presence proves the
// minimal tag was NOT used.
func registryIsJiejieMinimal() bool {
	for _, inboundType := range include.InboundRegistry().OptionTypes() {
		if inboundType == "cloudflared" {
			return false
		}
	}
	return true
}

// requireJiejieMinimalRegistry skips a test that is only meaningful under the
// production minimal tag set, and says why.
func requireJiejieMinimalRegistry(t *testing.T) {
	t.Helper()
	if !registryIsJiejieMinimal() {
		t.Skip("this audit is only valid under the production minimal tag set " +
			"(jiejie_server_minimal). Under the QUIC/H3 tag set the full registry is " +
			"linked on purpose, so the assertion that nothing unexpected is " +
			"registered does not apply and would fail for the wrong reason.")
	}
}
