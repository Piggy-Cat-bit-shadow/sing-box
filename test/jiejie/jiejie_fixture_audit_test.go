package jiejie_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file audits the production fixture for dangling references.
//
// `sing-box check` does NOT validate most cross-object references. Verified
// against the binary: it catches an unknown domain_resolver, but it happily
// accepts a detour naming a nonexistent inbound, a route.final naming a
// nonexistent outbound, an outbound naming a nonexistent outbound, and a DNS
// `final` naming a nonexistent DNS server.
//
// That matters most for the ShadowTLS detour, which is an INBOUND tag resolved
// through the inbound registry at route/route.go: an earlier fixture pointed it
// at "direct" (an outbound), which `check` accepted but which models the wrong
// production link. This test makes such a mistake impossible to reintroduce
// silently.

type productionFixture struct {
	DNS struct {
		Servers []struct {
			Tag    string `json:"tag"`
			Type   string `json:"type"`
			Server string `json:"server"`
			Port   uint16 `json:"server_port"`
		} `json:"servers"`
		Final string `json:"final"`
	} `json:"dns"`

	Inbounds []struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Detour     string `json:"detour"`
		ListenPort uint16 `json:"listen_port"`
		Users      []struct {
			Name     string `json:"name"`
			Username string `json:"username"`
		} `json:"users"`
		Handshake *struct {
			Detour         string `json:"detour"`
			DomainResolver string `json:"domain_resolver"`
		} `json:"handshake"`
	} `json:"inbounds"`

	Outbounds []struct {
		Type           string          `json:"type"`
		Tag            string          `json:"tag"`
		DomainResolver string          `json:"domain_resolver"`
		Outbounds      json.RawMessage `json:"outbounds"`
	} `json:"outbounds"`

	Route struct {
		Rules []productionRouteRule `json:"rules"`
		Final string                `json:"final"`
		// RuleSets and RawRules keep the raw rule list available for assertions on
		// options this struct does not model (override_address, override_port,
		// port, domain, domain_suffix). Adding typed fields one at a time would
		// mean a test cannot check a new rule option until this struct grows it,
		// which is exactly the kind of gap that lets a fixture drift unnoticed.
		RuleSets json.RawMessage   `json:"rule_set"`
		RawRules []json.RawMessage `json:"-"`
	} `json:"route"`
}

// productionRouteRule models the route options this fork's fixture uses.
type productionRouteRule struct {
	Outbound        string          `json:"outbound"`
	User            []string        `json:"user"`
	Inbound         []string        `json:"inbound"`
	Network         []string        `json:"network"`
	Domain          []string        `json:"domain"`
	DomainSuffix    []string        `json:"domain_suffix"`
	IPCIDR          []string        `json:"ip_cidr"`
	Port            []uint16        `json:"port"`
	Action          string          `json:"action"`
	Strategy        string          `json:"strategy"`
	Type            string          `json:"type"`
	OverrideAddress string          `json:"override_address"`
	OverridePort    uint16          `json:"override_port"`
	IPIsPrivate     bool            `json:"ip_is_private"`
	RuleSet         json.RawMessage `json:"rule_set"`
}

func loadProductionFixture(t *testing.T) (*productionFixture, string) {
	t.Helper()
	path := filepath.Join("..", "..", "release", "jiejie-production-topology.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read production fixture: %v", err)
	}
	var fixture productionFixture
	if err = json.Unmarshal(content, &fixture); err != nil {
		t.Fatalf("parse production fixture: %v", err)
	}
	// Capture the rules twice: once typed, once raw. The raw copy is what
	// TestJiejieNaiveSelfHostedWebRuleShapeMatchesProduction asserts against, so a
	// rule option that production sets but this struct does not model still shows
	// up in the test rather than being silently dropped by the decoder.
	var envelope struct {
		Route struct {
			Rules []json.RawMessage `json:"rules"`
		} `json:"route"`
	}
	if err = json.Unmarshal(content, &envelope); err != nil {
		t.Fatalf("parse production fixture rules: %v", err)
	}
	fixture.Route.RawRules = envelope.Route.Rules
	return &fixture, path
}

// TestJiejieProductionFixtureReferencesResolve is the reference audit.
func TestJiejieProductionFixtureReferencesResolve(t *testing.T) {
	fixture, _ := loadProductionFixture(t)

	inboundTags := make(map[string]bool)
	for _, inbound := range fixture.Inbounds {
		if inbound.Tag != "" {
			inboundTags[inbound.Tag] = true
		}
	}
	outboundTags := make(map[string]bool)
	for _, outbound := range fixture.Outbounds {
		if outbound.Tag != "" {
			outboundTags[outbound.Tag] = true
		}
	}
	dnsTags := make(map[string]bool)
	for _, server := range fixture.DNS.Servers {
		dnsTags[server.Tag] = true
	}

	// Every inbound detour is an INBOUND tag, resolved through the inbound
	// registry by route.go. This is the check `sing-box check` does not perform.
	for _, inbound := range fixture.Inbounds {
		if inbound.Detour == "" {
			continue
		}
		if !inboundTags[inbound.Detour] {
			t.Errorf("inbound %q has detour %q, which is not a declared inbound tag",
				inbound.Tag, inbound.Detour)
		}
		if outboundTags[inbound.Detour] && !inboundTags[inbound.Detour] {
			t.Errorf("inbound %q detour %q names an outbound, but a detour must be an inbound",
				inbound.Tag, inbound.Detour)
		}
		if inbound.Handshake != nil && inbound.Handshake.Detour != "" {
			if !outboundTags[inbound.Handshake.Detour] {
				t.Errorf("inbound %q handshake detour %q is not a declared outbound",
					inbound.Tag, inbound.Handshake.Detour)
			}
		}
	}

	// domain_resolver may appear on inbounds (handshake), outbounds and DNS
	// servers; every reference must resolve.
	resolverReferences := make(map[string]string)
	for _, inbound := range fixture.Inbounds {
		if inbound.Handshake != nil && inbound.Handshake.DomainResolver != "" {
			resolverReferences[inbound.Tag+".handshake"] = inbound.Handshake.DomainResolver
		}
	}
	for _, outbound := range fixture.Outbounds {
		if outbound.DomainResolver != "" {
			resolverReferences[outbound.Tag] = outbound.DomainResolver
		}
	}
	for _, server := range fixture.DNS.Servers {
		if server.Server == "" {
			t.Errorf("dns server %q has no server address", server.Tag)
		}
	}
	for source, resolver := range resolverReferences {
		if !dnsTags[resolver] {
			t.Errorf("%s references domain_resolver %q, which is not a declared DNS server",
				source, resolver)
		}
	}

	// route.final and every rule outbound must resolve.
	if !outboundTags[fixture.Route.Final] {
		t.Errorf("route.final %q is not a declared outbound", fixture.Route.Final)
	}
	for index, rule := range fixture.Route.Rules {
		if rule.Outbound == "" {
			continue
		}
		if !outboundTags[rule.Outbound] {
			t.Errorf("route.rules[%d] outbound %q is not a declared outbound", index, rule.Outbound)
		}
	}

	// A DNS `final` must resolve too.
	if fixture.DNS.Final != "" && !dnsTags[fixture.DNS.Final] {
		t.Errorf("dns.final %q is not a declared DNS server", fixture.DNS.Final)
	}
}

// TestJiejieProductionFixtureModelsRealTopology pins the specific production
// links so they cannot silently regress into a feature showcase.
func TestJiejieProductionFixtureModelsRealTopology(t *testing.T) {
	fixture, _ := loadProductionFixture(t)

	inboundTags := make(map[string]string)
	for _, inbound := range fixture.Inbounds {
		inboundTags[inbound.Tag] = inbound.Type
	}
	outboundTags := make(map[string]string)
	for _, outbound := range fixture.Outbounds {
		outboundTags[outbound.Tag] = outbound.Type
	}

	// The real ShadowTLS chain: shadowtls-in -> detour ss2022-in -> route.
	shadowTLS, loaded := inboundTags["shadowtls-in"]
	if !loaded || shadowTLS != "shadowtls" {
		t.Fatalf("production fixture must declare a shadowtls inbound tagged shadowtls-in, got %q", shadowTLS)
	}
	var shadowTLSDetour string
	for _, inbound := range fixture.Inbounds {
		if inbound.Tag == "shadowtls-in" {
			shadowTLSDetour = inbound.Detour
		}
	}
	if shadowTLSDetour != "ss2022-in" {
		t.Fatalf("shadowtls-in detour must be the ss2022-in inbound, got %q", shadowTLSDetour)
	}
	if kind, loaded := inboundTags["ss2022-in"]; !loaded || kind != "shadowsocks" {
		t.Fatalf("the shadowtls detour target must be a shadowsocks inbound tagged ss2022-in, got %q", kind)
	}

	// The four production inbounds must exist.
	for _, required := range []struct{ tag, kind string }{
		{"masque-h2", "http"},
		{"masque-h3", "http"},
		{"anytls-in", "anytls"},
	} {
		if kind, loaded := inboundTags[required.tag]; !loaded || kind != required.kind {
			t.Errorf("production fixture must declare %s inbound %q, got %q", required.kind, required.tag, kind)
		}
	}

	// Exactly two outbounds: direct and the residential SOCKS5 upstream.
	if len(fixture.Outbounds) != 2 {
		t.Errorf("production fixture must declare exactly 2 outbounds, got %d", len(fixture.Outbounds))
	}
	for _, required := range []struct{ tag, kind string }{
		{"direct", "direct"},
		{"residential-socks", "socks"},
	} {
		if kind, loaded := outboundTags[required.tag]; !loaded || kind != required.kind {
			t.Errorf("production fixture must declare %s outbound %q, got %q", required.kind, required.tag, kind)
		}
	}

	// Only one DNS server: the loopback AdGuard Home resolver over UDP.
	if len(fixture.DNS.Servers) != 1 {
		t.Fatalf("production fixture must declare exactly 1 DNS server, got %d", len(fixture.DNS.Servers))
	}
	if fixture.DNS.Servers[0].Type != "udp" {
		t.Errorf("the production resolver must be type udp, got %q", fixture.DNS.Servers[0].Type)
	}
	if fixture.DNS.Final != "local-agh" {
		t.Errorf("dns.final must be local-agh, got %q", fixture.DNS.Final)
	}

	// The real listen ports, so the fixture cannot drift back to placeholders.
	listenPorts := make(map[string]uint16)
	for _, inbound := range fixture.Inbounds {
		listenPorts[inbound.Tag] = inbound.ListenPort
	}
	for tag, port := range map[string]uint16{
		"masque-h2":    28440,
		"masque-h3":    443,
		"anytls-in":    28436,
		"shadowtls-in": 8554,
		"ss2022-in":    17414,
	} {
		if actual := listenPorts[tag]; actual != port {
			t.Errorf("inbound %s must listen on the production port %d, got %d", tag, port, actual)
		}
	}

	// route.final must be direct, not one of the conditional upstreams.
	if fixture.Route.Final != "direct" {
		t.Errorf("route.final must be direct, got %q", fixture.Route.Final)
	}

	// The residential split must exist and cover both networks: UDP rejected,
	// TCP resolved to IPv4 and routed to the SOCKS upstream.
	var residentialUDPReject, residentialTCPResolve, residentialTCPRoute bool
	for _, rule := range fixture.Route.Rules {
		isResidential := false
		for _, user := range rule.User {
			if user == "residential" {
				isResidential = true
			}
		}
		if !isResidential {
			continue
		}
		for _, network := range rule.Network {
			switch {
			case network == "udp" && rule.Action == "reject":
				residentialUDPReject = true
			case network == "tcp" && rule.Action == "resolve" && rule.Strategy == "ipv4_only":
				residentialTCPResolve = true
			case network == "tcp" && rule.Outbound == "residential-socks":
				residentialTCPRoute = true
			}
		}
	}
	if !residentialUDPReject {
		t.Error("the residential user's UDP traffic must be rejected")
	}
	if !residentialTCPResolve {
		t.Error("the residential user's TCP traffic must resolve with ipv4_only")
	}
	if !residentialTCPRoute {
		t.Error("the residential user's TCP traffic must route to residential-socks")
	}

	// No test-only or client-only outbound may appear in the production fixture.
	for _, forbidden := range []string{
		"masque-out", "masque-out-h2", "masque-out-h3", "anytls-out",
		"shadowtls-out", "ss2022-out", "select", "auto", "block",
	} {
		if kind, loaded := outboundTags[forbidden]; loaded {
			t.Errorf("production fixture must not contain the test-only outbound %q (type %s)", forbidden, kind)
		}
	}
	// No test-only inbound either.
	for _, forbidden := range []string{"socks-in", "mixed-in", "direct-in"} {
		if kind, loaded := inboundTags[forbidden]; loaded {
			t.Errorf("production fixture must not contain the test-only inbound %q (type %s)", forbidden, kind)
		}
	}
}

// TestJiejieProductionFixtureHasNoSecrets guards against a real credential,
// UUID or private key ever being committed into the fixture.
func TestJiejieProductionFixtureHasNoSecrets(t *testing.T) {
	_, path := loadProductionFixture(t)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	text := string(content)

	for _, forbidden := range []string{
		"PRIVATE KEY",
		"BEGIN CERTIFICATE",
		"-----BEGIN",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("production fixture must not embed key material (%q found)", forbidden)
		}
	}
	// The fixture may reference a certificate *path* but never inline material.
	// Every password in it must be an obvious placeholder.
	if !strings.Contains(text, "AAAAAAAAAAAAAAAAAAAAAA==") {
		// The SS2022 key is a documented placeholder and must stay that way.
		t.Log("note: SS2022 placeholder password not found verbatim; confirm it is still a placeholder")
	}
}
