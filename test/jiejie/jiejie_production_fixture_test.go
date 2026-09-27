package jiejie_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The production fixture model, shared by the tests that assert against
// release/jiejie-production-topology.json from this package.
//
// The product-contract assertions on the same fixture moved to
// test/contract/serverminimal, which compiles only the contracts. This file keeps the
// minimal model needed by the integration tests that REMAIN here and still read the
// fixture - currently the Naive self-hosted rule-shape check, which pins the shipped
// rule shape so the runtime tests cannot drift from production.
//
// If a third reader appears, this model is what to promote into a shared internal
// package rather than duplicating it again.

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
		// StreamReceiveWindow / ConnectionReceiveWindow are the Naive HTTP/2
		// flow-control windows. Production sets them deliberately and nothing
		// else in the fixture does, so they are captured as raw JSON: a value
		// that is present but not a plain number still reaches the assertion
		// below instead of quietly decoding to 0.
		StreamReceiveWindow     json.RawMessage `json:"stream_receive_window"`
		ConnectionReceiveWindow json.RawMessage `json:"connection_receive_window"`
		Users                   []struct {
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

// loadProductionFixture reads release/jiejie-production-topology.json, resolved
// relative to this test's working directory (test/jiejie), which is two levels below
// the repository root.
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
	// TestJiejieNaiveSelfHostedWebRuleShapeMatchesProduction (still in
	// test/jiejie, which exercises the live server) asserts against, so a rule
	// option that production sets but this struct does not model still shows up in
	// the test rather than being silently dropped by the decoder.
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
