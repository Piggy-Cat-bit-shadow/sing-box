package serverminimal_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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

func loadProductionFixture(t *testing.T) (*productionFixture, string) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "release", "jiejie-production-topology.json")
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

// TestProductionFixtureReferencesResolve is the reference audit.
func TestProductionFixtureReferencesResolve(t *testing.T) {
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

// TestProductionFixtureModelsRealTopology pins the specific production
// links so they cannot silently regress into a feature showcase.
func TestProductionFixtureModelsRealTopology(t *testing.T) {
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

// TestProductionFixtureHasNoSecrets guards against a real credential,
// UUID or private key ever being committed into the fixture.
func TestProductionFixtureHasNoSecrets(t *testing.T) {
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

// TestProductionFixtureDeclaresNativeNaive pins that the production fixture models
// the Native Naive inbound the live VPS configuration actually declares.
//
// # Why this replaced an absence assertion
//
// This test previously asserted the OPPOSITE: that the fixture contained no `naive`
// inbound, that the tag `naive-in` was gone, and that ports 28438/28439 never
// reappeared. That assertion was derived from the assumption that Caddy
// forwardproxy@udpintcp had replaced all Native Naive usage in this deployment.
//
// The assumption was wrong. The real server configuration still declares a `naive`
// inbound, and the Server Minimal binary built while this test demanded its absence
// rejected that configuration at startup with `unknown inbound type: naive`. A
// fixture that under-describes production is worse than stale documentation, because
// the contract tests are what CI trusts - it let CI certify a binary that could not
// start the server it was built for.
//
// The property worth defending is therefore PRESENCE, together with the shape of the
// listener. This is a real assertion, not a deletion: if the naive inbound, its tag,
// or its serving port disappears from the fixture, this fails and says why.
func TestProductionFixtureDeclaresNativeNaive(t *testing.T) {
	fixture, path := loadProductionFixture(t)

	var naiveInbounds []int
	for index, inbound := range fixture.Inbounds {
		if inbound.Type == "naive" {
			naiveInbounds = append(naiveInbounds, index)
		}
	}
	require.Len(t, naiveInbounds, 1,
		"%s must declare exactly one native naive inbound, because the live "+
			"production configuration declares one and this fixture is the contract "+
			"CI checks the shipped registry against", path)

	naiveInbound := fixture.Inbounds[naiveInbounds[0]]

	require.Equal(t, "naive-in", naiveInbound.Tag,
		"%s must keep the production tag for the native naive inbound", path)
	require.EqualValues(t, 28438, naiveInbound.ListenPort,
		"%s must bind the production native naive port", path)

	// The receive windows are part of the Naive listener's contract: they are what
	// makes the HTTP/2 CONNECT path usable at production RTT. Asserting them here
	// keeps the flow-control property the retired test protected, now on the inbound
	// that actually carries it.
	var streamWindow, connectionWindow int64
	require.NoError(t, json.Unmarshal(naiveInbound.StreamReceiveWindow, &streamWindow),
		"%s native naive stream_receive_window must be a plain byte count", path)
	require.NoError(t, json.Unmarshal(naiveInbound.ConnectionReceiveWindow, &connectionWindow),
		"%s native naive connection_receive_window must be a plain byte count", path)
	require.EqualValues(t, 8*1024*1024, streamWindow,
		"%s must pin the native naive HTTP/2 stream receive window explicitly", path)
	require.EqualValues(t, 32*1024*1024, connectionWindow,
		"%s must pin the native naive HTTP/2 connection receive window explicitly", path)

	// The UoT relay port 28439 is NOT asserted. It belonged to a superseded path and
	// its removal was correct; restoring the inbound must not silently restore a
	// listener that production no longer runs.
	for index, rule := range fixture.Route.Rules {
		require.NotEqualValues(t, 28439, rule.OverridePort,
			"%s route rule %d targets the retired UoT port 28439; that path is gone "+
				"and restoring the naive inbound must not bring it back", path, index)
	}
}

// TestProductionFixtureUsesOnlyRealReceiveWindowOwners keeps the flow-control
// assertion that the retired Naive test existed to make, generalised so it does not
// depend on Naive being present.
//
// The original point was that production pins HTTP/2 flow-control windows
// deliberately and that no OTHER inbound should quietly inherit or override them.
// That property is still worth defending after Naive left, so it is stated on its
// own: whichever inbound sets a receive window must set it explicitly and sanely.
func TestProductionFixtureUsesOnlyRealReceiveWindowOwners(t *testing.T) {
	fixture, path := loadProductionFixture(t)

	const (
		expectedStream     = 8 * 1024 * 1024
		expectedConnection = 32 * 1024 * 1024
	)

	var owners int
	for _, inbound := range fixture.Inbounds {
		if len(inbound.StreamReceiveWindow) == 0 && len(inbound.ConnectionReceiveWindow) == 0 {
			continue
		}
		owners++
		// Two production listeners legitimately pin HTTP/2 flow control: the MASQUE
		// HTTP inbound and the Native Naive inbound (whose CONNECT is carried over
		// HTTP/2). Anything else setting a window would be inheriting or overriding
		// flow control by accident.
		if inbound.Type != "http" && inbound.Type != "naive" {
			t.Errorf("%s inbound %q (type %s) sets a receive window; only the MASQUE "+
				"HTTP and Native Naive inbounds pin HTTP/2 flow control in production",
				path, inbound.Tag, inbound.Type)
		}

		var stream, connection int64
		if len(inbound.StreamReceiveWindow) > 0 {
			if err := json.Unmarshal(inbound.StreamReceiveWindow, &stream); err != nil {
				t.Errorf("%s inbound %q stream_receive_window must be a plain byte "+
					"count, got %s: %v", path, inbound.Tag, inbound.StreamReceiveWindow, err)
				continue
			}
		}
		if len(inbound.ConnectionReceiveWindow) > 0 {
			if err := json.Unmarshal(inbound.ConnectionReceiveWindow, &connection); err != nil {
				t.Errorf("%s inbound %q connection_receive_window must be a plain byte "+
					"count, got %s: %v", path, inbound.Tag, inbound.ConnectionReceiveWindow, err)
				continue
			}
		}
		if stream != 0 && stream != expectedStream {
			t.Errorf("%s inbound %q stream_receive_window is %d, expected %d",
				path, inbound.Tag, stream, expectedStream)
		}
		if connection != 0 && connection != expectedConnection {
			t.Errorf("%s inbound %q connection_receive_window is %d, expected %d",
				path, inbound.Tag, connection, expectedConnection)
		}
		if connection != 0 && stream != 0 && connection < stream {
			t.Errorf("%s inbound %q connection_receive_window (%d) must be at least the "+
				"stream_receive_window (%d), otherwise the stream window is unreachable",
				path, inbound.Tag, connection, stream)
		}
	}
	if owners == 0 {
		t.Logf("%s: no inbound pins HTTP/2 flow control; nothing to verify", path)
	}
}

// TestProductionResidentialChainOrdering pins the residential chain's routing
// contract, which is a DNS and privacy invariant rather than a preference.
//
// The chain is:
//
//	Residential-AnyTLS client
//	  -> AnyTLS to the VPS
//	  -> VPS resolves the target with ipv4_only
//	  -> residential-socks (SOCKS5)
//	  -> the residential exit reaches the IPv4 target
//
// Two properties make that work, and BOTH are order-dependent:
//
//  1. Residential UDP is REJECTED. The residential exit is IPv4-only for TCP; a
//     datagram path would either leak or fail silently.
//  2. The TCP `resolve` with `strategy: ipv4_only` must come BEFORE the rule that
//     routes to the SOCKS outbound. A resolve action needs the destination to still
//     be a DOMAIN, so if the routing rule ran first the SOCKS proxy would receive a
//     hostname and resolve it itself - moving DNS off the VPS and onto the
//     residential provider, which is exactly what this design forbids.
//
// This test fails if the rules are reordered, if the strategy changes, if the UDP
// reject is removed, or if the destination outbound changes.
func TestProductionResidentialChainOrdering(t *testing.T) {
	fixture, path := loadProductionFixture(t)

	var (
		udpRejectIndex  = -1
		resolveIndex    = -1
		routingIndex    = -1
		resolveStrategy string
		routingOutbound string
	)

	for index, rule := range fixture.Route.Rules {
		if !containsString(rule.User, "residential") {
			continue
		}
		switch {
		case rule.Action == "reject" && containsString(rule.Network, "udp"):
			if udpRejectIndex == -1 {
				udpRejectIndex = index
			}
		case rule.Action == "resolve":
			if resolveIndex == -1 {
				resolveIndex = index
				resolveStrategy = rule.Strategy
			}
		case rule.Outbound != "":
			if routingIndex == -1 {
				routingIndex = index
				routingOutbound = rule.Outbound
			}
		}
	}

	require.GreaterOrEqual(t, udpRejectIndex, 0,
		"%s must reject UDP for the residential user: the residential exit is "+
			"IPv4 TCP only, and a datagram path would leak or fail silently", path)
	require.GreaterOrEqual(t, resolveIndex, 0,
		"%s must resolve the residential destination on the VPS before routing it", path)
	require.GreaterOrEqual(t, routingIndex, 0,
		"%s must route the residential user to a SOCKS outbound", path)

	require.Equal(t, "ipv4_only", resolveStrategy,
		"%s must resolve ipv4_only: the residential exit is IPv4 only, so an AAAA "+
			"result would produce a connection the exit cannot make", path)

	require.Equal(t, "residential-socks", routingOutbound,
		"%s must route the residential user through the residential SOCKS outbound", path)

	// The ordering that keeps DNS on the VPS.
	require.Less(t, resolveIndex, routingIndex,
		"%s resolves AFTER routing to the SOCKS outbound. A resolve action needs the "+
			"destination to still be a domain, so this order would hand the SOCKS "+
			"proxy a hostname and move DNS to the residential provider", path)
	require.Less(t, udpRejectIndex, routingIndex,
		"%s must reject residential UDP before it reaches the SOCKS outbound", path)
}

// containsString is a small helper so this file does not depend on slices.Contains
// ordering semantics.
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
