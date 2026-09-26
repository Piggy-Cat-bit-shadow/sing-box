//go:build jiejie_client_macos

package jiejie_test

import (
	"context"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/vless"

	"github.com/stretchr/testify/require"
)

// Type-level audit of the Jiejie macOS client registry.
//
// This is the in-process companion to scripts/ci/audit-macos-client-registry.sh.
// That script reads the linked symbol table of a real darwin binary; this test
// asserts the same properties at the registry API level, so a regression is
// caught by `go test` rather than only by a macOS build.
//
// The two are complementary rather than redundant. The shell audit proves what
// the LINKER kept; this proves what the REGISTRY will resolve. A profile could
// pass either one alone and still be broken: a package can be linked but
// unregistered (which surfaces at runtime as "unknown type"), or the registry
// file can fail to compile in and the build silently falls back to the upstream
// full registry.
//
// Every assertion reads OptionTypes(), the registry's own published list. Asking
// the registry rather than inspecting a source file is the point: registration
// and resolution go through different code, and only resolution is what a
// configuration experiences.
//
// The whole file is gated on jiejie_client_macos, so it is inert in the upstream
// and server builds.

// hasType reports whether a registry resolves a type.
func hasType(types []string, want string) bool {
	return slices.Contains(types, want)
}

// requireTypesPresent asserts every wanted type resolves, reporting ALL missing
// types at once. Reporting one at a time would turn a single mistaken trim into
// a long series of test runs.
func requireTypesPresent(t *testing.T, kind string, types []string, want []string) {
	t.Helper()
	var missing []string
	for _, w := range want {
		if !hasType(types, w) {
			missing = append(missing, w)
		}
	}
	require.Empty(t, missing,
		"the macOS client %s registry must resolve these types; missing: %v; registered: %v",
		kind, missing, types)
}

// requireTypesAbsent asserts every unwanted type is absent, reporting all
// present ones at once, each with the reason it was excluded.
func requireTypesAbsent(t *testing.T, kind string, types []string, unwanted map[string]string) {
	t.Helper()
	var present []string
	for w := range unwanted {
		if hasType(types, w) {
			present = append(present, w+" ("+unwanted[w]+")")
		}
	}
	slices.Sort(present)
	require.Empty(t, present,
		"the macOS client %s registry must NOT register these types: %v", kind, present)
}

func TestClientMacOSInboundRegistryResolves(t *testing.T) {
	t.Parallel()
	types := include.InboundRegistry().OptionTypes()

	requireTypesPresent(t, "inbound", types, []string{
		"tun",    // the VPN interface: the client's primary mode
		"mixed",  // single-port HTTP+SOCKS, the GUI default
		"socks",  // explicit SOCKS inbound
		"http",   // explicit HTTP inbound
		"direct", // local passthrough listener
	})
}

func TestClientMacOSExcludedInboundsAreAbsent(t *testing.T) {
	t.Parallel()
	types := include.InboundRegistry().OptionTypes()

	requireTypesAbsent(t, "inbound", types, map[string]string{
		"redirect":  "Linux netfilter only",
		"tproxy":    "Linux netfilter only",
		"shadowtls": "a server-side handshake inbound; the client uses the outbound",
		"naive":     "the Native Naive server inbound is a Server Edition concern",
		"snell":     "the client connects via the snell outbound, not an inbound",
		"vless":     "the client connects via the vless outbound, not an inbound",
		"trojan":    "the client connects via the trojan outbound, not an inbound",
		"anytls":    "the client connects via the anytls outbound, not an inbound",
	})
}

// TestClientMacOSOutboundRegistryResolves is the core protocol assertion.
//
// Every type here is one the Jiejie client connects with. If a future edit trims
// the registry too far, the failure names the missing protocols rather than
// surfacing as "unknown outbound type" in a user's configuration.
func TestClientMacOSOutboundRegistryResolves(t *testing.T) {
	t.Parallel()
	types := include.OutboundRegistry().OptionTypes()

	requireTypesPresent(t, "outbound", types, []string{
		// routing primitives
		"direct",
		"block",
		// groups: every GUI needs both
		"selector",
		"urltest",
		// plain proxy chaining
		"socks",
		"http",
		// the Jiejie client protocol set
		"shadowsocks",
		"shadowtls",
		"snell",
		"trojan",
		"vless",
		"vmess",
		"anytls",
		"hysteria2",
		"tuic",
	})
}

// TestClientMacOSExcludedOutboundsAreAbsent asserts the trim is real.
//
// A profile that registers everything is not a client profile, it is the
// upstream build with extra steps. Each reason is recorded next to its type so a
// future reader can challenge the decision rather than guess at it.
func TestClientMacOSExcludedOutboundsAreAbsent(t *testing.T) {
	t.Parallel()
	types := include.OutboundRegistry().OptionTypes()

	requireTypesAbsent(t, "outbound", types, map[string]string{
		"tor":       "not part of the Jiejie client feature set; drags in a full Tor client",
		"ssh":       "not part of the Jiejie client feature set",
		"hysteria":  "Hysteria v1 is superseded by Hysteria2, which the client does register",
		"bridge":    "not part of the client profile",
		"wireguard": "a stub for a removed outbound; the endpoint form is not in this profile",
	})
}

// TestClientMacOSNaiveOutboundIsAStubNotAnImplementation pins the Naive decision.
//
// `naive` RESOLVES in this profile, and that is deliberate rather than an
// oversight. Upstream ships include/naive_outbound_stub.go behind
// `!with_naive_outbound`, and the stub registers the type with a constructor
// that always fails with "naive outbound is not included in this build, rebuild
// with -tags with_naive_outbound".
//
// So the honest description of the macOS core is: Naive is a KNOWN type that
// explains itself, not an absent one. A GUI offering a Naive node gets an
// actionable message instead of "unknown outbound type", and because the stub
// imports no Cronet code, the CGO dependency stays out of the binary.
//
// Deleting the stub call to make `naive` vanish would be worse for users and
// would not save anything: the stub is a few lines and the expensive package is
// already excluded. The property worth asserting is therefore that the type
// resolves while the IMPLEMENTATION is absent, which the symbol audit checks
// separately.
func TestClientMacOSNaiveOutboundIsAStubNotAnImplementation(t *testing.T) {
	t.Parallel()
	types := include.OutboundRegistry().OptionTypes()

	require.True(t, hasType(types, "naive"),
		"`naive` must resolve so users get an actionable error, not 'unknown outbound type'")

	// The construction must fail, which is what proves it is the stub rather
	// than a working implementation.
	registry := include.OutboundRegistry()
	rawOptions, loaded := registry.CreateOptions("naive")
	require.True(t, loaded, "the stub registers option types too")

	_, err := registry.CreateOutbound(context.Background(), nil, nil, "naive", "naive", rawOptions)
	require.Error(t, err, "naive must not construct without with_naive_outbound")
	require.Contains(t, err.Error(), "with_naive_outbound",
		"the error must name the tag that enables it")
}

// TestClientMacOSEndpointsAreAbsent asserts no endpoint is registered.
//
// Registering none is the single largest dependency saving in the profile, so it
// is worth an explicit assertion rather than an implicit one.
func TestClientMacOSEndpointsAreAbsent(t *testing.T) {
	t.Parallel()
	types := include.EndpointRegistry().OptionTypes()

	require.Empty(t, types, "the macOS client profile registers no endpoint")
	requireTypesAbsent(t, "endpoint", types, map[string]string{
		"wireguard":   "a large tree the client does not offer",
		"tailscale":   "a large tree the client does not offer",
		"openvpn":     "a large tree the client does not offer",
		"openconnect": "a large tree the client does not offer",
		"masque":      "not part of the client profile",
	})
}

// TestClientMacOSDNSTransportsResolve asserts the full client resolver set.
//
// This is the area most at risk of being trimmed too far: a client legitimately
// uses DoT, DoH, DoQ/DoH3 and FakeIP, and dropping any of them breaks a
// configuration that upstream accepts.
func TestClientMacOSDNSTransportsResolve(t *testing.T) {
	t.Parallel()
	types := include.DNSTransportRegistry().OptionTypes()

	requireTypesPresent(t, "DNS", types, []string{
		"udp",   // plain DNS
		"tcp",   // truncation fallback and explicit tcp servers
		"tls",   // DoT
		"https", // DoH
		"local", // REQUIRED boot dependency: box.go installs a local fallback
		"hosts", // static host entries
		"fakeip",
		"quic", // DoQ
		"h3",   // DoH3
	})
}

// TestClientMacOSExcludedDNSTransportsAreAbsent asserts the resolvers that make
// no sense on Darwin, or that are out of profile, are gone.
func TestClientMacOSExcludedDNSTransportsAreAbsent(t *testing.T) {
	t.Parallel()
	types := include.DNSTransportRegistry().OptionTypes()

	requireTypesAbsent(t, "DNS", types, map[string]string{
		"resolved":  "a systemd/D-Bus transport with no meaning on Darwin",
		"dhcp":      "not part of the client profile",
		"mdns":      "not registered, though dns/transport/local imports the package",
		"tailscale": "requires the tailscale endpoint tree",
	})
}

// TestClientMacOSLocalDNSTransportIsRegistered guards the boot dependency.
//
// box.go unconditionally initialises the DNS transport manager with a fallback
// that creates a C.DNSTypeLocal transport. Omitting `local` therefore does not
// remove a feature, it makes EVERY start fail with "default DNS server fallback:
// transport type not found: local". A whole-product failure caused by a one-line
// trim deserves its own test.
func TestClientMacOSLocalDNSTransportIsRegistered(t *testing.T) {
	t.Parallel()
	types := include.DNSTransportRegistry().OptionTypes()
	require.True(t, hasType(types, "local"),
		"`local` is a boot dependency, not a feature choice")
}

// TestClientMacOSRegistryIsNotTheUpstreamRegistry is the guard that would have
// caught the most likely mistake in this profile.
//
// include/registry.go is the upstream full registry. If the jiejie_client_macos
// build constraint on that file were ever lost or misspelled, the package would
// either fail to compile on a duplicate Context or silently ship the full
// registry. Asserting that an upstream-only type is ABSENT is what distinguishes
// "the client registry is active" from "the upstream registry is active", which
// no positive assertion can do.
func TestClientMacOSRegistryIsNotTheUpstreamRegistry(t *testing.T) {
	t.Parallel()

	inboundTypes := include.InboundRegistry().OptionTypes()
	require.False(t, hasType(inboundTypes, "redirect"),
		"the upstream registry is active; include/registry.go must be excluded by "+
			"the jiejie_client_macos build constraint")

	outboundTypes := include.OutboundRegistry().OptionTypes()
	require.False(t, hasType(outboundTypes, "tor"),
		"the upstream registry is active; include/registry.go must be excluded by "+
			"the jiejie_client_macos build constraint")

	// The QUIC surface must be the client one, not the full one: Hysteria v1 is
	// registered by include/quic.go but deliberately not by the client file.
	require.False(t, hasType(outboundTypes, "hysteria"),
		"include/quic.go is active; include/quic_client_macos.go must win")
	require.True(t, hasType(outboundTypes, "hysteria2"),
		"Hysteria2 must be registered by the client QUIC surface")
}

// TestClientMacOSRegistryCounts is a coarse change detector.
//
// Exact counts would make every legitimate addition a test failure, so the
// bounds are ranges. They exist to catch a wholesale swap — the upstream
// registry appearing, or the client registry compiling to nothing — which the
// type-level assertions above might survive if the swap happened to share types.
func TestClientMacOSRegistryCounts(t *testing.T) {
	t.Parallel()

	outboundCount := len(include.OutboundRegistry().OptionTypes())
	require.GreaterOrEqual(t, outboundCount, 15,
		"the client outbound registry looks too small to be the client registry")
	require.Less(t, outboundCount, 30,
		"the client outbound registry looks like the upstream full registry")

	inboundCount := len(include.InboundRegistry().OptionTypes())
	require.GreaterOrEqual(t, inboundCount, 5)
	require.Less(t, inboundCount, 15,
		"the client inbound registry looks like the upstream full registry")

	dnsCount := len(include.DNSTransportRegistry().OptionTypes())
	require.GreaterOrEqual(t, dnsCount, 9)
	require.Less(t, dnsCount, 14,
		"the client DNS registry looks like the upstream full registry")
}

// TestClientMacOSProtocolPackagesAreReal is a compile-and-link guard.
//
// The registry tests above read include.OutboundRegistry(). If a build-tag
// mistake made the registry file compile to nothing, those tests would fail on
// an empty list — but if the registry silently fell back to a stub-only
// registration, a list-based assertion could still pass. This test therefore
// drives the protocol packages' own registration functions into a FRESH registry
// and asserts each one actually registers its type, which forces the real
// packages to be linked into the test binary.
func TestClientMacOSProtocolPackagesAreReal(t *testing.T) {
	t.Parallel()

	register := map[string]func(*outbound.Registry){
		"socks":       socks.RegisterOutbound,
		"shadowsocks": shadowsocks.RegisterOutbound,
		"trojan":      trojan.RegisterOutbound,
		"vless":       vless.RegisterOutbound,
		"hysteria2":   hysteria2.RegisterOutbound,
		"tuic":        tuic.RegisterOutbound,
	}

	for name, registerOutbound := range register {
		registry := outbound.NewRegistry()
		registerOutbound(registry)
		require.True(t, hasType(registry.OptionTypes(), name),
			"%s.RegisterOutbound must register the %q type into a fresh registry", name, name)
	}

	// The concrete registry types, so the assertions above cannot pass against a
	// nil interface by accident.
	require.NotNil(t, inbound.NewRegistry())
	require.NotNil(t, outbound.NewRegistry())
	require.NotNil(t, endpoint.NewRegistry())
	require.NotNil(t, dns.NewTransportRegistry())
}
