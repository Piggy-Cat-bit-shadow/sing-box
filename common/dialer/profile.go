// Package dialer carries the native-bypass profile: a compact, precomputed answer to "would the
// userspace dial path do anything special for this flow?".
//
// # Why it lives here
//
// This package is where DialerOptions are interpreted: default.go reads each field and decides
// which socket option, bind, mark, network selection or resolver it produces. Anywhere else would
// be a second interpretation, and a second interpretation of the same options is how a newly added
// option silently becomes an unsafe bypass instead of a refusal.
//
// # The two-layer split
//
// The profile answers ONLY the socket question. The router answers the policy question - is this
// flow allowed to skip the userspace path at all, given its inbound, its sniffed domain, its
// FakeIP state, its trackers and its rule verdict. Both must say yes. Neither re-implements the
// other, and a profile that tried to answer the policy question would have to guess at metadata it
// cannot see.
package dialer

import (
	"net/netip"
	"reflect"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// NativeBypassBlocker is a set of reasons a dialer configuration, or a flow, is not equivalent to a
// plain connect performed by the platform.
//
// It is a bitmask rather than a boolean so that a refusal can be attributed. "The fast path is off"
// is not actionable; "the fast path is off because this outbound sets a routing mark" is, and the
// difference is the difference between a tuning exercise and a guess.
type NativeBypassBlocker uint64

// BlockerNone is the empty set: nothing stands in the way.
//
// It is declared outside the bit list so that the list starts at bit zero. Leaving it inside would
// shift every bit by one and leave a hole, which is the kind of thing a diagnostic renders as a
// number nobody can attribute.
const BlockerNone NativeBypassBlocker = 0

const (
	// BlockerUnclassified means this configuration sets an option that the profile has not
	// classified. It is the most important value in this list.
	//
	// A newly added DialerOptions field must not be able to make a bypass SAFE by default. The
	// builder therefore treats "set, but not in the classification table" as a refusal, so the
	// failure mode of forgetting to classify a field is a missed optimisation rather than a
	// discarded socket semantic. A test asserts the table covers the struct, so the omission is
	// also caught before it ships.
	BlockerUnclassified NativeBypassBlocker = 1 << iota

	// BlockerDetour: the connection leaves through another outbound.
	BlockerDetour
	// BlockerBindInterface: the socket is bound to a named interface.
	BlockerBindInterface
	// BlockerBindAddress: the socket is bound to a local address.
	BlockerBindAddress
	// BlockerBindAddressNoPort: the bind is done without a port, which is its own socket option.
	BlockerBindAddressNoPort
	// BlockerProtectPath: the socket is protected from the VPN by path.
	BlockerProtectPath
	// BlockerRoutingMark: packets from the socket carry a routing mark.
	BlockerRoutingMark
	// BlockerReuseAddr: the socket sets SO_REUSEADDR.
	BlockerReuseAddr
	// BlockerNetNs: the socket is created in another network namespace.
	BlockerNetNs
	// BlockerConnectTimeout: the dial has a configured time limit.
	BlockerConnectTimeout
	// BlockerUDPBindPort: the UDP source port is fixed.
	BlockerUDPBindPort
	// BlockerUDPFragment: UDP fragmentation is explicitly configured.
	BlockerUDPFragment
	// BlockerTCPFastOpen: TCP fast open is enabled.
	BlockerTCPFastOpen
	// BlockerTCPMultiPath: MPTCP is enabled.
	BlockerTCPMultiPath
	// BlockerTCPKeepAlive: TCP keepalive is configured away from the default.
	BlockerTCPKeepAlive
	// BlockerDomainResolution: a name must be resolved for this flow, and the outbound carries a
	// resolution policy that would take part in it.
	BlockerDomainResolution
	// BlockerFamilyStrategy: the resolution policy restricts the address family, and this flow's
	// destination is not in the permitted family.
	BlockerFamilyStrategy
	// BlockerNetworkStrategy: interface selection, ordering or fallback is configured.
	BlockerNetworkStrategy
	// BlockerNetworkUnsupported: the flow is not TCP or UDP.
	BlockerNetworkUnsupported
	// BlockerDestinationInvalid: the flow has no usable literal destination.
	BlockerDestinationInvalid
	// BlockerGlobalNetworkPolicy: the ambient network policy - the network manager's default bind
	// interface, routing mark, network strategy or fallback - would be applied to the userspace
	// dial and is not applied by a platform connect.
	BlockerGlobalNetworkPolicy
	// BlockerSelfAddress: the destination is one of this host's own addresses on the interface the
	// dialer serves, which the userspace path refuses in order to keep a TUN from routing a
	// connection back into itself.
	BlockerSelfAddress
)

// blockerNames maps each bit to the name used in diagnostics. A missing entry shows up as a number,
// which is the point: an unnamed blocker is one nobody classified.
var blockerNames = []struct {
	blocker NativeBypassBlocker
	name    string
}{
	{BlockerUnclassified, "unclassified dialer option"},
	{BlockerDetour, "detour"},
	{BlockerBindInterface, "bind_interface"},
	{BlockerBindAddress, "inet4_bind_address/inet6_bind_address"},
	{BlockerBindAddressNoPort, "bind_address_no_port"},
	{BlockerProtectPath, "protect_path"},
	{BlockerRoutingMark, "routing_mark"},
	{BlockerReuseAddr, "reuse_addr"},
	{BlockerNetNs, "netns"},
	{BlockerConnectTimeout, "connect_timeout"},
	{BlockerUDPBindPort, "udp source port"},
	{BlockerUDPFragment, "udp_fragment"},
	{BlockerTCPFastOpen, "tcp_fast_open"},
	{BlockerTCPMultiPath, "tcp_multi_path"},
	{BlockerTCPKeepAlive, "tcp keepalive"},
	{BlockerDomainResolution, "domain_resolver needs to resolve this flow"},
	{BlockerFamilyStrategy, "domain_resolver family strategy excludes this destination"},
	{BlockerNetworkStrategy, "network_strategy/network_type/fallback"},
	{BlockerNetworkUnsupported, "network is not TCP or UDP"},
	{BlockerDestinationInvalid, "destination is not a usable literal address"},
	{BlockerGlobalNetworkPolicy, "ambient network policy (bind interface, routing mark, strategy)"},
	{BlockerSelfAddress, "destination is this host's own address"},
}

// String names the set bits, for diagnostics and test failures. It allocates, so it is never on a
// data path: the router calls it at most once per refused flow, and only when a caller asked.
func (b NativeBypassBlocker) String() string {
	if b == BlockerNone {
		return "none"
	}
	var names []string
	for _, entry := range blockerNames {
		if b&entry.blocker != 0 {
			names = append(names, entry.name)
		}
	}
	if len(names) == 0 {
		return "unknown blockers (" + strconv.FormatUint(uint64(b), 10) + ")"
	}
	return strings.Join(names, ", ")
}

// NativeBypassFacts are the flow properties the socket layer needs in order to answer.
//
// It is deliberately four small fields and not a metadata object. The router owns the metadata; a
// dialer that took it would have to know about inbounds, rules and FakeIP, which is the layering
// this split exists to prevent.
type NativeBypassFacts struct {
	// Network is N.NetworkTCP or N.NetworkUDP. Anything else is refused.
	Network string
	// DestinationIsLiteral must be set to true by a caller that has established nothing will
	// resolve a name for this flow.
	//
	// The polarity is deliberate. A caller that forgets it gets the conservative answer, and a
	// caller that cannot express the question - some future BypassableOutbound asked about a domain
	// - cannot accidentally claim a literality it does not have.
	DestinationIsLiteral bool
	// Destination is the literal address, used for the family check and the zone check.
	Destination netip.Addr
	// FamilyStrategy is the family restriction the resolution policy would apply to this flow. It
	// is asked of the live dialer rather than read from the options, because the effective value
	// can come from the resolver's own configuration when the options leave it unset.
	FamilyStrategy C.DomainStrategy
}

// SocketSemantics is the precomputed profile of a set of DialerOptions.
//
// It is built once, when the dialer is built, and then answers per flow without reflection, without
// maps, without allocation and without re-reading the options. The zero value is a profile with no
// blockers, which is what a plain connect looks like.
type SocketSemantics struct {
	// always blocks every flow.
	always NativeBypassBlocker
	// tcpOnly and udpOnly block one network.
	tcpOnly NativeBypassBlocker
	udpOnly NativeBypassBlocker
	// resolutionOnly blocks only a flow that has a name resolved for it.
	resolutionOnly NativeBypassBlocker
}

// NativeBypassSemantics interprets options once into a profile.
//
// # Reflection, once, at construction
//
// The walk is driven by a classification table rather than by hand-written conditionals. That is
// what makes the completeness requirement enforceable: every field of the options struct must
// appear in the table, a test asserts it, and a field that is set without appearing there is
// refused at runtime rather than ignored. A hand-written version would have to be remembered in two
// places - the code and the test - and the two would drift.
//
// The cost is a reflect walk per outbound, not per flow and not per packet.
func NativeBypassSemantics(options option.DialerOptions) SocketSemantics {
	var semantics SocketSemantics
	visitDialerOptionFields(reflect.ValueOf(&options).Elem(), func(name string, field reflect.Value) {
		classification, classified := dialerOptionClassification[name]
		if !classified {
			if !field.IsZero() {
				// Fail closed. See BlockerUnclassified.
				semantics.always |= BlockerUnclassified
			}
			return
		}
		if classification.scope == scopeIgnore || field.IsZero() {
			return
		}
		switch classification.scope {
		case scopeAlways:
			semantics.always |= classification.blocker
		case scopeTCPOnly:
			semantics.tcpOnly |= classification.blocker
		case scopeUDPOnly:
			semantics.udpOnly |= classification.blocker
		case scopeResolutionOnly:
			semantics.resolutionOnly |= classification.blocker
		}
	})
	return semantics
}

// visitDialerOptionFields walks the struct's fields, following embedded structs, and calls visit
// for each leaf field with its Go name.
func visitDialerOptionFields(value reflect.Value, visit func(name string, field reflect.Value)) {
	valueType := value.Type()
	for index := 0; index < valueType.NumField(); index++ {
		field := value.Field(index)
		fieldType := valueType.Field(index)
		if fieldType.Anonymous && field.Kind() == reflect.Struct {
			visitDialerOptionFields(field, visit)
			continue
		}
		if !field.CanInterface() {
			continue
		}
		visit(fieldType.Name, field)
	}
}

// Blockers reports every reason this profile cannot reproduce the userspace path for this flow.
// The empty set means it can: the caller must treat any non-empty set as a refusal.
func (s SocketSemantics) Blockers(facts NativeBypassFacts) NativeBypassBlocker {
	blockers := s.always
	switch facts.Network {
	case N.NetworkTCP:
		blockers |= s.tcpOnly
	case N.NetworkUDP:
		blockers |= s.udpOnly
	default:
		blockers |= BlockerNetworkUnsupported
	}
	if !facts.DestinationIsLiteral {
		// A flow that must resolve a name needs the resolution policy, whatever it is.
		blockers |= s.resolutionOnly
		if s.resolutionOnly == 0 {
			// No policy is configured, so resolution would go through the router's default path -
			// which is not the platform's own connect either.
			blockers |= BlockerDomainResolution
		}
	} else if s.resolutionOnly != 0 {
		// The resolver is not consulted for a literal destination, with one exception that is not
		// obvious and is the reason this check is here at all: a hard single-family policy also
		// filters the LITERAL address, because the dial path applies it to the original attempt and
		// not only to resolved candidates. A profile that stopped at "the resolver is not used for
		// literals" would bypass a flow the userspace path would have refused to dial.
		if !AddressAllowedByStrategy(facts.Destination, facts.FamilyStrategy) {
			blockers |= BlockerFamilyStrategy
		}
	}
	if !facts.Destination.IsValid() || facts.Destination.Zone() != "" {
		// The platform's direct path for a bypassed flow is keyed by address alone.
		blockers |= BlockerDestinationInvalid
	}
	return blockers
}

// CanNativeBypass reports whether this profile reproduces a plain connect for this flow.
func (s SocketSemantics) CanNativeBypass(facts NativeBypassFacts) bool {
	return s.Blockers(facts) == BlockerNone
}

// IsPlain reports whether these options ask the socket layer for nothing at all.
//
// It is the question "does this configuration do anything?", which is what makes a detour to a
// direct outbound pointless and is NOT the same as "may this flow bypass". A direct outbound with
// only a domain_resolver is not plain - it resolves names - while a literal-IP flow through it is
// still reproducible by the platform. Answering both questions from one interpretation is what
// keeps them from disagreeing.
func (s SocketSemantics) IsPlain() bool {
	return s.always|s.tcpOnly|s.udpOnly|s.resolutionOnly == BlockerNone
}

// NetworkPolicyBlockers reports what the AMBIENT network policy would do to a userspace dial.
//
// # Why this is asked separately from the options
//
// A direct outbound with no dial options at all still inherits from the network manager: a default
// bind interface adds a socket bind, a default routing mark adds a mark wrapper, and a default
// strategy adds interface selection. A platform connect performs none of those, so the connection
// would silently lose policy the operator set globally rather than on this outbound.
//
// It is asked per flow rather than captured at construction because the manager's defaults are
// live state: an interface change can add or remove a bind while the outbound is running, and a
// cached answer would keep bypassing a flow that policy has since started to cover.
func NetworkPolicyBlockers(networkManager adapter.NetworkManager) NativeBypassBlocker {
	if networkManager == nil {
		return BlockerNone
	}
	defaults := networkManager.DefaultOptions()
	if defaults.BindInterface != "" ||
		defaults.RoutingMark != 0 ||
		defaults.NetworkStrategy != nil ||
		len(defaults.NetworkType) > 0 ||
		len(defaults.FallbackNetworkType) > 0 ||
		defaults.FallbackDelay != 0 {
		return BlockerGlobalNetworkPolicy
	}
	return BlockerNone
}

// optionScope says when an option matters.
type optionScope uint8

const (
	// scopeIgnore: not a socket semantic for a bypass decision.
	//
	// Every entry here needs a reason, because "ignore" is the one classification that can make a
	// bypass unsafe. The two that exist are internal fields no configuration can set, plus the
	// constructor's own UDP-fragment default.
	scopeIgnore optionScope = iota
	// scopeAlways: any non-zero value changes the socket the userspace path would use.
	scopeAlways
	// scopeTCPOnly: the option is applied to the TCP socket only.
	scopeTCPOnly
	// scopeUDPOnly: the option is applied to the UDP socket only.
	scopeUDPOnly
	// scopeResolutionOnly: the option only takes part when a name is resolved.
	scopeResolutionOnly
)

type optionClassification struct {
	blocker NativeBypassBlocker
	scope   optionScope
}

// dialerOptionClassification is the single source of truth for what each DialerOptions field means
// to a native bypass. The comments carry the reason, because the reason is the part that cannot be
// recovered from the code.
//
// The scopes were read off common/dialer/default.go and resolve.go, which is where each field is
// actually applied. A field that is applied to the TCP dialer is scopeTCPOnly, one applied to the
// UDP listener is scopeUDPOnly, and one that only reaches the resolver is scopeResolutionOnly.
var dialerOptionClassification = map[string]optionClassification{
	"Detour": {BlockerDetour, scopeAlways},

	// Every field below reaches dialer.Control or listenConfig.Control, which is a socket option,
	// a bind or a mark. None of them can be reproduced by the platform performing the connect.
	"BindInterface":     {BlockerBindInterface, scopeAlways},
	"Inet4BindAddress":  {BlockerBindAddress, scopeAlways},
	"Inet6BindAddress":  {BlockerBindAddress, scopeAlways},
	"BindAddressNoPort": {BlockerBindAddressNoPort, scopeAlways},
	"ProtectPath":       {BlockerProtectPath, scopeAlways},
	"RoutingMark":       {BlockerRoutingMark, scopeAlways},
	"NetNs":             {BlockerNetNs, scopeAlways},

	// ReuseAddr is applied to listenConfig only - the UDP listener - never to dialer.Control, so a
	// TCP bypass does not lose it. This is the flow-sensitivity the profile exists for, and it is
	// read off the code rather than guessed from the name.
	"ReuseAddr": {BlockerReuseAddr, scopeUDPOnly},

	// ConnectTimeout sets dialer.Timeout, which is a userspace dial deadline. A bypassed flow is
	// dialled by the application, with the application's deadline, so a configured value here would
	// be silently dropped. Zero means the dialer's own default and is not a configuration.
	"ConnectTimeout": {BlockerConnectTimeout, scopeAlways},

	// The TCP-only socket options. Applied to the TCP dialer, and to a UDP listener only as part of
	// the shared net.Dialer copy when they happen to be harmless there - which is why they are
	// classified per network rather than per configuration.
	"TCPFastOpen":          {BlockerTCPFastOpen, scopeTCPOnly},
	"TCPMultiPath":         {BlockerTCPMultiPath, scopeTCPOnly},
	"DisableTCPKeepAlive":  {BlockerTCPKeepAlive, scopeTCPOnly},
	"TCPKeepAlive":         {BlockerTCPKeepAlive, scopeTCPOnly},
	"TCPKeepAliveInterval": {BlockerTCPKeepAlive, scopeTCPOnly},
	// Not reachable from JSON, but a caller can set it and it changes keepalive behaviour.
	"TCPKeepAliveSystemDefaults": {BlockerTCPKeepAlive, scopeTCPOnly},

	// The UDP source port is fixed on the datagram socket.
	"UDPBindPort": {BlockerUDPBindPort, scopeUDPOnly},

	// UDP fragment is a socket option on both the dialer and the listener, so it matters for UDP.
	"UDPFragment": {BlockerUDPFragment, scopeUDPOnly},
	// UDPFragmentDefault is NOT a configuration: the direct constructor sets it to true, and
	// honouring it here would refuse every direct outbound. It is the default the userspace UDP path
	// has always used, and the native path's own default is the kernel's - see the package
	// documentation for why that difference is accepted rather than treated as a lost option.
	"UDPFragmentDefault": {scope: scopeIgnore},

	// Interface selection: strategy, type, fallback type and the delay that governs the fallback.
	// Also used by the resolver's dual-stack racing, which is a second reason it cannot be ignored.
	"NetworkStrategy":     {BlockerNetworkStrategy, scopeAlways},
	"NetworkType":         {BlockerNetworkStrategy, scopeAlways},
	"FallbackNetworkType": {BlockerNetworkStrategy, scopeAlways},
	"FallbackDelay":       {BlockerNetworkStrategy, scopeAlways},
	"DomainResolver":      {BlockerDomainResolution, scopeResolutionOnly},
	"DomainStrategy":      {BlockerDomainResolution, scopeResolutionOnly},
}
