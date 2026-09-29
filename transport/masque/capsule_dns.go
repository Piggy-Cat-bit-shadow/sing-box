package masque

import (
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/idna"
)

// DNS_ASSIGN and PREF64 capsules, defined by draft-ietf-masque-connect-ip-dns-06.
//
// # Wire format provenance
//
// Both type IDs are PROVISIONAL in the draft's own IANA table, which states they
// "will be replaced by a smaller one before publication". They are therefore named
// constants here rather than inline literals, so a future revision is a one-line
// change. The values were cross-checked against two independent sources:
//
//	draft-ietf-masque-connect-ip-dns-06  (the normative document)
//	quic-go/connect-ip-go                (the reference implementation)
//
// Both agree on 0x1ace79ec and 0x274c0fbc, and on the byte layouts below.
//
// # Why these are not simply "parse and discard"
//
// The draft is explicit that the receiver decides whether to use the configuration,
// and that acting on it "can have significant impact on endpoint security". A parser
// that discarded the result would satisfy the wire format and none of the intent, so
// these types are the input to real client state: the assigned-DNS transport reads
// them, and the resolver precedence in the endpoint consults them.
const (
	// capsuleTypeDNSAssign carries DNS configuration.
	//
	//	draft-ietf-masque-connect-ip-dns-06 §3.4
	capsuleTypeDNSAssign = 0x1ace79ec
	// capsuleTypePREF64 carries NAT64 prefixes for IPv6/IPv4 synthesis.
	//
	//	draft-ietf-masque-connect-ip-dns-06 §4.1
	capsuleTypePREF64 = 0x274c0fbc
)

// Bounds.
//
// The draft does not specify limits; these follow the reference implementation, which
// is the same approach the existing ADDRESS_ASSIGN bounds in this file take. The
// capsule-size limit is the important one and its rationale is the reference's own:
// the wire size is bounded, but PARSING amplifies memory use substantially, so a
// generous wire limit would still admit an unbounded allocation.
const (
	// maxDNSAssignCapsuleSize bounds the whole capsule before parsing.
	//
	// The reference comments that parsing "can amplify memory use by roughly 50x",
	// and 32 KiB is chosen there for that reason. This repository already carries a
	// 1 MiB per-capsule ceiling, which is far too loose for a structure with this
	// amplification factor, so the tighter DNS-specific limit is applied on top.
	maxDNSAssignCapsuleSize = 32 << 10
	// maxPREF64Prefixes bounds a PREF64 capsule. 13 bytes per prefix, so this is a
	// 3328-byte payload against a 1 MiB capsule ceiling.
	maxPREF64Prefixes = 256
	// maxDomainNameLen is the RFC 1035 §2.3.4 domain length limit, in octets.
	maxDomainNameLen = 255
	// maxServiceParametersLen is bounded by the 16-bit RDLENGTH of SVCB parameters
	// (RFC 1035 §4.1.3).
	maxServiceParametersLen = 1<<16 - 1
	// Per-count limits for the repeated structures.
	//
	// The reference has NO count limits and relies solely on the capsule-size check.
	// This fork's existing capsule parsers do bound their repeated entries (see
	// maxAddressesPerCapsule), and relying on the size check alone leans on the
	// parser erroring out when bytes run short rather than on an explicit bound. The
	// explicit limits are kept for consistency with the rest of this file and so the
	// failure is a clear "too many" rather than a truncation error several fields in.
	maxDNSNameserversPerConfig = 256
	maxDNSDomainsPerConfig     = 1024
	maxDNSConfigurations       = 64
	maxSVCParamsPerNameserver  = 64
)

// DNSNameserver describes the Nameserver structure of the draft.
//
// Field semantics follow §3.2 and the reference:
type DNSNameserver struct {
	// ServicePriority is the SVCB ServiceMode priority. The draft requires it to be
	// non-zero, because this specification relies on ServiceMode (SVCB §2.4.3).
	ServicePriority uint16
	// IPv4Addresses are reachable addresses for this nameserver.
	IPv4Addresses []netip.Addr
	// IPv6Addresses are reachable addresses for this nameserver. Scoped addresses are
	// rejected: a zone identifier is local to an endpoint and is not part of this
	// wire format.
	IPv6Addresses []netip.Addr
	// AuthenticationDomainName is the nameserver's FQDN in DNS presentation format,
	// including the trailing root dot, using IDNA A-labels. It may be empty, and the
	// draft permits that only when the nameserver supports unencrypted DNS.
	AuthenticationDomainName string
	// ServiceParameters are the SVCB parameters applying to this nameserver, in
	// wire-format keys whose values are the wire-format SvcParamValue.
	ServiceParameters map[dnsmessage.SVCParamKey][]byte
}

// DNSConfiguration describes the DNS Configuration structure of the draft.
type DNSConfiguration struct {
	Nameservers []DNSNameserver
	// InternalDomains are FQDNs this configuration is responsible for, including
	// subdomains. An empty string means the DNS root, i.e. every name.
	InternalDomains []string
	// SearchDomains are FQDNs to use as search domains. Empty is rejected.
	SearchDomains []string
}

// DNSAssignment is the resolved form of a DNS_ASSIGN capsule.
//
// The draft permits multiple DNS configurations in one capsule, "if different DNS
// servers are responsible for separate internal domains". The client-facing view
// flattens that to the single configuration it will actually use; see
// DNSAssignment.SelectNameservers.
type DNSAssignment struct {
	Configurations []DNSConfiguration
	// Generation increments on every accepted capsule, so consumers (and the DNS
	// transport environment) can tell one assignment from the next without comparing
	// the contents.
	Generation uint64
}

// dnsNameProfile mirrors the reference's IDNA profile.
var dnsNameProfile = idna.New(
	idna.MapForLookup(),
	idna.StrictDomainName(false),
	idna.BidiRule(),
	idna.VerifyDNSLength(true),
)

// validateDomainName enforces the draft's domain rules.
//
// It rejects non-ASCII (U-labels are not permitted on the wire), requires a trailing
// root dot, and requires the result to be a valid IDNA A-label. The comparison is
// case-insensitive because the IDNA profile is MapForLookup, which lowercases, so an
// upper-case A-label such as XN--BCHER-KVA.example. is legal.
func validateDomainName(name string, allowEmpty bool) error {
	if name == "" {
		if allowEmpty {
			return nil
		}
		return E.New("domain name must not be empty")
	}
	for i := range len(name) {
		if name[i] >= utf8.RuneSelf {
			return E.New("domain name must use IDNA A-label form")
		}
	}
	stripped, ok := strings.CutSuffix(name, ".")
	if !ok {
		return E.New("domain name must be an FQDN")
	}
	ascii, err := dnsNameProfile.ToASCII(stripped)
	if err != nil {
		return E.Cause(err, "domain name must be a valid IDNA A-label")
	}
	if !strings.EqualFold(ascii, stripped) {
		return E.New("domain name must use IDNA A-label form")
	}
	return nil
}

// validate applies every semantic rule the draft states for a configuration.
//
// This runs on the RECEIVING side. The reference runs the same checks on both sides,
// which is worth mirroring: a validating encoder is what stops this implementation
// from emitting configurations a conforming peer must reject.
func (c DNSConfiguration) validate() error {
	// The count bounds live here rather than only in the parser so the encoder and the
	// parser enforce ONE rule set. Keeping them in the parser alone allowed the parser to
	// accept what the encoder refused, which the DNS_ASSIGN round-trip fuzzer found
	// immediately: a configuration the parser had accepted could not be re-encoded, so a
	// message's validity depended on which side read it.
	if len(c.Nameservers) > maxDNSNameserversPerConfig {
		return E.New("too many nameservers in one configuration (maximum ",
			maxDNSNameserversPerConfig, ")")
	}
	if len(c.InternalDomains) > maxDNSDomainsPerConfig {
		return E.New("too many internal domains (maximum ", maxDNSDomainsPerConfig, ")")
	}
	if len(c.SearchDomains) > maxDNSDomainsPerConfig {
		return E.New("too many search domains (maximum ", maxDNSDomainsPerConfig, ")")
	}
	for index, nameserver := range c.Nameservers {
		if nameserver.ServicePriority == 0 {
			return E.New("nameserver ", index, ": service priority must not be zero")
		}
		if len(nameserver.ServiceParameters) > maxSVCParamsPerNameserver {
			return E.New("nameserver ", index, ": too many SVC parameters (maximum ",
				maxSVCParamsPerNameserver, ")")
		}
		var serviceParametersLen int
		var hasALPN, hasNoDefaultALPN bool
		for key, value := range nameserver.ServiceParameters {
			if len(value) > maxServiceParametersLen {
				return E.New("nameserver ", index, ": service parameter value too long")
			}
			// 4 bytes of header per parameter, per the SVCB wire format.
			serviceParametersLen += 4 + len(value)
			switch key {
			case dnsmessage.SVCParamALPN:
				hasALPN = true
			case dnsmessage.SVCParamNoDefaultALPN:
				hasNoDefaultALPN = true
			case dnsmessage.SVCParamIPv4Hint, dnsmessage.SVCParamIPv6Hint:
				// The draft forbids these explicitly: they are superseded by the
				// address lists carried in the same structure.
				return E.New("nameserver ", index, ": service parameter ", key, " is not allowed")
			}
		}
		if serviceParametersLen > maxServiceParametersLen {
			return E.New("nameserver ", index, ": service parameters too long")
		}
		if err := validateDomainName(nameserver.AuthenticationDomainName, true); err != nil {
			return E.Cause(err, "nameserver ", index, ": invalid authentication domain name")
		}
		// ALPN parameters describe an ENCRYPTED transport, which is meaningless
		// without a name to authenticate it against.
		if nameserver.AuthenticationDomainName == "" && (hasALPN || hasNoDefaultALPN) {
			return E.New("nameserver ", index,
				": ALPN service parameters require an authentication domain name")
		}
		// Address requirement, applied only when the nameserver actually offers
		// unencrypted DNS.
		//
		// # A conflict inside the draft, and which side this takes
		//
		// §3.2 states that when no-default-alpn is omitted the nameserver "supports
		// unencrypted DNS", and that in that case the address count "MUST be nonzero".
		// Taken literally that rejects the draft's OWN §3.6.1 full-tunnel example,
		// which carries alpn=h2,h3, no no-default-alpn, and ZERO addresses. The
		// reference implementation enforces the literal rule, so it would reject that
		// example too.
		//
		// The rule's stated purpose is to guarantee an address for the unencrypted
		// transports it infers. When the ALPN parameter is PRESENT that inference does
		// not hold: the ALPN list names the encrypted transports explicitly, which is
		// precisely the shape §3.6.1 uses to reach a nameserver by name alone.
		//
		// So the requirement applies only when ALPN is absent. This accepts strictly
		// more than the reference does, which is interop-safe on receive (anything the
		// reference sends still validates here), and it keeps every draft example
		// valid. It does NOT weaken the send path: a nameserver with neither an
		// address nor an ALPN list is still ambiguous and still refused.
		if !hasALPN && !hasNoDefaultALPN &&
			len(nameserver.IPv4Addresses)+len(nameserver.IPv6Addresses) == 0 {
			return E.New("nameserver ", index,
				": must have an address when no-default-alpn is omitted")
		}
		for _, address := range nameserver.IPv4Addresses {
			if !address.Is4() {
				return E.New("nameserver ", index, ": non-IPv4 address in IPv4 address list: ", address)
			}
		}
		for _, address := range nameserver.IPv6Addresses {
			if !address.Is6() || address.Is4In6() {
				return E.New("nameserver ", index, ": non-IPv6 address in IPv6 address list: ", address)
			}
			if address.Zone() != "" {
				return E.New("nameserver ", index, ": IPv6 address with zone: ", address)
			}
		}
	}
	for _, domain := range c.InternalDomains {
		// Empty is legal here and means the DNS root.
		if err := validateDomainName(domain, true); err != nil {
			return E.Cause(err, "invalid internal domain name")
		}
	}
	for _, domain := range c.SearchDomains {
		if err := validateDomainName(domain, false); err != nil {
			return E.Cause(err, "invalid search domain name")
		}
	}
	return nil
}

// parseDNSAssign decodes a DNS_ASSIGN capsule payload.
//
// The payload is a REPEATED DNS Configuration with no top-level count: the draft's
// capsule figure shows "DNS Configuration (..) ..." and the reference loops until the
// payload is exhausted. Each configuration does carry its own counts.
func parseDNSAssign(payload []byte) ([]DNSConfiguration, error) {
	if len(payload) > maxDNSAssignCapsuleSize {
		return nil, E.New("DNS_ASSIGN capsule too large: ", len(payload),
			" bytes (maximum ", maxDNSAssignCapsuleSize, ")")
	}
	var configurations []DNSConfiguration
	for len(payload) > 0 {
		if len(configurations) >= maxDNSConfigurations {
			return nil, E.New("too many DNS configurations in one capsule (maximum ",
				maxDNSConfigurations, ")")
		}
		nameservers, rest, err := parseDNSNameservers(payload)
		if err != nil {
			return nil, err
		}
		payload = rest
		internalDomains, rest, err := parseDomains(payload, maxDNSDomainsPerConfig)
		if err != nil {
			return nil, err
		}
		payload = rest
		searchDomains, rest, err := parseDomains(payload, maxDNSDomainsPerConfig)
		if err != nil {
			return nil, err
		}
		payload = rest
		configuration := DNSConfiguration{
			Nameservers:     nameservers,
			InternalDomains: internalDomains,
			SearchDomains:   searchDomains,
		}
		if err := configuration.validate(); err != nil {
			return nil, E.Cause(err, "invalid DNS configuration")
		}
		configurations = append(configurations, configuration)
	}
	return configurations, nil
}

func parseDNSNameservers(payload []byte) ([]DNSNameserver, []byte, error) {
	count, length, valid := decodeVarintChecked(payload)
	if !valid {
		return nil, nil, E.New("truncated nameserver count")
	}
	payload = payload[length:]
	if count > maxDNSNameserversPerConfig {
		return nil, nil, E.New("too many nameservers in one configuration (maximum ",
			maxDNSNameserversPerConfig, ")")
	}
	nameservers := make([]DNSNameserver, 0, count)
	for range count {
		nameserver, rest, err := parseDNSNameserver(payload)
		if err != nil {
			return nil, nil, err
		}
		nameservers = append(nameservers, nameserver)
		payload = rest
	}
	return nameservers, payload, nil
}

func parseDNSNameserver(payload []byte) (DNSNameserver, []byte, error) {
	var nameserver DNSNameserver
	if len(payload) < 2 {
		return nameserver, nil, E.New("truncated nameserver service priority")
	}
	nameserver.ServicePriority = uint16(payload[0])<<8 | uint16(payload[1])
	payload = payload[2:]

	ipv4Count, length, valid := decodeVarintChecked(payload)
	if !valid {
		return nameserver, nil, E.New("truncated IPv4 address count")
	}
	payload = payload[length:]
	// Each address is 4 bytes; checking the count against the remaining payload
	// before allocating stops a declared huge count from reserving memory it cannot
	// possibly fill.
	if ipv4Count*4 > uint64(len(payload)) {
		return nameserver, nil, E.New("IPv4 address count exceeds remaining payload")
	}
	nameserver.IPv4Addresses = make([]netip.Addr, 0, ipv4Count)
	for range ipv4Count {
		address, _ := netip.AddrFromSlice(payload[:4])
		nameserver.IPv4Addresses = append(nameserver.IPv4Addresses, address)
		payload = payload[4:]
	}

	ipv6Count, length, valid := decodeVarintChecked(payload)
	if !valid {
		return nameserver, nil, E.New("truncated IPv6 address count")
	}
	payload = payload[length:]
	if ipv6Count*16 > uint64(len(payload)) {
		return nameserver, nil, E.New("IPv6 address count exceeds remaining payload")
	}
	nameserver.IPv6Addresses = make([]netip.Addr, 0, ipv6Count)
	for range ipv6Count {
		address, _ := netip.AddrFromSlice(payload[:16])
		nameserver.IPv6Addresses = append(nameserver.IPv6Addresses, address)
		payload = payload[16:]
	}

	authenticationDomain, payload, err := parseDomain(payload)
	if err != nil {
		return nameserver, nil, err
	}
	nameserver.AuthenticationDomainName = authenticationDomain

	serviceParametersLength, length, valid := decodeVarintChecked(payload)
	if !valid {
		return nameserver, nil, E.New("truncated service parameters length")
	}
	payload = payload[length:]
	if serviceParametersLength > maxServiceParametersLen {
		return nameserver, nil, E.New("service parameters too long: ", serviceParametersLength)
	}
	if serviceParametersLength > uint64(len(payload)) {
		return nameserver, nil, E.New("service parameters length exceeds remaining payload")
	}
	parametersPayload := payload[:serviceParametersLength]
	payload = payload[serviceParametersLength:]
	if len(parametersPayload) > 0 {
		parameters, err := parseServiceParameters(parametersPayload)
		if err != nil {
			return nameserver, nil, err
		}
		nameserver.ServiceParameters = parameters
	}
	return nameserver, payload, nil
}

// parseServiceParameters decodes the SVCB wire format (RFC 9460 §2.2).
//
// Keys must be in strictly increasing order. That is not a stylistic preference: the
// format's whole point is that a parser can stream it, and allowing duplicates or
// reordering means later parameters could silently override earlier ones.
func parseServiceParameters(payload []byte) (map[dnsmessage.SVCParamKey][]byte, error) {
	parameters := make(map[dnsmessage.SVCParamKey][]byte)
	var previousKey dnsmessage.SVCParamKey
	for len(payload) > 0 {
		if len(parameters) >= maxSVCParamsPerNameserver {
			return nil, E.New("too many service parameters (maximum ", maxSVCParamsPerNameserver, ")")
		}
		if len(payload) < 4 {
			return nil, E.New("truncated service parameter header")
		}
		key := dnsmessage.SVCParamKey(uint16(payload[0])<<8 | uint16(payload[1]))
		valueLength := int(uint16(payload[2])<<8 | uint16(payload[3]))
		payload = payload[4:]
		if valueLength > len(payload) {
			return nil, E.New("truncated service parameter value")
		}
		if len(parameters) > 0 && key <= previousKey {
			return nil, E.New("service parameter keys must be in strictly increasing order")
		}
		// The three-index slice caps capacity so a later append cannot write into the
		// following parameter's bytes.
		parameters[key] = payload[:valueLength:valueLength]
		previousKey = key
		payload = payload[valueLength:]
	}
	return parameters, nil
}

func parseDomains(payload []byte, limit int) ([]string, []byte, error) {
	count, length, valid := decodeVarintChecked(payload)
	if !valid {
		return nil, nil, E.New("truncated domain count")
	}
	payload = payload[length:]
	if count > uint64(limit) {
		return nil, nil, E.New("too many domains in one configuration (maximum ", limit, ")")
	}
	domains := make([]string, 0, count)
	for range count {
		domain, rest, err := parseDomain(payload)
		if err != nil {
			return nil, nil, err
		}
		domains = append(domains, domain)
		payload = rest
	}
	return domains, payload, nil
}

func parseDomain(payload []byte) (string, []byte, error) {
	length, lengthSize, valid := decodeVarintChecked(payload)
	if !valid {
		return "", nil, E.New("truncated domain length")
	}
	payload = payload[lengthSize:]
	if length > maxDomainNameLen {
		return "", nil, E.New("domain name too long: ", length, " bytes")
	}
	if length == 0 {
		return "", payload, nil
	}
	if length > uint64(len(payload)) {
		return "", nil, E.New("domain length exceeds remaining payload")
	}
	return string(payload[:length]), payload[length:], nil
}

// parsePREF64 decodes a PREF64 capsule payload.
//
// Wire layout (draft §4.1): each prefix is EXACTLY 13 bytes, a one-byte prefix length
// followed by 12 bytes of address. The 12 bytes are always present regardless of the
// prefix length, because the field is defined as the highest 96 bits of the IPv6
// prefix.
func parsePREF64(payload []byte) ([]netip.Prefix, error) {
	if len(payload)%13 != 0 {
		return nil, E.New("PREF64 capsule length is not a multiple of 13: ", len(payload))
	}
	count := len(payload) / 13
	if count > maxPREF64Prefixes {
		return nil, E.New("too many NAT64 prefixes (maximum ", maxPREF64Prefixes, ")")
	}
	prefixes := make([]netip.Prefix, 0, count)
	for len(payload) > 0 {
		prefixLength := int(payload[0])
		switch prefixLength {
		case 32, 40, 48, 56, 64, 96:
			// The values RFC 6052 §2.2 permits for IPv6/IPv4 translation.
		default:
			return nil, E.New("invalid NAT64 prefix length: ", prefixLength)
		}
		var addressBytes [16]byte
		copy(addressBytes[:12], payload[1:13])
		address := netip.AddrFrom16(addressBytes)
		if address.Is4In6() {
			return nil, E.New("IPv4-mapped IPv6 address is not a valid NAT64 prefix: ", address)
		}
		// Masked, deliberately.
		//
		// The reference does NOT mask, and its own test asserts that
		// `2001:db8:0:0:1::/32` survives parsing with host bits set, which the draft
		// supports by defining the field as a fixed 96-bit prefix that the consumer
		// truncates. Masking here is safe AND stricter: the address also has its
		// trailing four bytes zeroed by construction above, and RFC 6052 synthesis
		// only ever reads the bits within the prefix length. Masking makes the stored
		// value compare equal across differently-padded encodings of the same prefix,
		// which is what latest-state replacement and cache keys need.
		prefixes = append(prefixes, netip.PrefixFrom(address, prefixLength).Masked())
		payload = payload[13:]
	}
	return prefixes, nil
}

// SelectNameservers returns the nameservers this assignment wants used, in the order
// the draft's service priorities express.
//
// The draft allows several DNS configurations when different servers own separate
// internal domains. For a client with a single resolver chain there is one usable
// view: the nameservers of the lowest-numbered configuration that carries any, with
// each nameserver's priority ordering them. The full configuration list is retained
// on the assignment so this policy can be revisited without re-parsing.
func (a *DNSAssignment) SelectNameservers() []DNSNameserver {
	if a == nil {
		return nil
	}
	var selected []DNSNameserver
	bestPriority := uint16(0)
	for _, configuration := range a.Configurations {
		for _, nameserver := range configuration.Nameservers {
			if nameserver.AuthenticationDomainName == "" &&
				len(nameserver.IPv4Addresses)+len(nameserver.IPv6Addresses) == 0 {
				// Nothing reachable and nothing to authenticate: unusable.
				continue
			}
			if len(selected) == 0 || nameserver.ServicePriority < bestPriority {
				bestPriority = nameserver.ServicePriority
				selected = []DNSNameserver{nameserver}
			} else if nameserver.ServicePriority == bestPriority {
				selected = append(selected, nameserver)
			}
		}
	}
	return selected
}

// Empty reports whether this assignment carries nothing usable, which is how a
// cleared or useless assignment is distinguished from a valid one.
func (a *DNSAssignment) Empty() bool {
	return a == nil || len(a.SelectNameservers()) == 0
}

// encodeDNSAssign builds a DNS_ASSIGN capsule payload from configurations.
//
// It validates before emitting, for the reason the reference does: a configuration
// this implementation would reject on receipt must not be one it sends.
func encodeDNSAssign(configurations []DNSConfiguration) (*buf.Buffer, error) {
	payload := make([]byte, 0, 256)
	for _, configuration := range configurations {
		if err := configuration.validate(); err != nil {
			return nil, E.Cause(err, "refusing to send an invalid DNS configuration")
		}
		payload = appendDNSVarint(payload, uint64(len(configuration.Nameservers)))
		for _, nameserver := range configuration.Nameservers {
			payload = append(payload, byte(nameserver.ServicePriority>>8),
				byte(nameserver.ServicePriority))
			payload = appendDNSVarint(payload, uint64(len(nameserver.IPv4Addresses)))
			for _, address := range nameserver.IPv4Addresses {
				addressBytes := address.As4()
				payload = append(payload, addressBytes[:]...)
			}
			payload = appendDNSVarint(payload, uint64(len(nameserver.IPv6Addresses)))
			for _, address := range nameserver.IPv6Addresses {
				addressBytes := address.As16()
				payload = append(payload, addressBytes[:]...)
			}
			payload = appendDomain(payload, nameserver.AuthenticationDomainName)
			// Sorted keys, required by the format's strictly-increasing rule.
			keys := sortedSVCParamKeys(nameserver.ServiceParameters)
			var serviceParametersLen int
			for _, key := range keys {
				serviceParametersLen += 4 + len(nameserver.ServiceParameters[key])
			}
			payload = appendDNSVarint(payload, uint64(serviceParametersLen))
			for _, key := range keys {
				value := nameserver.ServiceParameters[key]
				payload = append(payload, byte(key>>8), byte(key),
					byte(len(value)>>8), byte(len(value)))
				payload = append(payload, value...)
			}
		}
		payload = appendDNSVarint(payload, uint64(len(configuration.InternalDomains)))
		for _, domain := range configuration.InternalDomains {
			payload = appendDomain(payload, domain)
		}
		payload = appendDNSVarint(payload, uint64(len(configuration.SearchDomains)))
		for _, domain := range configuration.SearchDomains {
			payload = appendDomain(payload, domain)
		}
	}
	return newCapsule(capsuleTypeDNSAssign, payload), nil
}

// encodePREF64 builds a PREF64 capsule payload. An empty prefix list is legal and
// means "no NAT64 prefixes available", which invalidates previous state.
func encodePREF64(prefixes []netip.Prefix) (*buf.Buffer, error) {
	if len(prefixes) > maxPREF64Prefixes {
		return nil, E.New("too many NAT64 prefixes (maximum ", maxPREF64Prefixes, ")")
	}
	payload := make([]byte, 0, len(prefixes)*13)
	for _, prefix := range prefixes {
		switch prefix.Bits() {
		case 32, 40, 48, 56, 64, 96:
		default:
			return nil, E.New("invalid NAT64 prefix length: ", prefix.Bits())
		}
		if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return nil, E.New("NAT64 prefix must be an IPv6 prefix: ", prefix)
		}
		addressBytes := prefix.Masked().Addr().As16()
		payload = append(payload, byte(prefix.Bits()))
		payload = append(payload, addressBytes[:12]...)
	}
	return newCapsule(capsuleTypePREF64, payload), nil
}

func appendDomain(payload []byte, domain string) []byte {
	payload = appendDNSVarint(payload, uint64(len(domain)))
	return append(payload, domain...)
}

// appendDNSVarint appends a QUIC variable-length integer, reusing the same encoder the
// rest of this package and transport/http already share, so the two cannot drift.
func appendDNSVarint(payload []byte, value uint64) []byte {
	var scratch [8]byte
	length := transportHTTP.PutVarint(scratch[:], value)
	return append(payload, scratch[:length]...)
}

// decodeVarintChecked wraps the shared decoder, which reports validity as a bool
// rather than an error.
func decodeVarintChecked(payload []byte) (uint64, int, bool) {
	return transportHTTP.DecodeVarint(payload)
}

// sortedSVCParamKeys returns the parameter keys in ascending order, which the SVCB
// wire format requires on the wire.
func sortedSVCParamKeys(parameters map[dnsmessage.SVCParamKey][]byte) []dnsmessage.SVCParamKey {
	keys := make([]dnsmessage.SVCParamKey, 0, len(parameters))
	for key := range parameters {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
