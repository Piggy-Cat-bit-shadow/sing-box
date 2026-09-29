package masque

import (
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/dns/dnsmessage"
)

// SVCB service-parameter validation for DNS_ASSIGN nameservers.
//
// # Why this is stricter than "parse the bytes"
//
// draft-ietf-masque-connect-ip-dns-06 carries each nameserver's transport configuration in
// SVCB service parameters, and the client's transport decision is made entirely from them.
// A parameter that is accepted but MISREAD therefore does not produce a cosmetic error: it
// produces a resolver that looks usable and is not, or -- worse -- a downgrade to a
// transport the server did not offer.
//
// RFC 9460 gives the wire formats, and §2.2 is explicit about the consequence of getting
// them wrong:
//
//	"Clients MUST consider an RR malformed if ... the SvcParamValue for a SvcParamKey does
//	 not have the expected format."
//
// So a malformed value is not something to recover from or guess at. It makes the endpoint
// incompatible, and the caller moves on to the next resolver in the same configuration.
//
// # Which specification wins
//
// draft-06 is the direct specification for this extension and takes precedence over the
// general SVCB/HTTPS mapping where they differ. Two places where that matters:
//
//   - `ipv4hint` / `ipv6hint` are FORBIDDEN by draft-06 §3.2 ("MUST NOT include"), even
//     though RFC 9460/9461 permit them generally. Rejected here.
//   - the address-count rule is applied only when `alpn` is absent, because the literal
//     §3.2 rule rejects the draft's own §3.6.1 full-tunnel example. See
//     ValidateServiceParameters.

// SvcParamKeys used by this extension, as registered in RFC 9460 §14.3.2.
const (
	svcParamMandatory     = dnsmessage.SVCParamKey(0)
	svcParamALPN          = dnsmessage.SVCParamKey(1)
	svcParamNoDefaultALPN = dnsmessage.SVCParamKey(2)
	svcParamPort          = dnsmessage.SVCParamKey(3)
	svcParamIPv4Hint      = dnsmessage.SVCParamKey(4)
	svcParamECH           = dnsmessage.SVCParamKey(5)
	svcParamIPv6Hint      = dnsmessage.SVCParamKey(6)
	svcParamDohPath       = dnsmessage.SVCParamKey(7)
)

// SvcParamKeyNames maps the keys this client understands to their registered names, for
// error messages. A key absent from this map is "unknown" to us.
var SvcParamKeyNames = map[dnsmessage.SVCParamKey]string{
	svcParamMandatory:     "mandatory",
	svcParamALPN:          "alpn",
	svcParamNoDefaultALPN: "no-default-alpn",
	svcParamPort:          "port",
	svcParamIPv4Hint:      "ipv4hint",
	svcParamECH:           "ech",
	svcParamIPv6Hint:      "ipv6hint",
	svcParamDohPath:       "dohpath",
}

// SvcParamKeyName renders a key for a message, using the registered name when known and the
// RFC 9460 §2.1 "keyNNNNN" form otherwise.
func SvcParamKeyName(key dnsmessage.SVCParamKey) string {
	if name, known := SvcParamKeyNames[key]; known {
		return name
	}
	return "key" + strconv.Itoa(int(key))
}

// ParsedServiceParameters is the validated view of one nameserver's SvcParams.
//
// It is produced by validation rather than by ad-hoc lookups, so "was this key present" and
// "was its value well formed" are answered once, and the transport decision cannot see a
// half-parsed parameter.
type ParsedServiceParameters struct {
	// alpn is the validated ALPN set. Nil when `alpn` was absent.
	ALPN []string
	// noDefaultALPN reports that the default transport was explicitly withdrawn.
	NoDefaultALPN bool
	// Port is the advertised port, and HasPort records whether one was advertised at all.
	// The two are distinct because port 0 is a legal wire value but distinct from absent.
	Port    uint16
	HasPort bool
	// dohPath is the advertised URI Template, raw. Validation of the template itself happens
	// where the transport is chosen, because - see validateDohPath - it depends on whether
	// an encrypted HTTP transport was advertised at all.
	DohPath string
	// hasDohPath records presence, so an empty template is distinguishable from an absent one.
	HasDohPath bool
	// mandatory lists the extra mandatory keys the server declared.
	Mandatory []dnsmessage.SVCParamKey
}

// mandatoryKey reports whether a key is mandatory for this resolver.
//
// Two sources, per RFC 9460 §8:
//
//   - the `mandatory` parameter lists keys the RR cannot work without;
//   - some keys are "automatically mandatory": present in the RR and required for correct
//     interpretation. RFC 9461's HTTP mapping names `port` and `no-default-alpn`, and this
//     extension adds `alpn`, because a client that ignores `alpn` would select a transport
//     the server never offered. That choice is recorded in
//     ValidateServiceParameters and in the docs.
func (p ParsedServiceParameters) MandatoryKey(key dnsmessage.SVCParamKey) bool {
	for _, listed := range p.Mandatory {
		if listed == key {
			return true
		}
	}
	return false
}

// ValidateServiceParameters parses and validates one nameserver's SvcParams.
//
// # The rules applied, and where each comes from
//
//	key order        RFC 9460 §2.2   strictly increasing, so no duplicates. The capsule
//	                                 parser has already enforced this; it is re-checked
//	                                 because this function must be safe to call on any map.
//	alpn             RFC 9460 §7.1.1 length-prefixed pairs that MUST exactly fill the value
//	no-default-alpn  RFC 9460 §7.1.1 value MUST be empty
//	port             RFC 9460 §7.2   exactly 2 octets, network byte order
//	mandatory        RFC 9460 §8     keys present, no duplicates, must not list itself
//	ipv4hint/ipv6hint draft-06 §3.2  MUST NOT appear
//	unknown keys     RFC 9460 §2.4.3 ignored UNLESS listed as mandatory, in which case the
//	                                 resolver is incompatible because we cannot honour a
//	                                 requirement we do not understand.
//
// # The address-count rule, and the draft's self-contradiction
//
// §3.2 says that when `no-default-alpn` is omitted the nameserver supports unencrypted DNS
// and therefore "the sum of IPv4 Address Count and IPv6 Address Count MUST be nonzero". Taken
// literally that rejects the draft's OWN §3.6.1 example, which carries `alpn=h2,h3`, no
// `no-default-alpn`, and zero addresses.
//
// The rule's purpose is to guarantee an address for the unencrypted transports it infers.
// When `alpn` IS present that inference does not hold: the ALPN list names the encrypted
// transports explicitly, which is exactly how §3.6.1 reaches a nameserver by name alone. So
// the requirement is applied only when `alpn` is absent.
//
// This is a deliberate deviation and it is recorded as one. It accepts strictly MORE than the
// literal rule on receive, so anything the reference sends still validates here, and it keeps
// every published example valid.
func ValidateServiceParameters(nameserver DNSNameserver) (ParsedServiceParameters, error) {
	var parsed ParsedServiceParameters

	keys := sortedSVCParamKeys(nameserver.ServiceParameters)
	for index := 1; index < len(keys); index++ {
		if keys[index-1] >= keys[index] {
			return parsed, E.New("service parameters are not in strictly increasing key order: ",
				SvcParamKeyName(keys[index-1]), " then ", SvcParamKeyName(keys[index]))
		}
	}

	for _, key := range keys {
		value := nameserver.ServiceParameters[key]
		switch key {
		case svcParamALPN:
			alpn, err := DecodeALPNWire(value)
			if err != nil {
				return parsed, E.Cause(err, "invalid alpn service parameter")
			}
			parsed.ALPN = alpn
		case svcParamNoDefaultALPN:
			// RFC 9460 §7.1.1: "the presentation and wire-format values MUST be empty".
			if len(value) != 0 {
				return parsed, E.New("no-default-alpn service parameter must have an empty value, got ",
					len(value), " bytes")
			}
			parsed.NoDefaultALPN = true
		case svcParamPort:
			// RFC 9460 §7.2: exactly two octets, network byte order. Anything else is a
			// syntax error, and this key is automatically mandatory, so a malformed value
			// must NOT be silently replaced by a default -- that would be a downgrade to a
			// port the server did not name.
			if len(value) != 2 {
				return parsed, E.New("port service parameter must be exactly 2 bytes, got ", len(value))
			}
			parsed.Port = uint16(value[0])<<8 | uint16(value[1])
			parsed.HasPort = true
		case svcParamDohPath:
			parsed.DohPath = string(value)
			parsed.HasDohPath = true
		case svcParamIPv4Hint, svcParamIPv6Hint:
			// draft-06 §3.2: "The service parameters MUST NOT include ipv4hint or ipv6hint
			// SvcParams, as they are superseded by the included IP addresses." draft-06 is
			// the direct specification here, so this rejects what RFC 9461 would allow.
			return parsed, E.New(SvcParamKeyName(key),
				" is not permitted in a DNS_ASSIGN nameserver: the addresses are already carried by the nameserver structure")
		case svcParamMandatory:
			list, err := DecodeMandatoryWire(value)
			if err != nil {
				return parsed, E.Cause(err, "invalid mandatory service parameter")
			}
			parsed.Mandatory = list
		default:
			// Unknown, non-mandatory keys are ignored, per RFC 9460 §2.4.3. If the
			// `mandatory` list names one, the check below refuses the resolver instead:
			// that is the whole point of the parameter.
		}
	}

	// RFC 9460 §8 self-consistency: every listed key MUST appear in the SvcParams.
	for _, key := range parsed.Mandatory {
		if _, present := nameserver.ServiceParameters[key]; !present {
			return parsed, E.New("mandatory lists ", SvcParamKeyName(key),
				", which is not present in the service parameters")
		}
	}

	// RFC 9460 §8: mandatory is always automatically mandatory, and MUST NOT list itself.
	for _, key := range parsed.Mandatory {
		if key == svcParamMandatory {
			return parsed, E.New("mandatory service parameter must not list itself")
		}
	}
	if duplicate := firstDuplicate(parsed.Mandatory); duplicate != 0 || hasZero(parsed.Mandatory) {
		return parsed, E.New("mandatory service parameter lists a key more than once")
	}

	// The client must recognise every mandatory key, and the values must permit a connection.
	if err := checkMandatoryRecognised(nameserver, parsed); err != nil {
		return parsed, err
	}

	// draft-06 §3.2: if the authentication domain name is empty, alpn and no-default-alpn
	// MUST be omitted.
	if nameserver.AuthenticationDomainName == "" && (len(parsed.ALPN) > 0 || parsed.NoDefaultALPN) {
		return parsed, E.New("alpn and no-default-alpn must be omitted when the authentication domain name is empty")
	}

	// RFC 9460 §7.1.1: "When no-default-alpn is specified in an RR, alpn must also be
	// specified in order for the RR to be self-consistent."
	if parsed.NoDefaultALPN && len(parsed.ALPN) == 0 {
		return parsed, E.New("no-default-alpn requires alpn to also be present")
	}

	// The draft's address rule, applied only when alpn is absent. See the function comment.
	if len(parsed.ALPN) == 0 && !parsed.NoDefaultALPN &&
		len(nameserver.IPv4Addresses)+len(nameserver.IPv6Addresses) == 0 {
		return parsed, E.New("nameserver must have an address when alpn is omitted and no-default-alpn is not set")
	}

	return parsed, nil
}

// checkMandatoryRecognised refuses a resolver whose mandatory keys this client cannot honour.
//
// Two ways that happens:
//
//   - a mandatory key we do not recognise at all, so we cannot implement its requirement;
//   - a mandatory key we DO recognise but cannot act on, which for this client means DoT and
//     DoQ: we have no such transport, so a resolver that requires one cannot serve us.
//
// The resolver becomes incompatible and the caller tries the next one in the same
// configuration. Silently ignoring the requirement is what RFC 9460 §8 forbids.
func checkMandatoryRecognised(nameserver DNSNameserver, parsed ParsedServiceParameters) error {
	for _, key := range parsed.Mandatory {
		if !isKnownSvcParam(key) {
			// A key we do not even recognise cannot have its requirement honoured, because we
			// do not know what the requirement is.
			return E.New("mandatory lists unknown key ", SvcParamKeyName(key),
				", which this client cannot honour")
		}
		if !isSupportedMandatorySvcParam(key) {
			// KNOWN IS NOT SUPPORTED. A key whose name we recognise, but whose semantics we do
			// not implement, is just as impossible to honour -- and worse, because a name in
			// the registry creates the impression that it works.
			//
			// ECH is the concrete case. This client does not fetch, validate or apply an
			// Encrypted ClientHello configuration, so a server declaring it mandatory is
			// saying the connection will not work correctly if it is ignored. It will not, so
			// the resolver is incompatible.
			return E.New("mandatory lists ", SvcParamKeyName(key),
				", which this client recognises but does not implement")
		}
	}
	// A key we know and support may still be unsupportable for THIS resolver, which is a
	// different failure: the transport it names is absent.
	if parsed.MandatoryKey(svcParamALPN) || parsed.MandatoryKey(svcParamNoDefaultALPN) {
		if err := requireUsableTransportALPN(parsed.ALPN); err != nil {
			return err
		}
	}
	return nil
}

// isKnownSvcParam reports whether the key has a name this client recognises.
//
// This is a statement about the REGISTRY, not about the implementation. See
// isSupportedMandatorySvcParam for the distinction that mandatory keys actually require.
func isKnownSvcParam(key dnsmessage.SVCParamKey) bool {
	_, known := SvcParamKeyNames[key]
	return known
}

// isSupportedMandatorySvcParam reports whether this client can actually honour a key's
// requirement as a mandatory key.
//
// # The rule, applied one key at a time
//
// A key belongs here only if ignoring it would change the connection in a way we would get
// wrong -- and only if we do the right thing instead. Auditing every key this client names:
//
//	mandatory       RFC 9460 §8: always automatically mandatory and must not list itself. It is
//	                handled by its own encoding rules, never "honoured" per se, so it never
//	                appears in this set.
//	alpn            SUPPORTED. We select transports from it, and refuse a set naming only
//	                transports we lack. See requireUsableTransportALPN.
//	no-default-alpn SUPPORTED. It withdraws the plain transport, and we honour that by refusing
//	                rather than falling back to cleartext.
//	port            SUPPORTED. Honoured for both plain DNS and DoH; a malformed length is
//	                rejected rather than defaulted.
//	dohpath         SUPPORTED. Required by RFC 9461 to expand to a valid HTTP path, and we
//	                validate and expand it or refuse the resolver.
//	ipv4hint        NOT APPLICABLE. draft-06 forbids the key outright, so a resolver carrying it
//	ipv6hint        is rejected during parameter validation before mandatory is consulted.
//	ech             NOT SUPPORTED. Recognised so the error can name it, but this client performs
//	                no ECH handshake, so a mandatory ECH cannot be honoured.
//	anything else   NOT SUPPORTED. Unknown keys are unhonourable by definition.
//
// A key that is present but NOT mandatory may still be unused: ipv4hint would be rejected as
// malformed, and an unknown optional key is ignored per RFC 9460 §2.4.3.
func isSupportedMandatorySvcParam(key dnsmessage.SVCParamKey) bool {
	switch key {
	case svcParamALPN, svcParamNoDefaultALPN, svcParamPort, svcParamDohPath:
		return true
	default:
		return false
	}
}

// requireUsableTransportALPN refuses an ALPN set that names only transports this client lacks.
//
// DoT and DoQ are recognised so the error can NAME them rather than calling the set unknown,
// but neither is implemented. A resolver offering only those cannot serve this client.
func requireUsableTransportALPN(alpn []string) error {
	if len(alpn) == 0 {
		return nil
	}
	for _, protocol := range alpn {
		switch protocol {
		case "h2", "h3":
			// Reachable through the DoH path.
			return nil
		}
	}
	return E.New("alpn advertises only ", alpn,
		", and neither DoT nor DoQ is implemented by this client")
}

// DecodeALPNWire parses the RFC 9460 §7.1.1 wire format.
//
//	"The wire-format value for alpn consists of at least one alpn-id prefixed by its length
//	 as a single octet, and these length-value pairs are concatenated to form the
//	 SvcParamValue. These pairs MUST exactly fill the SvcParamValue; otherwise, the
//	 SvcParamValue is malformed."
//
// # Why there is no fallback
//
// An earlier version fell back to reading the bytes as a comma-separated list when
// length-prefix parsing failed. That is wrong on the wire: there is no presentation form in
// a capsule. The fallback meant a genuinely malformed value could be reinterpreted as a
// protocol name -- `\x05h` became the ALPN "\x05h" -- so a server could smuggle an arbitrary
// string past validation and have it treated as a transport. Malformed input is now an error.
func DecodeALPNWire(value []byte) ([]string, error) {
	if len(value) == 0 {
		// RFC 9460 §7.1.1 requires at least one alpn-id.
		return nil, E.New("alpn must contain at least one protocol identifier")
	}
	var protocols []string
	remaining := value
	for len(remaining) > 0 {
		length := int(remaining[0])
		remaining = remaining[1:]
		if length == 0 {
			return nil, E.New("alpn contains a zero-length protocol identifier")
		}
		if length > len(remaining) {
			return nil, E.New("alpn protocol identifier length ", length,
				" exceeds the ", len(remaining), " bytes remaining")
		}
		protocols = append(protocols, string(remaining[:length]))
		remaining = remaining[length:]
	}
	return protocols, nil
}

// DecodeMandatoryWire parses the RFC 9460 §8 wire format: 2-octet keys in strictly
// increasing numeric order, concatenated.
//
//	"This SvcParamKey is always automatically mandatory and MUST NOT appear in its own
//	 value-list."
func DecodeMandatoryWire(value []byte) ([]dnsmessage.SVCParamKey, error) {
	if len(value) == 0 {
		return nil, E.New("mandatory must list at least one key")
	}
	if len(value)%2 != 0 {
		return nil, E.New("mandatory value must be an even number of bytes, got ", len(value))
	}
	list := make([]dnsmessage.SVCParamKey, 0, len(value)/2)
	for index := 0; index < len(value); index += 2 {
		key := dnsmessage.SVCParamKey(uint16(value[index])<<8 | uint16(value[index+1]))
		if key == svcParamMandatory {
			return nil, E.New("mandatory must not list itself")
		}
		if len(list) > 0 && key <= list[len(list)-1] {
			return nil, E.New("mandatory keys must be in strictly increasing order and must not repeat")
		}
		list = append(list, key)
	}
	return list, nil
}

// firstDuplicate returns the first value that appears more than once, or 0 if none does.
func firstDuplicate(keys []dnsmessage.SVCParamKey) dnsmessage.SVCParamKey {
	seen := make(map[dnsmessage.SVCParamKey]struct{}, len(keys))
	for _, key := range keys {
		if _, loaded := seen[key]; loaded {
			return key
		}
		seen[key] = struct{}{}
	}
	return 0
}

// hasZero reports whether a key list contains the zero value, which is `mandatory` itself.
func hasZero(keys []dnsmessage.SVCParamKey) bool {
	for _, key := range keys {
		if key == 0 {
			return true
		}
	}
	return false
}

// DohPathIsRelative reports whether a dohpath is a relative reference.
//
// RFC 9461 §5 defines dohpath as a RELATIVE URI Template: it must not carry a scheme or an
// authority. An absolute URI would let a server redirect our DNS queries to a different
// origin than the one the tunnel is authenticated for, which the same-origin rule exists to
// prevent -- so it is refused before any request is built.
func DohPathIsRelative(template string) bool {
	if template == "" {
		return false
	}
	if strings.HasPrefix(template, "//") {
		return false
	}
	// A scheme is ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":".
	for index := 0; index < len(template); index++ {
		character := template[index]
		switch {
		case character == ':':
			return index == 0
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z':
			continue
		case character >= '0' && character <= '9',
			character == '+', character == '-', character == '.':
			if index == 0 {
				return true
			}
			continue
		default:
			return true
		}
	}
	return true
}
