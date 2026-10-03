package rule

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// The dns_server_address and dns_search_domain rule items must match the DNS transport by the
// property they name, and only that property.
//
// # What the items decide
//
// dns_server_address matches when the transport's server addresses fall inside a configured prefix;
// dns_search_domain matches when one of the transport's search domains equals a configured domain,
// compared canonically so that a trailing dot or mixed case does not change the answer. Both are
// transport SELECTORS: a rule using one of them decides which resolver serves a query.
//
// # Why the negative direction matters as much
//
// A selector that matches too broadly routes queries to a resolver the operator did not choose,
// which is a correctness and a privacy problem rather than a cosmetic one. A selector that matches
// too narrowly silently stops matching after a configuration change. Both are asserted.

// dnsRuleItemTransport is a transport exposing exactly the two properties the items read.
type dnsRuleItemTransport struct {
	adapter.DNSTransport
	tag           string
	serverAddrs   []netip.Addr
	searchDomains []string
}

func (t *dnsRuleItemTransport) Tag() string                   { return t.tag }
func (t *dnsRuleItemTransport) Type() string                  { return "test-dns-rule-item" }
func (t *dnsRuleItemTransport) ServerAddresses() []netip.Addr { return t.serverAddrs }
func (t *dnsRuleItemTransport) SearchDomains() []string       { return t.searchDomains }

// dnsRuleItemManager resolves tags to the test transports.
type dnsRuleItemManager struct {
	adapter.DNSTransportManager
	transports map[string]adapter.DNSTransport
}

func (m *dnsRuleItemManager) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, loaded := m.transports[tag]
	return transport, loaded
}

func (m *dnsRuleItemManager) Transports() []adapter.DNSTransport {
	list := make([]adapter.DNSTransport, 0, len(m.transports))
	for _, transport := range m.transports {
		list = append(list, transport)
	}
	return list
}

// newDNSRuleItemContext builds a context carrying the manager the items resolve through.
func newDNSRuleItemContext(transports map[string]adapter.DNSTransport) context.Context {
	manager := &dnsRuleItemManager{transports: transports}
	return service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
}

// serverAddressMap builds the TypedMap the constructor takes.
//
// It is built by unmarshalling, which is how a configuration file reaches it: the type's own
// initialiser is unexported, and going through JSON also means the test covers the parse path the
// option actually uses.
func serverAddressMap(t *testing.T, tag string, cidrs ...string) *badjson.TypedMap[string, badoption.Listable[*badoption.Prefixable]] {
	t.Helper()
	quoted := make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		quoted = append(quoted, strconv.Quote(cidr))
	}
	document := `{"` + tag + `":[` + strings.Join(quoted, ",") + `]}`
	typedMap := new(badjson.TypedMap[string, badoption.Listable[*badoption.Prefixable]])
	require.NoError(t, typedMap.UnmarshalJSON([]byte(document)))
	return typedMap
}

// TestDNSServerAddressItemMatchesByPrefix is the positive case.
func TestDNSServerAddressItemMatchesByPrefix(t *testing.T) {
	transport := &dnsRuleItemTransport{
		tag:         "remote",
		serverAddrs: []netip.Addr{netip.MustParseAddr("192.0.2.53")},
	}
	ctx := newDNSRuleItemContext(map[string]adapter.DNSTransport{"remote": transport})

	item := NewDNSServerAddressItem(ctx, serverAddressMap(t, "remote", "192.0.2.0/24"))
	require.NoError(t, item.Start())

	require.True(t, item.Match(&adapter.InboundContext{}),
		"the transport's address lies inside the configured prefix")
}

// TestDNSServerAddressItemRejectsAnAddressOutsideThePrefix is the security half.
func TestDNSServerAddressItemRejectsAnAddressOutsideThePrefix(t *testing.T) {
	transport := &dnsRuleItemTransport{
		tag:         "remote",
		serverAddrs: []netip.Addr{netip.MustParseAddr("198.51.100.53")},
	}
	ctx := newDNSRuleItemContext(map[string]adapter.DNSTransport{"remote": transport})

	item := NewDNSServerAddressItem(ctx, serverAddressMap(t, "remote", "192.0.2.0/24"))
	require.NoError(t, item.Start())

	require.False(t, item.Match(&adapter.InboundContext{}),
		"an address outside the configured prefix must not match; matching here would route a "+
			"query to a resolver the operator did not select")
}

// TestDNSServerAddressItemHandlesAnEmptyResolution covers a transport that reports no addresses.
//
// With nothing to compare, the item must not match: "no address information" is not evidence that
// the transport is the configured one.
func TestDNSServerAddressItemHandlesAnEmptyResolution(t *testing.T) {
	transport := &dnsRuleItemTransport{tag: "remote"}
	ctx := newDNSRuleItemContext(map[string]adapter.DNSTransport{"remote": transport})

	item := NewDNSServerAddressItem(ctx, serverAddressMap(t, "remote", "192.0.2.0/24"))
	require.NoError(t, item.Start())

	require.False(t, item.Match(&adapter.InboundContext{}),
		"a transport reporting no addresses cannot be shown to be the configured one")
}

// TestDNSServerAddressItemRequiresTheTransportToExist covers the failure mode that must be loud: a
// rule naming a tag that does not exist is a configuration error, not a silent non-match.
func TestDNSServerAddressItemRequiresTheTransportToExist(t *testing.T) {
	ctx := newDNSRuleItemContext(map[string]adapter.DNSTransport{})
	item := NewDNSServerAddressItem(ctx, serverAddressMap(t, "missing", "192.0.2.0/24"))
	require.Error(t, item.Start(),
		"a rule referencing an unknown DNS server must fail to start rather than never match")
}

// searchDomainMap builds the TypedMap the search-domain constructor takes, also by unmarshalling.
func searchDomainMap(t *testing.T, tag string, domains ...string) *badjson.TypedMap[string, badoption.Listable[string]] {
	t.Helper()
	quoted := make([]string, 0, len(domains))
	for _, domain := range domains {
		quoted = append(quoted, strconv.Quote(domain))
	}
	document := `{"` + tag + `":[` + strings.Join(quoted, ",") + `]}`
	typedMap := new(badjson.TypedMap[string, badoption.Listable[string]])
	require.NoError(t, typedMap.UnmarshalJSON([]byte(document)))
	return typedMap
}

// TestDNSSearchDomainItemMatchesCanonically is the positive case, including the trailing-dot and
// case forms that must compare equal.
func TestDNSSearchDomainItemMatchesCanonically(t *testing.T) {
	for _, reported := range []string{"corp.example", "corp.example.", "CORP.EXAMPLE"} {
		transport := &dnsRuleItemTransport{tag: "corp", searchDomains: []string{reported}}
		ctx := newDNSRuleItemContext(map[string]adapter.DNSTransport{"corp": transport})

		item := NewDNSSearchDomainItem(ctx, searchDomainMap(t, "corp", "corp.example"))
		require.NoError(t, item.Start())

		require.True(t, item.Match(&adapter.InboundContext{}),
			"search domain %q must match corp.example: DNS names are canonical, so a trailing dot "+
				"or differing case is the same domain", reported)
	}
}

// TestDNSSearchDomainItemRejectsADifferentDomain is the security half.
func TestDNSSearchDomainItemRejectsADifferentDomain(t *testing.T) {
	transport := &dnsRuleItemTransport{tag: "corp", searchDomains: []string{"other.example"}}
	ctx := newDNSRuleItemContext(map[string]adapter.DNSTransport{"corp": transport})

	item := NewDNSSearchDomainItem(ctx, searchDomainMap(t, "corp", "corp.example"))
	require.NoError(t, item.Start())

	require.False(t, item.Match(&adapter.InboundContext{}),
		"a different search domain must not match")
}

// TestDNSSearchDomainItemRejectsASuffixThatIsNotEqual guards the boundary between "same domain" and
// "domain that merely ends with it", which is the classic matching mistake.
func TestDNSSearchDomainItemRejectsASuffixThatIsNotEqual(t *testing.T) {
	transport := &dnsRuleItemTransport{tag: "corp", searchDomains: []string{"evilcorp.example"}}
	ctx := newDNSRuleItemContext(map[string]adapter.DNSTransport{"corp": transport})

	item := NewDNSSearchDomainItem(ctx, searchDomainMap(t, "corp", "corp.example"))
	require.NoError(t, item.Start())

	require.False(t, item.Match(&adapter.InboundContext{}),
		"evilcorp.example must not match corp.example; the item compares whole canonical names, and "+
			"a suffix test would hand an attacker-controlled domain the corporate resolver")
}

// TestDNSSearchDomainItemHandlesAnEmptyResolution covers a transport reporting no search domains.
func TestDNSSearchDomainItemHandlesAnEmptyResolution(t *testing.T) {
	transport := &dnsRuleItemTransport{tag: "corp"}
	ctx := newDNSRuleItemContext(map[string]adapter.DNSTransport{"corp": transport})

	item := NewDNSSearchDomainItem(ctx, searchDomainMap(t, "corp", "corp.example"))
	require.NoError(t, item.Start())

	require.False(t, item.Match(&adapter.InboundContext{}),
		"a transport reporting no search domains cannot be shown to be the configured one")
}
