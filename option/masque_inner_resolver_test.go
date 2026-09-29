package option_test

import (
	"context"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// The MASQUE endpoint has TWO resolvers, and the most likely way to break this
// feature is to wire the wrong one to the wrong job. These tests pin the
// distinction at the configuration layer, where it is cheap to see.

func TestMASQUEInnerDomainResolverDecodesSeparately(t *testing.T) {
	t.Parallel()

	var options option.MASQUEClientEndpointOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"server": "masque.example.com",
		"server_port": 443,
		"domain_resolver": "dns-bootstrap",
		"inner_domain_resolver": {
			"server": "dns-inner",
			"strategy": "prefer_ipv6",
			"timeout": "3s"
		}
	}`), &options)
	require.NoError(t, err)

	// The bootstrap resolver must land on the dialer options, untouched.
	require.Equal(t, "dns-bootstrap", options.DomainResolver.Server,
		"domain_resolver must keep resolving the MASQUE SERVER hostname")

	// The inner resolver must land on its own field and carry its own settings.
	require.NotNil(t, options.InnerDomainResolver,
		"inner_domain_resolver must decode to its own field, not into domain_resolver")
	require.Equal(t, "dns-inner", options.InnerDomainResolver.Server)
	require.EqualValues(t, C.DomainStrategyPreferIPv6, options.InnerDomainResolver.Strategy)
	require.Equal(t, 3*time.Second, time.Duration(options.InnerDomainResolver.Timeout))

	// And the two must not have been aliased to each other.
	require.NotEqual(t, options.DomainResolver.Server, options.InnerDomainResolver.Server,
		"the two resolvers are distinct settings and must not share a value")
}

// TestMASQUEInnerDomainResolverIsOptional is the backward-compatibility contract.
//
// Every existing MASQUE configuration in the wild omits this field, so an omitted
// value must be nil -- the signal the endpoint reads as "apply the normal DNS
// rules", i.e. exactly the previous behaviour.
func TestMASQUEInnerDomainResolverIsOptional(t *testing.T) {
	t.Parallel()

	var options option.MASQUEClientEndpointOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"server": "masque.example.com",
		"server_port": 443,
		"domain_resolver": "dns-bootstrap"
	}`), &options)
	require.NoError(t, err)

	require.Nil(t, options.InnerDomainResolver,
		"an omitted inner_domain_resolver must stay nil so the previous behaviour is "+
			"preserved; a non-nil zero value would change every existing configuration")
	require.Equal(t, "dns-bootstrap", options.DomainResolver.Server)
}

// TestMASQUEInnerDomainResolverAcceptsBareServerString proves the field reuses
// DomainResolveOptions' shorthand, where a bare string means "this server, default
// everything else". A bespoke schema would not accept this.
func TestMASQUEInnerDomainResolverAcceptsBareServerString(t *testing.T) {
	t.Parallel()

	var options option.MASQUEClientEndpointOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"server": "masque.example.com",
		"server_port": 443,
		"inner_domain_resolver": "dns-inner"
	}`), &options)
	require.NoError(t, err)
	require.NotNil(t, options.InnerDomainResolver)
	require.Equal(t, "dns-inner", options.InnerDomainResolver.Server)
}
