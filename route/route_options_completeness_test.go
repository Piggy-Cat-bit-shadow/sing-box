package route

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tlsspoof"
	C "github.com/sagernet/sing-box/constant"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Completeness guard for the route-option metadata application.
//
// # The failure this prevents
//
// The route actions carry options that change how a connection is handled - a rewritten destination,
// a UDP timeout, TLS fragmentation, a network strategy. `applyRouteOptionsMetadata` copies them onto
// the connection metadata, and the Direct Fast Path's eligibility decision reads that metadata.
//
// Upstream adds a field to RuleActionRouteOptions. The fork does not know about it. The metadata is
// then missing the option, the fast path judges a connection that has NOT had that option applied,
// and the connection takes a native path with the operator's setting silently discarded. Nothing
// errors, nothing logs, and the only symptom is a policy that does not apply.
//
// # Two mechanisms, because either one alone drifts
//
// The table below is checked against the struct by reflection, so a new field cannot be added without
// being classified here. Each entry is also a BEHAVIOURAL case: the option is set, the metadata is
// applied, and the field it is supposed to reach is asserted. A table alone would pass while the
// handler ignored the field; the behavioural half is what makes the entry mean something.
//
// It is the same shape as the DialerOptions classification guard in common/dialer, for the same
// reason: what a fork must not do is fail open when upstream grows.

// routeOptionCase is one field of RuleActionRouteOptions, how to set it, and the metadata it must
// reach.
type routeOptionCase struct {
	// field is the Go field name, which is what the reflection check compares against.
	field string
	// apply sets the option on a zero value.
	apply func(options *R.RuleActionRouteOptions)
	// assert reports whether the metadata reflects it. It is given the metadata after application.
	assert func(t *testing.T, metadata *adapter.InboundContext)
}

func routeOptionCases() []routeOptionCase {
	return []routeOptionCase{
		{
			field: "OverrideAddress",
			apply: func(options *R.RuleActionRouteOptions) {
				options.OverrideAddress = M.ParseSocksaddr("203.0.113.9")
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.Equal(t, M.ParseSocksaddrHostPort("203.0.113.9", metadata.Destination.Port),
					metadata.Destination)
				require.True(t, metadata.RouteOriginalDestination.IsValid(),
					"the pre-rewrite destination is recorded")
				require.Empty(t, metadata.DestinationAddresses,
					"and a resolved address list belongs to the pre-rewrite destination")
			},
		},
		{
			field: "OverridePort",
			apply: func(options *R.RuleActionRouteOptions) {
				options.OverridePort = 8443
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.EqualValues(t, 8443, metadata.Destination.Port)
				require.True(t, metadata.RouteOriginalDestination.IsValid())
			},
		},
		{
			field: "NetworkStrategy",
			apply: func(options *R.RuleActionRouteOptions) {
				strategy := C.NetworkStrategyDefault
				options.NetworkStrategy = &strategy
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.NotNil(t, metadata.NetworkStrategy)
			},
		},
		{
			field: "NetworkType",
			apply: func(options *R.RuleActionRouteOptions) {
				options.NetworkType = []C.InterfaceType{C.InterfaceTypeWIFI}
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.Equal(t, []C.InterfaceType{C.InterfaceTypeWIFI}, metadata.NetworkType)
			},
		},
		{
			field: "FallbackNetworkType",
			apply: func(options *R.RuleActionRouteOptions) {
				options.FallbackNetworkType = []C.InterfaceType{C.InterfaceTypeCellular}
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.Equal(t, []C.InterfaceType{C.InterfaceTypeCellular},
					metadata.FallbackNetworkType)
			},
		},
		{
			field: "FallbackDelay",
			apply: func(options *R.RuleActionRouteOptions) {
				options.FallbackDelay = 300 * time.Millisecond
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.Equal(t, 300*time.Millisecond, metadata.FallbackDelay)
			},
		},
		{
			field: "UDPDisableDomainUnmapping",
			apply: func(options *R.RuleActionRouteOptions) {
				options.UDPDisableDomainUnmapping = true
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.True(t, metadata.UDPDisableDomainUnmapping)
			},
		},
		{
			field: "UDPConnect",
			apply: func(options *R.RuleActionRouteOptions) {
				options.UDPConnect = true
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.True(t, metadata.UDPConnect)
			},
		},
		{
			field: "UDPTimeout",
			apply: func(options *R.RuleActionRouteOptions) {
				options.UDPTimeout = 90 * time.Second
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.Equal(t, 90*time.Second, metadata.UDPTimeout)
			},
		},
		{
			field: "TLSFragment",
			apply: func(options *R.RuleActionRouteOptions) {
				options.TLSFragment = true
				options.TLSFragmentFallbackDelay = 40 * time.Millisecond
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.True(t, metadata.TLSFragment)
				require.Equal(t, 40*time.Millisecond, metadata.TLSFragmentFallbackDelay,
					"the fallback delay travels with the flag that gives it meaning")
			},
		},
		{
			field: "TLSFragmentFallbackDelay",
			apply: func(options *R.RuleActionRouteOptions) {
				options.TLSFragment = true
				options.TLSFragmentFallbackDelay = 40 * time.Millisecond
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.Equal(t, 40*time.Millisecond, metadata.TLSFragmentFallbackDelay)
			},
		},
		{
			field: "TLSRecordFragment",
			apply: func(options *R.RuleActionRouteOptions) {
				options.TLSRecordFragment = true
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.True(t, metadata.TLSRecordFragment)
			},
		},
		{
			field: "TLSSpoof",
			apply: func(options *R.RuleActionRouteOptions) {
				options.TLSSpoof = "example.com"
				options.TLSSpoofMethod = tlsspoof.MethodWrongSequence
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.Equal(t, "example.com", metadata.TLSSpoof)
				require.Equal(t, tlsspoof.MethodWrongSequence, metadata.TLSSpoofMethod,
					"the method travels with the name it applies to")
			},
		},
		{
			field: "TLSSpoofMethod",
			apply: func(options *R.RuleActionRouteOptions) {
				options.TLSSpoof = "example.com"
				options.TLSSpoofMethod = tlsspoof.MethodWrongSequence
			},
			assert: func(t *testing.T, metadata *adapter.InboundContext) {
				require.Equal(t, tlsspoof.MethodWrongSequence, metadata.TLSSpoofMethod)
			},
		},
	}
}

// TestEveryRouteOptionReachesTheMetadata is the guard. It is the one that should fail first when the
// pinned upstream adds a route option.
func TestEveryRouteOptionReachesTheMetadata(t *testing.T) {
	optionType := reflect.TypeFor[R.RuleActionRouteOptions]()
	covered := make(map[string]bool, optionType.NumField())

	for _, testCase := range routeOptionCases() {
		require.False(t, covered[testCase.field],
			"%s is covered twice, so one of the two cases is not being read", testCase.field)
		covered[testCase.field] = true

		t.Run(testCase.field, func(t *testing.T) {
			var options R.RuleActionRouteOptions
			testCase.apply(&options)

			metadata := adapter.InboundContext{
				Network:     N.NetworkTCP,
				Destination: M.ParseSocksaddr("93.184.216.34:443"),
				DestinationAddresses: []netip.Addr{
					netip.MustParseAddr("93.184.216.34"),
				},
			}
			applyRouteOptionsMetadata(&metadata, &options)
			testCase.assert(t, &metadata)
		})
	}

	// Every field of the struct must be covered, which is the half that fails on an upstream bump.
	uncovered := uncoveredFields(optionType, covered)
	require.Empty(t, uncovered,
		"route/rule.RuleActionRouteOptions fields are not covered by this test: %v\n\n"+
			"An upstream field that the fork does not apply to the metadata is a field the Direct\n"+
			"Fast Path cannot see: a connection carrying it would be judged as if the option were\n"+
			"not set, and would take a native path with the operator's setting silently discarded.\n\n"+
			"Apply it in applyRouteOptionsMetadata and add a case here that sets it and asserts the\n"+
			"metadata field it reaches.", uncovered)
}

// uncoveredFields reports the fields of the struct that the covered set does not name.
func uncoveredFields(structType reflect.Type, covered map[string]bool) []string {
	var uncovered []string
	for index := 0; index < structType.NumField(); index++ {
		fieldName := structType.Field(index).Name
		if !covered[fieldName] {
			uncovered = append(uncovered, fieldName)
		}
	}
	return uncovered
}

// TestTheCompletenessCheckDetectsAnUncoveredField is the mutation that proves the guard above can
// fail.
//
// A completeness check that cannot report an uncovered field would pass on every struct, including
// the one it exists to protect, and its green would mean nothing.
func TestTheCompletenessCheckDetectsAnUncoveredField(t *testing.T) {
	type syntheticOptions struct {
		Covered   int
		Uncovered int
	}

	uncovered := uncoveredFields(reflect.TypeFor[syntheticOptions](), map[string]bool{"Covered": true})
	require.Equal(t, []string{"Uncovered"}, uncovered,
		"the check must name the field it did not find, or the failure message that tells a "+
			"maintainer what to do cannot be produced")

	require.Empty(t, uncoveredFields(reflect.TypeFor[syntheticOptions](),
		map[string]bool{"Covered": true, "Uncovered": true}))

	// The table's own names must all still exist, or a rename leaves an entry testing nothing while
	// the new name goes uncovered.
	optionType := reflect.TypeFor[R.RuleActionRouteOptions]()
	for _, testCase := range routeOptionCases() {
		_, loaded := optionType.FieldByName(testCase.field)
		require.True(t, loaded,
			"%s is named by this test but is no longer a field of route/rule.RuleActionRouteOptions: "+
				"the entry is stale", testCase.field)
	}
}

// TestRouteOptionApplicationIsIdempotent pins that a second application cannot change the metadata
// further.
//
// The pre-match path and the full match path both call this function for the same connection, so a
// field that accumulates - appended rather than assigned, or a counter - would make the pre-match
// decision disagree with the routing that follows it.
func TestRouteOptionApplicationIsIdempotent(t *testing.T) {
	var options R.RuleActionRouteOptions
	options.OverrideAddress = M.ParseSocksaddr("203.0.113.9")
	options.OverridePort = 8443
	options.UDPTimeout = 90 * time.Second
	options.TLSFragment = true
	options.TLSRecordFragment = true
	options.UDPConnect = true

	metadata := adapter.InboundContext{Destination: M.ParseSocksaddr("93.184.216.34:443")}
	applyRouteOptionsMetadata(&metadata, &options)
	once := metadata
	applyRouteOptionsMetadata(&metadata, &options)

	require.Equal(t, once.Destination, metadata.Destination)
	require.Equal(t, once.RouteOriginalDestination, metadata.RouteOriginalDestination,
		"the recorded original destination must stay the FIRST one")
	require.Equal(t, once.UDPTimeout, metadata.UDPTimeout)
	require.Equal(t, once.DestinationAddresses, metadata.DestinationAddresses)
}
