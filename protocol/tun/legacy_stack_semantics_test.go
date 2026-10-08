package tun

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// THE LEGACY `stack` OPTION MUST KEEP MEANING WHAT THE USER WROTE.
//
// # Why this is a behavioural test and not a schema assertion
//
// sing-box 1.15 makes sing-tun's own TCP/IP stack the default and deprecates `stack`. The tempting
// shortcut - keep parsing the option, then quietly hand every value to the new Go stack - is
// forbidden, and it is forbidden for a user-visible reason: a configuration that says
// `"stack": "gvisor"` was written by someone who needed gVisor's UDP behaviour, and a build that
// silently runs a different stack gives them a tunnel that starts, passes a smoke test, and
// misbehaves in production with nothing in the log to explain it. A clear startup failure is the
// only acceptable outcome when the requested stack is not in the build.
//
// So the assertions are made against the three places the value actually travels:
//
//  1. the config field still parses every value, including ones sing-box does not know
//     (option.TunInboundOptions is the compatibility parse and must not reject them itself);
//  2. NewInbound passes the string through unmodified (no normalisation to "go");
//  3. sing-tun's NewStack resolves it to that stack or to an error - never to a different stack.
//
// The last point is the one that matters. `tun.NewStack` is upstream's, and the test pins the
// contract sing-box depends on: unknown and unavailable values fail loudly.

// stackProbeValues is the compatibility matrix: the unset default, both shipped stacks, the two
// values whose implementation is gone from the build, and a value nobody ever defined.
var stackProbeValues = []struct {
	name string
	// configured is the raw JSON value; "" means the key is absent entirely, which is the
	// default the migration introduces.
	configured string
	// wantGo / wantSystem describe the stack the value must resolve to, when it resolves.
	wantGo     bool
	wantSystem bool
	// wantUnavailable is set for the values whose implementation is build-tagged out.
	wantUnavailable bool
	// wantUnknown is set for a value sing-tun has never heard of.
	wantUnknown bool
}{
	{name: "unset", configured: "", wantGo: true},
	{name: "explicit go", configured: "go", wantGo: true},
	{name: "system", configured: "system", wantSystem: true},
	{name: "gvisor", configured: "gvisor", wantUnavailable: true},
	{name: "mixed", configured: "mixed", wantUnavailable: true},
	{name: "unknown", configured: "definitely-not-a-stack", wantUnknown: true},
}

// TestUnsetStackSelectsTheNewGoStack is the migration's default, stated on its own so a reader can
// find it without reading the table. "The default changed" is the entire point of this release, and
// a default that silently became the old system stack again would be a release-blocking regression
// that no other test in the tree would notice.
func TestUnsetStackSelectsTheNewGoStack(t *testing.T) {
	ctx, inbound := newLegacyStackInbound(t, "")
	require.Empty(t, inbound.stack, "an unset `stack` must stay empty through NewInbound")
	stack, err := newProbeStack(ctx, inbound.stack)
	require.NoError(t, err)
	require.IsType(t, &tun.Go{}, stack,
		"an unset `stack` must select sing-tun's Go stack; that is the 1.15 default")
}

// TestLegacyStackValueResolvesToItsOwnStack walks the compatibility matrix. Every row asserts the
// resolved type or the failure, never merely that construction succeeded.
func TestLegacyStackValueResolvesToItsOwnStack(t *testing.T) {
	for _, testCase := range stackProbeValues {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, inbound := newLegacyStackInbound(t, testCase.configured)
			require.Equal(t, testCase.configured, inbound.stack,
				"NewInbound must pass the configured stack through unmodified; normalising it here is "+
					"how a user's `gvisor` silently becomes something else")

			stack, err := newProbeStack(ctx, inbound.stack)
			switch {
			case testCase.wantGo:
				require.NoError(t, err)
				require.IsType(t, &tun.Go{}, stack)
			case testCase.wantSystem:
				require.NoError(t, err)
				require.IsType(t, &tun.System{}, stack)
			case testCase.wantUnavailable:
				if tun.WithGVisor {
					// A control build (with_gvisor) legitimately resolves these. The shipped
					// composition does not include the tag, which is asserted by the builder's own
					// tag-policy tripwire rather than here.
					require.NoError(t, err)
					require.NotNil(t, stack)
					return
				}
				require.Error(t, err)
				require.Nil(t, stack, "a failed resolution must not hand back a usable stack")
				require.ErrorIs(t, err, tun.ErrGVisorNotIncluded,
					"a build without gVisor must say so; the user asked for a specific stack and "+
						"silently getting a different one is the failure this test exists to prevent")
			case testCase.wantUnknown:
				require.Error(t, err)
				require.Nil(t, stack)
				require.Contains(t, err.Error(), "unknown stack: ", testCase.configured)
			}
		})
	}
}

// TestGVisorAndMixedAreNeverMappedOntoTheGoStack is the forbidden outcome, asserted directly rather
// than inferred from the matrix. If a future refactor "simplifies" the stack selection by falling
// back to the default, this fails even if the unknown-value case is also broken.
func TestGVisorAndMixedAreNeverMappedOntoTheGoStack(t *testing.T) {
	for _, value := range []string{"gvisor", "mixed"} {
		t.Run(value, func(t *testing.T) {
			ctx := newStackTestContext(t)
			stack, err := newProbeStack(ctx, value)
			if tun.WithGVisor {
				t.Skip("this build includes gVisor; the mapping check applies to the shipped build")
			}
			require.Error(t, err)
			_, resolvedToGoStack := stack.(*tun.Go)
			require.False(t, resolvedToGoStack,
				"`stack: %q` must fail, not run the default stack with a different name", value)
			require.ErrorIs(t, err, tun.ErrGVisorNotIncluded)
			require.Contains(t, err.Error(), "gVisor",
				"the error must name what is missing, or the user cannot act on it")
		})
	}
}

// TestLegacyStackOptionStillParsesUnknownValues pins the compatibility parse. Validation belongs to
// stack construction, not to JSON decoding: rejecting an unknown value at parse time would break
// configs that the previous release accepted with a warning, and sing-box keeps parsing the option
// until upstream actually removes it.
func TestLegacyStackOptionStillParsesUnknownValues(t *testing.T) {
	for _, testCase := range stackProbeValues {
		t.Run(testCase.name, func(t *testing.T) {
			var options option.TunInboundOptions
			document := `{}`
			if testCase.configured != "" {
				document = `{"stack":` + mustJSON(t, testCase.configured) + `}`
			}
			require.NoError(t, json.Unmarshal([]byte(document), &options),
				"the `stack` option must still decode; it is deprecated, not removed")
			require.Equal(t, testCase.configured, options.Stack)
		})
	}
}

// TestLegacyStackOptionIsReportedAsDeprecated checks the other half of "keep the compatibility
// parse": a user who still writes the option is told, once, through the standard deprecation
// channel. An option that is deprecated but silent is one a user never learns to remove.
func TestLegacyStackOptionIsReportedAsDeprecated(t *testing.T) {
	for _, testCase := range stackProbeValues {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := &recordingDeprecatedManager{}
			_, _ = newLegacyStackInboundWithRecorder(t, testCase.configured, recorder)
			if testCase.configured == "" {
				require.Empty(t, recorder.reported(),
					"an unset `stack` is the documented default and must not warn; warning on the "+
						"default would put a deprecation notice in front of every user who did nothing wrong")
				return
			}
			require.Equal(t, []deprecated.Note{deprecated.OptionTunStack}, recorder.reported())
		})
	}
}

// TestTunStackDeprecationNoteMatchesTheMigrationWindow pins the note's schedule against the
// migration guide the note links to. The deprecation is only useful if the version it names is the
// version the docs promise, because that is when the parse is allowed to become a hard failure.
func TestTunStackDeprecationNoteMatchesTheMigrationWindow(t *testing.T) {
	note := deprecated.OptionTunStack
	require.Equal(t, "tun-stack", note.Name)
	require.Equal(t, "`stack` option in TUN", note.Description)
	require.Equal(t, "1.15.0", note.DeprecatedVersion)
	require.Equal(t, "1.17.0", note.ScheduledVersion)
	require.Equal(t, "TUN_STACK", note.EnvName)
	require.Contains(t, note.MigrationLink, "migrate-tun-stack",
		"the note must point at the migration section that explains what to do")
	require.Contains(t, deprecated.Options, note,
		"a note that is not in Options is never surfaced by the CLI")
}

// newLegacyStackInbound builds a real Inbound for the configured stack value and returns it. It uses
// the production constructor rather than assembling the struct, because the property under test is
// what the constructor does with the option.
func newLegacyStackInbound(t *testing.T, configured string) (context.Context, *Inbound) {
	t.Helper()
	return newLegacyStackInboundWithRecorder(t, configured, nil)
}

func newLegacyStackInboundWithRecorder(t *testing.T, configured string, recorder *recordingDeprecatedManager) (context.Context, *Inbound) {
	t.Helper()
	ctx := newStackTestContext(t)
	if recorder != nil {
		ctx = service.ContextWith[deprecated.Manager](ctx, recorder)
	}
	options := option.TunInboundOptions{Stack: configured}
	inbound, err := NewInbound(ctx, nil, log.NewNOPFactory().Logger(), "tun-in", options)
	require.NoError(t, err, "constructing the inbound for stack %q must succeed; the option is "+
		"deprecated, and a deprecated option that fails at parse time is a removal", configured)
	typed, isTun := inbound.(*Inbound)
	require.True(t, isTun)
	return ctx, typed
}

// newStackTestContext registers the one service NewInbound reads unconditionally. The network
// manager is a stub: nothing on the constructor path under test dials or listens, and a stub that
// returns zero values keeps the test from depending on the host's interfaces.
func newStackTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ctx = service.ContextWith[adapter.NetworkManager](ctx, &stackNetworkManagerStub{})
	return ctx
}

// newProbeStack resolves the way the inbound does at Start time, with the same options shape.
//
// The interface address is not incidental: the legacy `system` stack REFUSES to be constructed
// without one ("missing interface address"), which is itself part of its contract - it forwards
// from the tun's own address, so it has nothing to bind its listener to otherwise. Supplying the
// address keeps this probe measuring stack selection rather than that precondition, which is
// covered by the constructor's own upstream tests.
func newProbeStack(ctx context.Context, stack string) (tun.Stack, error) {
	return tun.NewStack(stack, tun.StackOptions{
		Context:     ctx,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Minute,
		TunOptions: tun.Options{
			MTU:                1500,
			Inet4Address:       []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
			Inet6Address:       []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
			IPRoute2TableIndex: tun.DefaultIPRoute2TableIndex,
			IPRoute2RuleIndex:  tun.DefaultIPRoute2RuleIndex,
		},
	})
}

func mustJSON(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return string(encoded)
}

// recordingDeprecatedManager captures what the constructor reported, so "no warning" and "the tun
// warning" are distinguishable rather than both being "the test passed".
type recordingDeprecatedManager struct {
	access sync.Mutex
	notes  []deprecated.Note
}

func (m *recordingDeprecatedManager) ReportDeprecated(feature deprecated.Note) {
	m.access.Lock()
	defer m.access.Unlock()
	m.notes = append(m.notes, feature)
}

func (m *recordingDeprecatedManager) reported() []deprecated.Note {
	m.access.Lock()
	defer m.access.Unlock()
	return append([]deprecated.Note(nil), m.notes...)
}

// stackNetworkManagerStub satisfies adapter.NetworkManager. Only the methods NewInbound actually
// reads are meaningful; the rest exist because the interface is wide and a narrower stub would not
// compile against the production constructor.
type stackNetworkManagerStub struct{}

func (m *stackNetworkManagerStub) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (m *stackNetworkManagerStub) Close() error                                       { return nil }
func (m *stackNetworkManagerStub) Initialize(ruleSets []adapter.RuleSet)              {}
func (m *stackNetworkManagerStub) InterfaceFinder() control.InterfaceFinder           { return nil }
func (m *stackNetworkManagerStub) UpdateInterfaces() error                            { return nil }
func (m *stackNetworkManagerStub) DefaultNetworkInterface() *adapter.NetworkInterface { return nil }
func (m *stackNetworkManagerStub) NetworkInterfaces() []adapter.NetworkInterface      { return nil }
func (m *stackNetworkManagerStub) NetworkEnvironment() uint64                         { return 0 }
func (m *stackNetworkManagerStub) AutoDetectInterface() bool                          { return false }
func (m *stackNetworkManagerStub) AutoDetectInterfaceFunc() control.Func              { return nil }
func (m *stackNetworkManagerStub) ProtectFunc() control.Func                          { return nil }
func (m *stackNetworkManagerStub) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}
func (m *stackNetworkManagerStub) RegisterAutoRedirectOutputMark(mark uint32) error { return nil }
func (m *stackNetworkManagerStub) AutoRedirectOutputMark() uint32                   { return 0 }
func (m *stackNetworkManagerStub) AutoRedirectOutputMarkFunc() control.Func         { return nil }
func (m *stackNetworkManagerStub) RegisterBridgeInterface(interfaceName string)     {}
func (m *stackNetworkManagerStub) BridgeInterfaces() []string                       { return nil }
func (m *stackNetworkManagerStub) NetworkMonitor() tun.NetworkUpdateMonitor         { return nil }
func (m *stackNetworkManagerStub) InterfaceMonitor() tun.DefaultInterfaceMonitor    { return nil }
func (m *stackNetworkManagerStub) PackageManager() tun.PackageManager               { return nil }
func (m *stackNetworkManagerStub) NeedWIFIState() bool                              { return false }
func (m *stackNetworkManagerStub) WIFIState() adapter.WIFIState                     { return adapter.WIFIState{} }
func (m *stackNetworkManagerStub) UpdateWIFIState(ctx context.Context)              {}
func (m *stackNetworkManagerStub) ResetNetwork(ctx context.Context)                 {}
func (m *stackNetworkManagerStub) ReleaseMemory(ctx context.Context)                {}
func (m *stackNetworkManagerStub) TrimMemory(ctx context.Context)                   {}

var (
	_ adapter.NetworkManager = (*stackNetworkManagerStub)(nil)
	_ deprecated.Manager     = (*recordingDeprecatedManager)(nil)
)
