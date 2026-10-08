package group

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Tests for the transport-manager integration: member resolution, start-order
// dependency handling, and the exclusions.

// managerRegistry constructs real group transports and fakes for everything
// else, which is what lets a test drive the manager's own start ordering.
type managerRegistry struct {
	members map[string]*fakeTransport
}

func (r *managerRegistry) OptionTypes() []string { return nil }

func (r *managerRegistry) CreateOptions(transportType string) (any, bool) { return nil, false }

func (r *managerRegistry) CreateDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, transportType string, options any) (adapter.DNSTransport, error) {
	if transportType == C.DNSTypeGroup {
		var groupOptions option.GroupDNSServerOptions
		if options != nil {
			groupOptions = options.(option.GroupDNSServerOptions)
		}
		return NewTransport(ctx, logger, tag, groupOptions)
	}
	fake := newFakeTransport(tag)
	fake.transportType = transportType
	r.members[tag] = fake
	return fake, nil
}

func newManagerHarness(t *testing.T) (*dns.TransportManager, *managerRegistry, context.Context, log.ContextLogger) {
	t.Helper()
	registry := &managerRegistry{members: make(map[string]*fakeTransport)}
	manager := dns.NewTransportManager(registry, nil, "")
	manager.Initialize(func() (adapter.DNSTransport, error) {
		fake := newFakeTransport("default")
		fake.transportType = "test"
		return fake, nil
	})
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	logger := log.NewNOPFactory().NewLogger("dns-group-manager-test")
	return manager, registry, ctx, logger
}

func startManager(t *testing.T, manager *dns.TransportManager, ctx context.Context, logger log.ContextLogger) *adapter.Scope {
	t.Helper()
	scope := adapter.NewScope(ctx, logger)
	require.NoError(t, manager.Start(adapter.StartStateInitialize, scope))
	require.NoError(t, manager.Start(adapter.StartStateStart, scope))
	t.Cleanup(func() {
		_ = scope.Close()
	})
	return scope
}

// TestNestedGroupStartsAndAnswers is the composition claim: a group may name
// another group, the manager starts them in dependency order, and a query
// reaches the leaves.
func TestNestedGroupStartsAndAnswers(t *testing.T) {
	manager, registry, ctx, logger := newManagerHarness(t)

	require.NoError(t, manager.Create(ctx, logger, "leaf1", "test", struct{}{}))
	require.NoError(t, manager.Create(ctx, logger, "leaf2", "test", struct{}{}))
	require.NoError(t, manager.Create(ctx, logger, "inner", C.DNSTypeGroup, option.GroupDNSServerOptions{
		Servers: badoption.Listable[string]{"leaf1", "leaf2"},
		Mode:    ModeStable,
	}))
	require.NoError(t, manager.Create(ctx, logger, "outer", C.DNSTypeGroup, option.GroupDNSServerOptions{
		Servers: badoption.Listable[string]{"inner"},
		Mode:    ModeStable,
	}))

	startManager(t, manager, ctx, logger)
	registry.members["leaf1"].succeed()
	registry.members["leaf2"].succeed()

	outerTransport, loaded := manager.Transport("outer")
	require.True(t, loaded)
	response, err := outerTransport.Exchange(testContext(t), queryMessage())
	require.NoError(t, err, "a nested group must start and answer")
	require.NotNil(t, response)
	require.NotZero(t, registry.members["leaf1"].callCount()+registry.members["leaf2"].callCount(),
		"the outer group must have reached one of the leaves through the inner group")
}

// TestMemberCycleIsRejectedByTheManager verifies the free cycle report the
// manager derives from Dependencies().
func TestMemberCycleIsRejectedByTheManager(t *testing.T) {
	manager, _, ctx, logger := newManagerHarness(t)

	require.NoError(t, manager.Create(ctx, logger, "cycle-a", C.DNSTypeGroup, option.GroupDNSServerOptions{
		Servers: badoption.Listable[string]{"cycle-b"},
	}))
	require.NoError(t, manager.Create(ctx, logger, "cycle-b", C.DNSTypeGroup, option.GroupDNSServerOptions{
		Servers: badoption.Listable[string]{"cycle-a"},
	}))

	scope := adapter.NewScope(ctx, logger)
	defer scope.Close()
	require.NoError(t, manager.Start(adapter.StartStateInitialize, scope))
	err := manager.Start(adapter.StartStateStart, scope)
	require.ErrorContains(t, err, "circular server dependency")
}

// TestMissingMemberIsRejected verifies the other half of the dependency report:
// a tag nobody created.
func TestMissingMemberIsRejected(t *testing.T) {
	manager, _, ctx, logger := newManagerHarness(t)

	require.NoError(t, manager.Create(ctx, logger, "lonely", C.DNSTypeGroup, option.GroupDNSServerOptions{
		Servers: badoption.Listable[string]{"nope"},
	}))

	scope := adapter.NewScope(ctx, logger)
	defer scope.Close()
	require.NoError(t, manager.Start(adapter.StartStateInitialize, scope))
	err := manager.Start(adapter.StartStateStart, scope)
	require.ErrorContains(t, err, "dependency[nope] not found for server[lonely]")
}

// TestUnknownMemberIsRejectedAtStart covers the transport's own guard. The
// manager reports its own dependency error first (see
// TestMissingMemberIsRejected), but Start is reachable through any manager
// implementation, so the group must refuse an unknown tag itself.
func TestUnknownMemberIsRejectedAtStart(t *testing.T) {
	_, _, ctx, logger := newManagerHarness(t)

	rawTransport, err := NewTransport(ctx, logger, "g", option.GroupDNSServerOptions{
		Servers: badoption.Listable[string]{"nope"},
	})
	require.NoError(t, err)
	err = rawTransport.Start(adapter.StartStateStart, nil)
	require.EqualError(t, err, "group[g]: DNS server not found: nope")
}

// TestSyntheticMembersAreRejectedAtStart covers the exclusion criterion: a
// member that cannot fail over the network cannot be failed over from.
func TestSyntheticMembersAreRejectedAtStart(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		memberType string
		want       string
	}{
		{
			name:       "fakeip",
			memberType: C.DNSTypeFakeIP,
			want:       "group[synth]: server type fakeip is not allowed in a group: blocked",
		},
		{
			name:       "hosts",
			memberType: C.DNSTypeHosts,
			want:       "group[synth]: server type hosts is not allowed in a group: blocked",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			manager, _, ctx, logger := newManagerHarness(t)

			// Seed a real server first, so the default slot is taken and the
			// manager's own fakeip-default rule does not fire before the group
			// gets to reject the member.
			require.NoError(t, manager.Create(ctx, logger, "seed", "test", struct{}{}))
			require.NoError(t, manager.Create(ctx, logger, "blocked", testCase.memberType, struct{}{}))
			require.NoError(t, manager.Create(ctx, logger, "synth", C.DNSTypeGroup, option.GroupDNSServerOptions{
				Servers: badoption.Listable[string]{"blocked"},
			}))

			scope := adapter.NewScope(ctx, logger)
			defer scope.Close()
			require.NoError(t, manager.Start(adapter.StartStateInitialize, scope))
			err := manager.Start(adapter.StartStateStart, scope)
			require.ErrorContains(t, err, testCase.want)
		})
	}
}
