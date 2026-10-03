package masque

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// Minimal service doubles for constructor-level tests.
//
// # Why these exist rather than stubbing NewClientEndpoint
//
// The point of these tests is to run the REAL constructor. NewClientEndpoint resolves its
// dialer through common/dialer, which resolves a `domain_resolver` tag through the
// DNSTransportManager and builds default query options through the NetworkManager. Those are
// lookups into the service registry, so the registry is what gets a test double -- the
// constructor itself takes its normal path.
//
// The interfaces are large, but only a handful of methods are ever reached. The unused ones
// return zero values and are marked so a reader is not misled into thinking they matter.

// stubTransportManager serves DNS transports by tag.
type stubTransportManager struct {
	transports map[string]adapter.DNSTransport
}

func (m *stubTransportManager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (m *stubTransportManager) Close() error { return nil }
func (m *stubTransportManager) Transports() []adapter.DNSTransport {
	out := make([]adapter.DNSTransport, 0, len(m.transports))
	for _, transport := range m.transports {
		out = append(out, transport)
	}
	return out
}
func (m *stubTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, loaded := m.transports[tag]
	return transport, loaded
}
func (m *stubTransportManager) Default() adapter.DNSTransport   { return nil }
func (m *stubTransportManager) FakeIP() adapter.FakeIPTransport { return nil }
func (m *stubTransportManager) Remove(tag string) error         { return nil }
func (m *stubTransportManager) Create(ctx context.Context, logger log.ContextLogger, tag string, outboundType string, options any) error {
	return nil
}

// registryDNSTransport is an inert transport registered under the tag a test's
// `domain_resolver` names. It is never queried: the bootstrap lookup goes straight to the
// DNS router, which the test supplies separately.
type registryDNSTransport struct {
	tag string
}

func (s *registryDNSTransport) Type() string                                   { return "stub" }
func (s *registryDNSTransport) Tag() string                                    { return s.tag }
func (s *registryDNSTransport) Dependencies() []string                         { return nil }
func (s *registryDNSTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (s *registryDNSTransport) Close() error                                   { return nil }
func (s *registryDNSTransport) Reset()                                         {}
func (s *registryDNSTransport) Exchange(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return nil, errTestBootstrapUnavailable
}
func (s *registryDNSTransport) ExchangeAsync(context.Context, *mDNS.Msg, func(*mDNS.Msg, error)) {}

// stubNetworkManager supplies the network defaults the constructor reads.
//
// Only DefaultOptions is meaningful: it is how common/dialer decides which resolver to use
// when a dialer carries no explicit `domain_resolver`. An empty DomainResolver keeps that
// path off, so the tests exercise the explicit-resolver path they set up rather than
// silently falling through to a default one.
//
// Every other method returns a zero value. They are required only because the interface is
// wide; nothing on the constructor path under test reaches them.
type stubNetworkManager struct{}

func (m *stubNetworkManager) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (m *stubNetworkManager) Close() error                                               { return nil }
func (m *stubNetworkManager) Initialize(ruleSets []adapter.RuleSet)                      {}
func (m *stubNetworkManager) InterfaceFinder() control.InterfaceFinder                   { return nil }
func (m *stubNetworkManager) UpdateInterfaces() error                                    { return nil }
func (m *stubNetworkManager) DefaultNetworkInterface() *adapter.NetworkInterface         { return nil }
func (m *stubNetworkManager) NetworkInterfaces() []adapter.NetworkInterface              { return nil }
func (m *stubNetworkManager) NetworkEnvironment() uint64                                 { return 0 }
func (m *stubNetworkManager) AutoDetectInterface() bool                                  { return false }
func (m *stubNetworkManager) AutoDetectInterfaceFunc() control.Func                      { return nil }
func (m *stubNetworkManager) ProtectFunc() control.Func                                  { return nil }
func (m *stubNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}
func (m *stubNetworkManager) RegisterAutoRedirectOutputMark(mark uint32) error { return nil }
func (m *stubNetworkManager) AutoRedirectOutputMark() uint32                   { return 0 }
func (m *stubNetworkManager) AutoRedirectOutputMarkFunc() control.Func         { return nil }
func (m *stubNetworkManager) RegisterBridgeInterface(interfaceName string)     {}
func (m *stubNetworkManager) BridgeInterfaces() []string                       { return nil }
func (m *stubNetworkManager) NetworkMonitor() tun.NetworkUpdateMonitor         { return nil }
func (m *stubNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor    { return nil }
func (m *stubNetworkManager) PackageManager() tun.PackageManager               { return nil }
func (m *stubNetworkManager) NeedWIFIState() bool                              { return false }
func (m *stubNetworkManager) WIFIState() adapter.WIFIState                     { return adapter.WIFIState{} }
func (m *stubNetworkManager) UpdateWIFIState(ctx context.Context)              {}
func (m *stubNetworkManager) ResetNetwork(ctx context.Context)                 {}
func (m *stubNetworkManager) ReleaseMemory(ctx context.Context)                {}

// newTestRegistryContext builds a context whose service registry satisfies everything
// NewClientEndpoint reaches for on the path under test.
func newTestRegistryContext(dnsRouter adapter.DNSRouter) context.Context {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, &stubTransportManager{
		transports: map[string]adapter.DNSTransport{
			"dns-bootstrap": &registryDNSTransport{tag: "dns-bootstrap"},
		},
	})
	ctx = service.ContextWith[adapter.NetworkManager](ctx, &stubNetworkManager{})
	if dnsRouter != nil {
		ctx = service.ContextWith[adapter.DNSRouter](ctx, dnsRouter)
	}
	return ctx
}
