package outbound

import (
	"github.com/sagernet/sing-box/option"
)

type Adapter struct {
	outboundType string
	outboundTag  string
	network      []string
	dependencies []string
	// domainResolver is the DNS server tag this outbound resolves names through, or "".
	//
	// It is NOT in dependencies, and the two must not be confused: dependencies is the start-order
	// edge (detour, group members) and it names OUTBOUNDS, while this names a DNS TRANSPORT. Keeping
	// them apart is what lets the outbound sort treat a resolver as a peer of another namespace
	// instead of failing with "dependency not found".
	//
	// It is exported through DomainResolverReference because the DNS transport manager needs the
	// outbound half of the cross-kind graph it cannot see: its own transports declare a detour into
	// an outbound through References(), and the closing edge - that outbound resolving through that
	// transport - lives only here. See cross_kind_cycle.go.
	domainResolver string
}

func NewAdapter(outboundType string, outboundTag string, network []string, dependencies []string) Adapter {
	return Adapter{
		outboundType: outboundType,
		outboundTag:  outboundTag,
		network:      network,
		dependencies: dependencies,
	}
}

func NewAdapterWithDialerOptions(outboundType string, outboundTag string, network []string, dialOptions option.DialerOptions) Adapter {
	var dependencies []string
	if dialOptions.Detour != "" {
		dependencies = []string{dialOptions.Detour}
	}
	var domainResolver string
	if dialOptions.DomainResolver != nil {
		domainResolver = dialOptions.DomainResolver.Server
	}
	adapter := NewAdapter(outboundType, outboundTag, network, dependencies)
	adapter.domainResolver = domainResolver
	return adapter
}

// DomainResolverReference reports the DNS server tag this outbound resolves names through, or "".
//
// The value is taken from the dialer options the outbound was constructed with, which is the same
// source common/dialer reads when it builds the ResolveDialer. Declaring it here rather than
// re-deriving it from the options later is what makes the cross-kind graph a view of the objects
// that will actually dial, so the two cannot disagree.
func (a *Adapter) DomainResolverReference() string {
	return a.domainResolver
}

func (a *Adapter) Type() string {
	return a.outboundType
}

func (a *Adapter) Tag() string {
	return a.outboundTag
}

func (a *Adapter) Network() []string {
	return a.network
}

func (a *Adapter) Dependencies() []string {
	return a.dependencies
}
