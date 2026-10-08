package libbox

import (
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
)

const (
	DNSModeDisabled = tun.DNSModeDisabled
	DNSModeNative   = tun.DNSModeNative
	DNSModeHijack   = tun.DNSModeHijack
)

type TunOptions interface {
	GetInet4Address() RoutePrefixIterator
	GetInet6Address() RoutePrefixIterator
	GetDNSMode() *StringBox
	GetDNSServerAddress() (StringIterator, error)
	GetMTU() int32
	GetAutoRoute() bool
	GetStrictRoute() bool
	GetInet4RouteAddress() RoutePrefixIterator
	GetInet6RouteAddress() RoutePrefixIterator
	GetInet4RouteExcludeAddress() RoutePrefixIterator
	GetInet6RouteExcludeAddress() RoutePrefixIterator
	GetInet4RouteRange() RoutePrefixIterator
	GetInet6RouteRange() RoutePrefixIterator
	GetIncludePackage() StringIterator
	GetExcludePackage() StringIterator
	IsHTTPProxyEnabled() bool
	GetHTTPProxyServer() string
	GetHTTPProxyServerPort() int32
	GetHTTPProxyBypassDomain() StringIterator
	GetHTTPProxyMatchDomain() StringIterator
}

type RoutePrefix struct {
	address netip.Addr
	prefix  int
}

func (p *RoutePrefix) Address() string {
	return p.address.String()
}

func (p *RoutePrefix) Prefix() int32 {
	return int32(p.prefix)
}

func (p *RoutePrefix) Mask() string {
	var bits int
	if p.address.Is6() {
		bits = 128
	} else {
		bits = 32
	}
	return net.IP(net.CIDRMask(p.prefix, bits)).String()
}

func (p *RoutePrefix) String() string {
	return netip.PrefixFrom(p.address, p.prefix).String()
}

type RoutePrefixIterator interface {
	Next() *RoutePrefix
	HasNext() bool
}

func mapRoutePrefix(prefixes []netip.Prefix) RoutePrefixIterator {
	return newIterator(common.Map(prefixes, func(prefix netip.Prefix) *RoutePrefix {
		return &RoutePrefix{
			address: prefix.Addr(),
			prefix:  prefix.Bits(),
		}
	}))
}

var _ TunOptions = (*tunOptions)(nil)

type tunOptions struct {
	*tun.Options
	routeRanges []netip.Prefix
	option.TunPlatformOptions
}

func (o *tunOptions) GetInet4Address() RoutePrefixIterator {
	return mapRoutePrefix(o.Inet4Address)
}

func (o *tunOptions) GetInet6Address() RoutePrefixIterator {
	return mapRoutePrefix(o.Inet6Address)
}

func (o *tunOptions) GetDNSMode() *StringBox {
	return wrapString(o.Options.DNSMode)
}

func (o *tunOptions) GetDNSServerAddress() (StringIterator, error) {
	dnsServers, err := o.Options.DNSServerAddress()
	if err != nil {
		return nil, err
	}
	return newIterator(common.Map(dnsServers, netip.Addr.String)), nil
}

func (o *tunOptions) GetMTU() int32 {
	return int32(o.MTU)
}

func (o *tunOptions) GetAutoRoute() bool {
	return o.AutoRoute
}

func (o *tunOptions) GetStrictRoute() bool {
	return o.StrictRoute
}

func (o *tunOptions) GetInet4RouteAddress() RoutePrefixIterator {
	return mapRoutePrefix(o.Inet4RouteAddress)
}

func (o *tunOptions) GetInet6RouteAddress() RoutePrefixIterator {
	return mapRoutePrefix(o.Inet6RouteAddress)
}

func (o *tunOptions) GetInet4RouteExcludeAddress() RoutePrefixIterator {
	return mapRoutePrefix(o.Inet4RouteExcludeAddress)
}

func (o *tunOptions) GetInet6RouteExcludeAddress() RoutePrefixIterator {
	return mapRoutePrefix(o.Inet6RouteExcludeAddress)
}

func (o *tunOptions) GetInet4RouteRange() RoutePrefixIterator {
	return mapRoutePrefix(common.Filter(o.routeRanges, func(it netip.Prefix) bool {
		return it.Addr().Is4()
	}))
}

func (o *tunOptions) GetInet6RouteRange() RoutePrefixIterator {
	return mapRoutePrefix(common.Filter(o.routeRanges, func(it netip.Prefix) bool {
		return it.Addr().Is6()
	}))
}

func (o *tunOptions) GetIncludePackage() StringIterator {
	return newIterator(o.IncludePackage)
}

func (o *tunOptions) GetExcludePackage() StringIterator {
	return newIterator(o.ExcludePackage)
}

func (o *tunOptions) IsHTTPProxyEnabled() bool {
	if o.TunPlatformOptions.HTTPProxy == nil {
		return false
	}
	return o.TunPlatformOptions.HTTPProxy.Enabled
}

// GetHTTPProxyServer returns the HTTP proxy address the platform should point the TUN interface at.
//
// # Why this is deliberately still a bare string, against the rule above
//
// It has the shape that rule exists to catch - a Go-implemented accessor read FROM the bound
// language, so it goes through the generated cgo //export wrapper and its packed result frame. The
// fix would be the same one GetDNSMode uses: return *StringBox and read it through Value.
//
// It is not applied here because the blocked dependency is on the OTHER side of the boundary. The
// shipped Apple client calls this and expects a string:
//
//	clients/apple/Library/Network/ExtensionPlatformInterface.swift
//	    options.getHTTPProxyServer()
//
// Changing the Go signature rewrites the generated ObjC method from `- (NSString *)` to
// `- (LibboxStringBox *)`, so the Apple client stops compiling until that one call site becomes
// `options.getHTTPProxyServer()?.value`. That is a coordinated two-repository release, and doing
// half of it here would break the Apple build to remove a risk that is currently theoretical:
// upstream's fix (cmd/cgo CL 692935, Go 1.26) is about frame alignment, and whether any particular
// generated frame lands off an 8-byte boundary depends on the platform C compiler's frame offset,
// which is not visible from here.
//
// So it is registered as checked debt in gomobile_surface_test.go instead. The tripwire still fails
// on any NEW occurrence, and it fails if this entry is removed without the signature being fixed,
// so the register cannot rot into a mute allowlist. Converting this belongs with the Apple client
// migration, where the call site can move in the same commit.
func (o *tunOptions) GetHTTPProxyServer() string {
	return o.TunPlatformOptions.HTTPProxy.Server
}

func (o *tunOptions) GetHTTPProxyServerPort() int32 {
	return int32(o.TunPlatformOptions.HTTPProxy.ServerPort)
}

func (o *tunOptions) GetHTTPProxyBypassDomain() StringIterator {
	return newIterator(o.TunPlatformOptions.HTTPProxy.BypassDomain)
}

func (o *tunOptions) GetHTTPProxyMatchDomain() StringIterator {
	return newIterator(o.TunPlatformOptions.HTTPProxy.MatchDomain)
}
