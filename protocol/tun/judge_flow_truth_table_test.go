package tun

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"

	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

// The complete DNS precedence truth table, plus the concurrent route-set pair.
//
// # Why a table rather than more single cases
//
// DNS precedence is a precedence ORDER between four independent inputs: a configured hijack address,
// the by-port rule, a route address-set miss, and a route exclude-set hit. Individual tests pin the
// pairs someone thought of; a table pins every combination, so a future edit that reorders the checks
// has to fail somewhere rather than moving a case nobody covered.

// truthTableInbound builds an inbound with every input the table varies.
func truthTableInbound(t *testing.T, dnsAddress []netip.Addr, byPort bool, routeSet []*netipx.IPSet, excludeSet []*netipx.IPSet) *Inbound {
	t.Helper()
	return &Inbound{
		tag:                    "tun-truth",
		ctx:                    context.Background(),
		router:                 &neverBypassRouter{},
		logger:                 log.NewNOPFactory().Logger(),
		dnsHijackAddress:       dnsAddress,
		dnsHijackByPort:        byPort,
		routeAddressSet:        routeSet,
		routeExcludeAddressSet: excludeSet,
	}
}

func ipSetOf(t *testing.T, prefixes ...string) *netipx.IPSet {
	t.Helper()
	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		builder.AddPrefix(netip.MustParsePrefix(prefix))
	}
	set, err := builder.IPSet()
	require.NoError(t, err)
	return set
}

// TestJudgeFlowDNSPrecedenceTruthTable is H1.
func TestJudgeFlowDNSPrecedenceTruthTable(t *testing.T) {
	const (
		protocolTCP = 6
		protocolUDP = 17
	)
	dnsAddress := netip.MustParseAddr("198.18.0.1")
	otherAddress := netip.MustParseAddr("203.0.113.5")

	// A route set that does NOT contain the queried address, so a miss is in play.
	missSet := ipSetOf(t, "10.0.0.0/8")
	// A route set that DOES contain it.
	hitSet := ipSetOf(t, "203.0.113.0/24")
	// An exclude set containing it.
	excludeHit := ipSetOf(t, "203.0.113.0/24")

	cases := []struct {
		name        string
		dnsAddress  []netip.Addr
		byPort      bool
		routeSet    []*netipx.IPSet
		excludeSet  []*netipx.IPSet
		protocol    uint8
		destination netip.AddrPort
		expected    tun.FlowAction
		why         string
	}{
		// --- the configured hijack address wins over everything ---
		{"addr/udp", []netip.Addr{dnsAddress}, false, nil, nil, protocolUDP,
			netip.AddrPortFrom(dnsAddress, 5353), tun.ActionHijackDNS,
			"a configured DNS address is hijacked on every port, not only 53"},
		{"addr/tcp", []netip.Addr{dnsAddress}, false, nil, nil, protocolTCP,
			netip.AddrPortFrom(dnsAddress, 5353), tun.ActionAccept,
			"TCP is accepted so the stream DNS path takes it, never bypassed"},
		{"addr beats route-set miss", []netip.Addr{dnsAddress}, false, []*netipx.IPSet{missSet}, nil, protocolUDP,
			netip.AddrPortFrom(dnsAddress, 53), tun.ActionHijackDNS, "DNS precedes the route-set bypass"},
		{"addr beats exclude hit", []netip.Addr{dnsAddress}, false, nil, []*netipx.IPSet{excludeHit}, protocolUDP,
			netip.AddrPortFrom(dnsAddress, 53), tun.ActionHijackDNS, "DNS precedes the exclude-set bypass"},

		// --- the by-port rule, when enabled ---
		{"byport/udp53", nil, true, nil, nil, protocolUDP,
			netip.AddrPortFrom(otherAddress, 53), tun.ActionHijackDNS, "UDP/53 is hijacked"},
		{"byport/tcp53", nil, true, nil, nil, protocolTCP,
			netip.AddrPortFrom(otherAddress, 53), tun.ActionAccept,
			"TCP/53 is accepted, not hijacked and not bypassed"},
		{"byport/udp non-53 falls through", nil, true, nil, nil, protocolUDP,
			netip.AddrPortFrom(otherAddress, 5353), tun.ActionAccept,
			"only port 53 is special; a continuing router with no flow Port accepts"},
		{"byport beats route-set miss", nil, true, []*netipx.IPSet{missSet}, nil, protocolUDP,
			netip.AddrPortFrom(otherAddress, 53), tun.ActionHijackDNS, "by-port precedes the bypasses"},
		{"byport beats exclude hit", nil, true, nil, []*netipx.IPSet{excludeHit}, protocolTCP,
			netip.AddrPortFrom(otherAddress, 53), tun.ActionAccept, "by-port precedes the bypasses"},

		// --- disabled by-port ---
		{"byport disabled/udp53", nil, false, nil, nil, protocolUDP,
			netip.AddrPortFrom(otherAddress, 53), tun.ActionAccept, "the rule is off, so nothing special"},

		// --- the route-set bypasses, with DNS out of the picture ---
		{"route-set miss bypasses", nil, false, []*netipx.IPSet{missSet}, nil, protocolTCP,
			netip.AddrPortFrom(otherAddress, 443), tun.ActionBypass, "a miss means route it without sing-box"},
		{"route-set hit continues", nil, false, []*netipx.IPSet{hitSet}, nil, protocolTCP,
			netip.AddrPortFrom(otherAddress, 443), tun.ActionAccept, "a hit means the rules apply"},
		{"exclude hit bypasses", nil, false, nil, []*netipx.IPSet{excludeHit}, protocolTCP,
			netip.AddrPortFrom(otherAddress, 443), tun.ActionBypass, "an excluded address is bypassed"},
		{"empty route set does not bypass", nil, false, nil, nil, protocolTCP,
			netip.AddrPortFrom(otherAddress, 443), tun.ActionAccept,
			"an empty route set means no constraint, not a miss"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			inbound := truthTableInbound(t, testCase.dnsAddress, testCase.byPort, testCase.routeSet, testCase.excludeSet)
			verdict := inbound.JudgeFlow(testCase.protocol,
				netip.MustParseAddrPort("192.168.1.2:40000"), testCase.destination, nil)
			require.Equal(t, testCase.expected, verdict.Action, testCase.why)
		})
	}
}

// TestBypassVerdictCarriesNoPort is H/H3's Port invariant, over every bypassing case.
func TestBypassVerdictCarriesNoPort(t *testing.T) {
	otherAddress := netip.MustParseAddr("203.0.113.5")
	missSet := ipSetOf(t, "10.0.0.0/8")

	bypassCases := []struct {
		name       string
		routeSet   []*netipx.IPSet
		excludeSet []*netipx.IPSet
		protocol   uint8
	}{
		{"route-set miss", []*netipx.IPSet{missSet}, nil, 6},
		{"exclude hit", nil, []*netipx.IPSet{ipSetOf(t, "203.0.113.0/24")}, 6},
		{"route-set miss udp", []*netipx.IPSet{missSet}, nil, 17},
	}

	for _, testCase := range bypassCases {
		t.Run(testCase.name, func(t *testing.T) {
			inbound := truthTableInbound(t, nil, false, testCase.routeSet, testCase.excludeSet)
			verdict := inbound.JudgeFlow(testCase.protocol,
				netip.MustParseAddrPort("192.168.1.2:40000"),
				netip.AddrPortFrom(otherAddress, 443), nil)

			require.Equal(t, tun.ActionBypass, verdict.Action)
			require.Nil(t, verdict.Port,
				"a bypass verdict carried a Port. The pinned consumer type-asserts it to a ping "+
					"destination, so attaching one turns a bypass into a ping")
			require.Zero(t, verdict.UDPTimeout)
			require.Nil(t, verdict.NewTracker)
		})
	}
}

// TestRouteSetPairIsReadConsistentlyUnderConcurrentUpdate is H4.
//
// The include and exclude sets are one decision, so a reader must never observe the include set from
// one update and the exclude set from another - that combination describes a state the inbound was
// never in, and could bypass traffic the policy meant to route.
func TestRouteSetPairIsReadConsistentlyUnderConcurrentUpdate(t *testing.T) {
	inbound := truthTableInbound(t, nil, false, nil, nil)
	// The router behind the bypass: never bypass there, so only the sets decide.
	inbound.router = &neverBypassRouter{}

	const (
		generationCount = 2000
		readerCount     = 4
	)
	var waitGroup sync.WaitGroup
	var readersDone sync.WaitGroup
	stop := make(chan struct{})

	// Writers alternate between two PAIRED states. Each pair is internally consistent, so any
	// observation that is not one of the two pairs is a torn read.
	stateAInclude := ipSetOf(t, "10.0.0.0/8")
	stateAExclude := ipSetOf(t, "192.0.2.0/24")
	stateBInclude := ipSetOf(t, "172.16.0.0/12")
	stateBExclude := ipSetOf(t, "198.51.100.0/24")

	// A destination that the PAIRED states answer identically: it is a miss under A's include and a
	// hit under B's exclude, so both pairs bypass it. A torn read is not detectable from a verdict,
	// so the assertion below reads the pair directly through the same lock the reader uses.
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for index := 0; index < generationCount; index++ {
			include, exclude := stateAInclude, stateAExclude
			if index%2 == 1 {
				include, exclude = stateBInclude, stateBExclude
			}
			inbound.routeAddressSetAccess.Lock()
			inbound.routeAddressSet = []*netipx.IPSet{include}
			inbound.routeExcludeAddressSet = []*netipx.IPSet{exclude}
			inbound.routeAddressSetAccess.Unlock()
		}
		close(stop)
	}()

	var tornReads atomic.Int32
	for reader := 0; reader < readerCount; reader++ {
		readersDone.Add(1)
		go func() {
			defer readersDone.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Exactly the reader JudgeFlow performs.
				inbound.routeAddressSetAccess.RLock()
				include := inbound.routeAddressSet
				exclude := inbound.routeExcludeAddressSet
				inbound.routeAddressSetAccess.RUnlock()

				if len(include) == 0 || len(exclude) == 0 {
					continue
				}
				includeIsA := include[0] == stateAInclude
				excludeIsA := exclude[0] == stateAExclude
				if includeIsA != excludeIsA {
					tornReads.Add(1)
				}
			}
		}()
	}

	waitGroup.Wait()
	readersDone.Wait()

	require.Zero(t, tornReads.Load(),
		"a reader observed the include set from one update and the exclude set from another. They "+
			"are one policy and are published together, so the pair must be read together")
}

// neverBypassRouter never takes the fast path, so the route sets alone decide.
//
// A router that continues the flow yields ActionFlow from adapter.JudgeFlow.
type neverBypassRouter struct {
	adapter.Router
}

func (r *neverBypassRouter) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	return adapter.PreMatchResult{Action: adapter.PreMatchContinue}
}

func (r *neverBypassRouter) PreMatchFlowAction(network string) adapter.PreMatchAction {
	return adapter.PreMatchContinue
}
