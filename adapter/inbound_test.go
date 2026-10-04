package adapter

import (
	"context"
	"github.com/sagernet/sing-box/common/trafficclass"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSResponseAddressesUnmapsHTTPSIPv4Hints(t *testing.T) {
	t.Parallel()

	ipv4Hint := net.ParseIP("1.1.1.1")
	require.NotNil(t, ipv4Hint)

	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response: true,
			Rcode:    dns.RcodeSuccess,
		},
		Answer: []dns.RR{
			&dns.HTTPS{
				SVCB: dns.SVCB{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn("example.com"),
						Rrtype: dns.TypeHTTPS,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Priority: 1,
					Target:   ".",
					Value: []dns.SVCBKeyValue{
						&dns.SVCBIPv4Hint{Hint: []net.IP{ipv4Hint}},
					},
				},
			},
		},
	}

	addresses := DNSResponseAddresses(response)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, addresses)
	require.True(t, addresses[0].Is4())
}

// TestContextForMultiplexSessionDoesNotInheritTrafficClass pins a boundary that is easy to break by
// accident.
//
// A multiplex session is a SHARED transport. It carries many logical flows, and those flows can
// hold different traffic classes - an interactive prompt and a bulk upload can share one mux
// session. The session-level context must therefore stay transport-scoped.
//
// The failure this guards is subtle and permanent: if ContextForMultiplexSession copied the class
// from whichever flow happened to establish the session, the underlying tunnel would be marked
// interactive for the rest of its life, and a later bulk flow through that tunnel would inherit a
// priority it was never given.
func TestContextForMultiplexSessionDoesNotInheritTrafficClass(t *testing.T) {
	// The first logical flow through the session is interactive.
	firstFlow := &InboundContext{
		Outbound:     "shared-vless",
		TrafficClass: trafficclass.ClassInteractive,
	}
	firstCtx := WithContext(context.Background(), firstFlow)

	sessionCtx := ContextForMultiplexSession(firstCtx)
	session := ContextFrom(sessionCtx)
	require.NotNil(t, session)

	// Transport-level metadata is still carried: the session has to know which outbound it belongs
	// to.
	require.Equal(t, "shared-vless", session.Outbound,
		"the session context must still carry transport-level metadata")

	// But the per-flow class is not.
	require.Equal(t, trafficclass.ClassDefault, session.TrafficClass,
		"a multiplex session carries flows of several classes; inheriting the first flow's class "+
			"would mark the shared tunnel permanently")

	// And the first flow keeps its own class: the session context is a separate value, not a
	// mutation of the flow's.
	require.Equal(t, trafficclass.ClassInteractive, ContextFrom(firstCtx).TrafficClass,
		"building a session context must not alter the logical flow's metadata")

	// A second flow builds its own session context. It must be transport-scoped too: it neither
	// inherits the first flow's interactive class nor exports its own bulk class onto the session.
	secondFlow := &InboundContext{
		Outbound:     "shared-vless",
		TrafficClass: trafficclass.ClassBulk,
	}
	secondFlowCtx := WithContext(context.Background(), secondFlow)
	secondSession := ContextForMultiplexSession(secondFlowCtx)
	require.Equal(t, trafficclass.ClassDefault, ContextFrom(secondSession).TrafficClass,
		"the session context stays transport-scoped whichever flow built it")
	require.Equal(t, trafficclass.ClassBulk, ContextFrom(secondFlowCtx).TrafficClass,
		"the flow's own class is untouched by building a session context")
}
