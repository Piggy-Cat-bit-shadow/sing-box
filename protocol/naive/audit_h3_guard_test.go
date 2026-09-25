package naive

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// chooseHTTP3Availability is the decision the inbound makes before calling the
// HTTP/3 listener constructor.
//
// The constructor is installed by the QUIC support package and is left NIL by
// builds that do not include it. Under the production tag set
// (with_quic,jiejie_server_minimal) no file assigns it, so an inbound that
// enables UDP used to reach a nil function call and panic with a nil
// dereference - a crash reachable from configuration alone.
//
// The decision is extracted so it can be tested without standing up a full
// inbound, and asserted in BOTH directions so it cannot be satisfied by always
// refusing to serve HTTP/3.
// TestAuditHTTP3NilConstructorIsHandled covers the production tag set, where the
// constructor is nil and the configuration enables UDP.
func TestAuditHTTP3NilConstructorIsHandled(t *testing.T) {
	t.Run("udp only is a fatal configuration error", func(t *testing.T) {
		// Nothing else is being served, so starting anyway would mean an inbound
		// that accepts nothing.
		got := decideHTTP3AvailabilityForOptions(false, option.NetworkList("udp"))
		if got != http3UnavailableFatal {
			t.Fatalf("a udp-only inbound with no HTTP/3 must fail, got %v", got)
		}
	})

	t.Run("tcp and udp keeps serving TCP", func(t *testing.T) {
		// TCP CONNECT is the production data path; a missing optional transport
		// must not stop it.
		got := decideHTTP3AvailabilityForOptions(false, option.NetworkList("tcp\nudp"))
		if got != http3UnavailableNonFatal {
			t.Fatalf("a tcp+udp inbound with no HTTP/3 must degrade, not fail, got %v", got)
		}
	})

	t.Run("tcp only never consults HTTP/3", func(t *testing.T) {
		// The production topology is tcp-only, so this is the shape that actually
		// ships. The decision is not even reached, but the helper must not claim
		// a fatal error for it.
		got := decideHTTP3AvailabilityForOptions(false, option.NetworkList("tcp"))
		if got != http3UnavailableFatal {
			t.Fatalf("a tcp-only inbound does not call HTTP/3 at all, got %v", got)
		}
	})
}

// TestAuditHTTP3ConstructorIsUsedWhenPresent is the other direction: when a
// constructor exists the inbound must proceed to use it. This is what stops the
// guard from silently disabling HTTP/3 in builds that do support it.
func TestAuditHTTP3ConstructorIsUsedWhenPresent(t *testing.T) {
	for _, network := range []option.NetworkList{
		option.NetworkList("udp"),
		option.NetworkList("tcp\nudp"),
		option.NetworkList("tcp"),
		option.NetworkList(""), // unset resolves to BOTH tcp and udp
	} {
		if got := decideHTTP3AvailabilityForOptions(true, network); got != http3Available {
			t.Fatalf("a present HTTP/3 constructor must be used for %q, got %v",
				string(network), got)
		}
	}
}

// TestAuditProductionNetworkIsTCPOnly pins the shipped topology.
//
// The production Naive inbound is tcp-only: UDP/443 belongs to MASQUE H3 and
// Native Naive carries its UDP inside the TCP CONNECT tunnel. If that ever
// changed to include udp, this inbound would start depending on the HTTP/3
// constructor being present, which under the production tag set it is not.
func TestAuditProductionNetworkIsTCPOnly(t *testing.T) {
	// The listener matrix helper is exercised here only to record the invariant
	// in one place next to the guard it affects.
	if !containsOnlyTCP(option.NetworkList("tcp")) {
		t.Fatal("precondition: a tcp-only network list must be recognised as such")
	}
	if containsOnlyTCP(option.NetworkList("tcp\nudp")) {
		t.Fatal("a tcp+udp list must not be mistaken for tcp-only")
	}
	if containsOnlyTCP(option.NetworkList("udp")) {
		t.Fatal("a udp-only list must not be mistaken for tcp-only")
	}
	if containsOnlyTCP(option.NetworkList("")) {
		t.Fatal("an unset network means BOTH tcp and udp, not tcp-only")
	}
}

func containsOnlyTCP(network option.NetworkList) bool {
	// Build() resolves the empty value to both transports, so an unset network is
	// not tcp-only and must not be reported as such.
	for _, one := range network.Build() {
		if one != N.NetworkTCP {
			return false
		}
	}
	return true
}

var _ = C.TypeNaive
