package urltest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests for the address family of a measurement destination.
//
// # The defect these pin
//
// The destination was built as
//
//	M.Socksaddr{Fqdn: hostname, Port: ...}
//
// for every spelling, so `http://127.0.0.1/...` produced a DOMAIN destination whose name happens to
// look like an address.
//
// # Why the distinction is real on the wire
//
// Socksaddr encodes an address in one of three ways, and the proxy protocols carry that choice:
// ATYP IPv4, ATYP IPv6, or ATYP DOMAIN. Filling Fqdn for a numeric literal therefore asks the
// remote end to resolve "1.1.1.1" as a DOMAIN, which is a different operation from connecting to the
// address the operator wrote. It can re-enter a resolver, choose a different address family, or be
// rejected outright - and an IPv6 literal has to survive as a literal rather than as a bracketed
// name.
//
// Comparing String() would not catch this: a DOMAIN "127.0.0.1" and an IPv4 127.0.0.1 render
// identically, so the assertions below inspect the address fields.

// TestIPv4TargetProducesIPDestination is §9.1.
func TestIPv4TargetProducesIPDestination(t *testing.T) {
	target, err := ParseMeasurementTarget("http://127.0.0.1:8080/a")
	require.NoError(t, err)

	require.True(t, target.Destination.IsIP(),
		"an IPv4 literal must produce an IP destination, not a DOMAIN whose text looks numeric: "+
			"the proxy protocol encodes the difference, and a DOMAIN asks the remote end to "+
			"resolve a literal the operator already resolved")
	require.True(t, target.Destination.IsIPv4(), "and specifically an IPv4 one")
	require.False(t, target.Destination.IsFqdn())
	require.EqualValues(t, 8080, target.Destination.Port)
}

// TestIPv6TargetProducesIPDestination is §9.1.
func TestIPv6TargetProducesIPDestination(t *testing.T) {
	target, err := ParseMeasurementTarget("http://[::1]:8080/a")
	require.NoError(t, err)

	require.True(t, target.Destination.IsIP())
	require.True(t, target.Destination.IsIPv6(), "an IPv6 literal must survive as IPv6")
	require.False(t, target.Destination.IsFqdn())
	require.EqualValues(t, 8080, target.Destination.Port)

	// A full-form literal must also be recognised.
	full, err := ParseMeasurementTarget("https://[2001:db8::1]/a")
	require.NoError(t, err)
	require.True(t, full.Destination.IsIPv6())
}

// TestDomainTargetProducesDomainDestination is §9.1.
func TestDomainTargetProducesDomainDestination(t *testing.T) {
	target, err := ParseMeasurementTarget("https://example.com:8080/a")
	require.NoError(t, err)

	require.True(t, target.Destination.IsFqdn(),
		"a real hostname must remain a domain so the proxy resolves it, which is what makes it "+
			"reachable through a resolver the client cannot see")
	require.False(t, target.Destination.IsIP())
	require.EqualValues(t, 8080, target.Destination.Port)
}

// TestDestinationFamilyAcrossSpellings is a table over the shapes a configuration uses.
func TestDestinationFamilyAcrossSpellings(t *testing.T) {
	for _, testCase := range []struct {
		link     string
		isIP     bool
		isIPv4   bool
		isIPv6   bool
		isDomain bool
	}{
		{"http://1.1.1.1/", true, true, false, false},
		{"http://1.1.1.1:80/", true, true, false, false},
		{"https://8.8.8.8/x", true, true, false, false},
		{"http://[::1]/", true, false, true, false},
		{"http://[2001:db8::1]:8080/", true, false, true, false},
		{"http://example.com/", false, false, false, true},
		{"http://sub.example.com:8080/", false, false, false, true},
		{"http://192.0.2.1.example.com/", false, false, false, true},
	} {
		t.Run(testCase.link, func(t *testing.T) {
			target, err := ParseMeasurementTarget(testCase.link)
			require.NoError(t, err)

			destination := target.Destination
			require.Equal(t, testCase.isIP, destination.IsIP(), "IsIP")
			require.Equal(t, testCase.isIPv4, destination.IsIPv4(), "IsIPv4")
			require.Equal(t, testCase.isIPv6, destination.IsIPv6(), "IsIPv6")
			require.Equal(t, testCase.isDomain, destination.IsFqdn(), "IsFqdn")
		})
	}
}
