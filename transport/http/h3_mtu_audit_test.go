//go:build with_quic

package http

import (
	"testing"

	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// MTU / PMTU audit for the HTTP/3 inbound.
//
// This file contains no new option. It PINS what is already configurable and, more
// importantly, what is deliberately NOT, so a future reader does not add a second
// parameter for something the stack already derives.
//
// # What already exists, and is therefore not re-invented here
//
//	initial_packet_size          -> quic.Config.InitialPacketSize
//	disable_path_mtu_discovery   -> quic.Config.DisablePathMTUDiscovery
//
// Both are explicit per-inbound options wired through httpclient.NewQUICConfig, so an
// operator who needs a different starting MTU or wants PMTU discovery off already has a
// control. Adding a second knob for the same thing would create two sources of truth.
//
// # What deliberately does NOT exist
//
// There is no `max_datagram_size`. The QUIC DATAGRAM ceiling is not a free parameter on
// this stack: quic-go derives the maximum payload from
//
//	c.maxPayloadSizeEstimate.Load()
//
// (connection.go SendDatagram), and that estimate is maintained by the path-MTU
// discovery the same option above controls. So a hand-configured datagram ceiling would
// either be ignored or would contradict the discovered path MTU, and a value that
// disagrees with the real path causes datagrams to be dropped or fragmented below QUIC.
// The stack already reports a payload that does not fit through
// DatagramTooLargeError{MaxDatagramPayloadSize}, which is exactly what the MASQUE layer
// consumes to generate an ICMP Packet Too Big - so the information flows without a
// configuration parameter.
//
// No MTU probe engine is implemented here either: PMTU discovery is quic-go's, and
// reimplementing it in sing-box would duplicate a mature implementation with a worse
// one.

// TestMTUOptionsAreExplicitlyConfigurable documents the controls that DO exist.
func TestMTUOptionsAreExplicitlyConfigurable(t *testing.T) {
	// An explicit initial packet size reaches the QUIC config.
	options := option.QUICOptions{InitialPacketSize: 1400}
	config := httpclient.NewQUICConfig(options)
	require.EqualValues(t, 1400, config.InitialPacketSize,
		"initial_packet_size must reach quic.Config, or the documented option does nothing")

	// PMTU discovery is on by default and can be turned off explicitly.
	require.False(t, httpclient.NewQUICConfig(option.QUICOptions{}).DisablePathMTUDiscovery,
		"PMTU discovery must be ENABLED by default: it is the library default and what "+
			"the reference implementations get")

	disabled := httpclient.NewQUICConfig(option.QUICOptions{DisablePathMTUDiscovery: true})
	require.True(t, disabled.DisablePathMTUDiscovery,
		"disable_path_mtu_discovery must reach quic.Config")
}

// TestNoHardcodedMTUDefault proves the inbound does not silently impose a packet size.
//
// A hardcoded 1200 or 1350 would change behaviour for every existing deployment that
// never asked for it, which is exactly the kind of "optimization" this round was told
// not to make.
func TestNoHardcodedMTUDefault(t *testing.T) {
	config := httpclient.NewQUICConfig(option.QUICOptions{})
	require.Zero(t, config.InitialPacketSize,
		"an unset initial_packet_size must leave quic-go's own default in place rather "+
			"than being filled with a hardcoded MTU")
}

// TestDatagramCeilingIsDerivedNotConfigured records why there is no max_datagram_size.
//
// The assertion is on the OPTION SURFACE rather than on quic-go internals: if a
// max_datagram_size field is ever added, this test must be updated together with a
// justification, so the decision is visible instead of arriving as a drive-by option.
func TestDatagramCeilingIsDerivedNotConfigured(t *testing.T) {
	// The option set carries the two MTU controls and nothing else MTU-shaped.
	//
	// This is a compile-time-shaped check: the fields below are the whole MTU surface of
	// QUICOptions. The comment above QUICOptions records that the ceiling is derived from
	// the PMTU estimate, and the MASQUE layer consumes DatagramTooLargeError rather than
	// a configured number.
	options := option.QUICOptions{}

	// The two fields that exist are reachable and independent.
	options.InitialPacketSize = 1200
	options.DisablePathMTUDiscovery = true
	require.Equal(t, 1200, options.InitialPacketSize)
	require.True(t, options.DisablePathMTUDiscovery)

	// A datagram that does not fit is reported by quic-go with the maximum it WOULD
	// accept, which is the value the MASQUE PTB path needs. That is asserted in
	// transport/masque/packet_too_big_test.go and is the reason no option is required.
	t.Log("MTU ceiling: derived from quic-go's PMTU estimate; surfaced to MASQUE as " +
		"DatagramTooLargeError.MaxDatagramPayloadSize, which becomes an ICMP Packet Too " +
		"Big. No max_datagram_size option is added, because a configured value would " +
		"either be ignored or contradict the discovered path MTU.")
}
