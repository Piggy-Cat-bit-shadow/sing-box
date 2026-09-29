package masque

import (
	"context"
	"net"
	"net/netip"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
)

// testCandidateConnector builds a connectCandidateFunc that mimics the transport's own
// connector, for tests that drive the racer directly.
//
// The production connector lives in transport/http (see HTTP3CandidateConnector) and is handed
// to the racer per call. These tests need to supply one without a live HTTP client, so this
// helper performs the same three steps the transport does -- UDP dial, QUIC start -- over a
// caller-supplied dialer.
//
// It deliberately does NOT install congestion control: congestion-control ordering is the
// transport's responsibility and is asserted in transport/http, where the real connector is.
func testCandidateConnector(dialer N.Dialer, server M.Socksaddr, tlsConfig aTLS.Config, quicConfig *quic.Config) connectCandidateFunc {
	return func(ctx context.Context, address netip.Addr) (net.Conn, *quic.Conn, error) {
		rawConn, err := dialer.DialContext(ctx, N.NetworkUDP, M.SocksaddrFrom(address, server.Port))
		if err != nil {
			return nil, nil, err
		}
		quicConn, err := qtls.DialEarly(ctx, rawConn, tlsConfig, quicConfig)
		if err != nil {
			_ = rawConn.Close()
			return nil, nil, err
		}
		return rawConn, quicConn, nil
	}
}
