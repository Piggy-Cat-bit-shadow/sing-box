package socks

import (
	"context"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// relayDialer normalises the relay address a SOCKS5 server hands back in a UDP ASSOCIATE reply.
//
// # The failure it prevents
//
// After a successful UDP ASSOCIATE the client dials the relay at whatever BND.ADDR the server
// sent. Public proxies commonly answer with "0.0.0.0" or "::" meaning "any address of mine", and
// in the SOCKS5 RFC that is a legal value. Go does not read it that way: an unspecified literal
// is treated as the LOCAL SYSTEM, so every datagram is sent to 127.0.0.1 (or [::1]), where
// nothing is listening. The symptom is the worst kind - TCP through the same proxy works, UDP
// silently does not, and no error is ever produced.
//
// The relay therefore dials the address the operator configured for the server, with the port
// the server chose, whenever BND.ADDR is unspecified or empty. A concrete BND.ADDR is used as
// sent: the server is entitled to name a specific relay address, and a private or loopback
// address it names is a decision to honour, not to second-guess.
//
// Only packet dials are rewritten. TCP dials pass through untouched, so the CONNECT path and the
// control connection are unaffected.
type relayDialer struct {
	dialer     N.Dialer
	serverAddr M.Socksaddr
}

var _ N.Dialer = (*relayDialer)(nil)

func newRelayDialer(dialer N.Dialer, serverAddr M.Socksaddr) *relayDialer {
	return &relayDialer{dialer: dialer, serverAddr: serverAddr}
}

func (d *relayDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkUDP {
		return d.dialer.DialContext(ctx, network, destination)
	}
	relayAddress, err := d.relayAddress(destination)
	if err != nil {
		return nil, err
	}
	return d.dialer.DialContext(ctx, network, relayAddress)
}

func (d *relayDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.dialer.ListenPacket(ctx, destination)
}

// Upstream exposes the wrapped dialer so the route layer's capability casts reach through the
// wrapper rather than stopping at it.
func (d *relayDialer) Upstream() any {
	return d.dialer
}

// relayAddress resolves the address the UDP relay must actually be dialled at.
func (d *relayDialer) relayAddress(bind M.Socksaddr) (M.Socksaddr, error) {
	if bind.Port == 0 {
		// Port zero names no relay; dialling it would produce a confusing failure far from the
		// protocol error that caused it.
		return M.Socksaddr{}, E.New("socks5: server returned an unusable UDP relay port in UDP ASSOCIATE: ", bind.String())
	}
	bind = bind.Unwrap()
	if bind.Addr.IsValid() && !bind.Addr.IsUnspecified() {
		return bind, nil
	}
	// Unspecified or absent host: the server did not name one, so it means itself.
	serverAddr := d.serverAddr.Unwrap()
	return M.Socksaddr{Addr: serverAddr.Addr, Fqdn: serverAddr.Fqdn, Port: bind.Port}, nil
}
