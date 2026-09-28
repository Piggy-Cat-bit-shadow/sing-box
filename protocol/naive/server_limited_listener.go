package naive

import (
	"net"
	"time"
)

// limitedListener enforces the connection-count limits at ACCEPT time.
//
// # Why accept time and not request time
//
// This is the whole point of the control. The lifecycle audit measured that a
// peer can complete the TLS handshake and then never send a request at all --
// measured open past 20s, with no header timeout. Such a peer never reaches
// ServeHTTP, so a limiter installed on the request path would never see it and
// would not count it. Counting at Accept is the only placement that covers the
// silent-peer case, which is the cheapest attack to mount.
//
// # Release ownership
//
// A slot is taken in Accept and released when the connection closes. The release
// is attached to the connection itself via limitedConn, so it happens exactly
// once no matter how the connection ends: a normal close, an error, a TLS
// failure during the handshake, or the server shutting down. Attaching it to the
// connection rather than to a request is what makes the accounting correct for
// connections that never carry a request.
//
// If no limits are configured the limiter is nil and this wrapper is not used at
// all, so an unconfigured inbound takes no locks on the accept path.
type limitedListener struct {
	net.Listener
	limiter *serverLimiter
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		release, admitted := l.limiter.acquire(conn.RemoteAddr().String(), time.Now())
		if !admitted {
			// Refused. Close immediately rather than accepting and then dropping:
			// the slot was never taken, so there is nothing to release, and
			// closing here keeps the refusal cheap and constant-time.
			_ = conn.Close()
			continue
		}
		return &limitedConn{Conn: conn, release: release}, nil
	}
}

// limitedConn releases its connection slot when it is closed.
//
// Release is tied to Close, not to Read/Write, so a connection that is accepted
// and then never used still releases its slot as soon as it is closed -- which is
// the case the limit exists to reclaim.
type limitedConn struct {
	net.Conn
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}
