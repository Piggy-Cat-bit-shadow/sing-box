package anytls

import (
	"net"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/tls"
)

// firstReadTimeoutConn bounds ONLY the first application read after the TLS
// handshake, then gets out of the way completely.
//
// Why this exists: sing-anytls reads the AnyTLS prologue with a single
// ReadOnceFrom (see Service.handleConnection in sing-anytls). That read carries
// no deadline of its own. An attacker can therefore complete the TLS handshake
// and then send nothing at all -- neither an AnyTLS password nor an HTTP
// fallback payload -- and hold the file descriptor, the goroutine, the completed
// TLS state and the connection buffers open indefinitely. Repeated cheaply, that
// exhausts a 1 GiB host.
//
// The timeout reuses the existing pre-authentication budget C.TCPTimeout (15s)
// rather than adding another configuration knob: "how long may an
// unauthenticated peer stay silent" is exactly the question that constant
// already answers elsewhere in this codebase.
//
// The deadline is ONE-SHOT and is cleared as soon as application data arrives,
// so a legitimate AnyTLS session -- and a legitimate slow tunnel -- is never
// affected past its first byte. The fallback path benefits too: fallback only
// receives this connection after the first read has already succeeded, by which
// point the deadline is cleared, so a slow fallback backend is unaffected.
//
// The wrapper deliberately PRESERVES the tls.Conn interface. protocol/anytls's
// fallbackConnection reads ConnectionState().NegotiatedProtocol off the
// connection to route fallback_for_alpn; hiding the tls.Conn behind a bare
// net.Conn silently broke that routing and sent every client to the default
// backend. Embedding the original connection interface keeps the type
// assertion working, and common.Cast[tls.Conn] additionally unwraps through
// NetConn().
// firstReadTimeoutConn is the TLS-preserving flavour. It embeds tls.Conn so the
// fallback path's type assertion keeps working.
type firstReadTimeoutConn struct {
	tls.Conn

	// accessed guards the one-shot state. Read and the clear path can be called
	// from different goroutines (the handler goroutine and onClose), so the
	// state is synchronized rather than assumed single-threaded.
	accessed sync.Mutex
	// pending is true until the first application byte has been observed.
	pending bool
}

// newFirstReadTimeoutConn arms a one-shot read deadline on conn. The deadline is
// installed immediately, because the first Read may happen before the caller has
// a chance to do anything else. A non-positive timeout returns conn untouched.
func newFirstReadTimeoutConn(conn net.Conn, timeout time.Duration) net.Conn {
	if timeout <= 0 {
		return conn
	}
	// Only a connection that actually went through sing-box's TLS layer is
	// wrapped: that is the one sing-anytls reads the unauthenticated prologue
	// from, and it is the one whose TLS interface must survive wrapping.
	if tlsConn, isTLS := conn.(tls.Conn); isTLS {
		return newFirstReadTimeoutTLSConn(tlsConn, timeout)
	}
	return conn
}

// Read passes through to the wrapped connection, clearing the one-shot deadline
// as soon as any application byte is seen.
//
// The clear happens when n > 0 EVEN IF err != nil: a partial read with an error
// still proves the peer sent application data, so that peer must not be punished
// with the pre-authentication timeout afterwards.
func (c *firstReadTimeoutConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.clearDeadlineOnce()
	}
	return n, err
}

// clearDeadlineOnce removes the read deadline at most once. A failure to clear
// it is not fatal (the peer already sent data), so the error is ignored.
func (c *firstReadTimeoutConn) clearDeadlineOnce() {
	c.accessed.Lock()
	defer c.accessed.Unlock()
	if !c.pending {
		return
	}
	c.pending = false
	_ = c.Conn.SetReadDeadline(time.Time{})
}

// firstReadDeadlineArmed reports whether the one-shot deadline is still pending.
// It exists for tests.
func (c *firstReadTimeoutConn) firstReadDeadlineArmed() bool {
	c.accessed.Lock()
	defer c.accessed.Unlock()
	return c.pending
}

// defaultPreAuthTimeout is the pre-authentication budget used by the inbound. It
// is C.TCPTimeout so this fix introduces no new tunable.
func defaultPreAuthTimeout() time.Duration {
	return C.TCPTimeout
}

// newFirstReadTimeoutTLSConn is the tls.Conn flavour, used for the connection a
// TLS handshake produced. Keeping the TLS interface is required: fallback_for_alpn
// routing type-asserts the connection to tls.Conn.
func newFirstReadTimeoutTLSConn(conn tls.Conn, timeout time.Duration) tls.Conn {
	if timeout <= 0 {
		return conn
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return conn
	}
	return &firstReadTimeoutConn{
		Conn:    conn,
		pending: true,
	}
}

// compile-time proof that each wrapper still satisfies the interfaces the
// fallback path relies on.
var (
	_ net.Conn = (*firstReadTimeoutConn)(nil)
	// The TLS interface must survive wrapping, because fallback_for_alpn routing
	// type-asserts the connection to tls.Conn.
	_ tls.Conn = (*firstReadTimeoutConn)(nil)
)
