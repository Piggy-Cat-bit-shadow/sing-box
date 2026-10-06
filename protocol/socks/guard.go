package socks

import (
	"io"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// errEmptyDomain is the malformed-address rejection.
//
// It exists because a zero-length SOCKS5 domain desynchronises the stream rather
// than failing cleanly. sing's address serializer does not read the port field
// when the decoded address is not valid (common/metadata/serializer.go,
// ReadAddrPort), so after a zero-length ATYP=domain address the two port bytes
// are left in the stream and every byte after them is shifted by two. Whatever
// the parser then calls the tunnel payload begins two bytes early.
//
// Rejecting at this boundary is the narrow fix: it does not change the shared
// serializer contract, which other protocols and other address families rely on.
var errEmptyDomain = E.New("socks5: empty domain name in request address")

// GuardSOCKS5Address wraps conn so that a SOCKS5 request carrying a zero-length
// domain name fails the read that would deliver it, instead of desynchronising
// the stream.
//
// # Why the guard is on the connection
//
// SOCKS5 negotiation is a round trip: the client sends its greeting, WAITS for
// the method selection, and only then sends the request. At the moment the
// inbound could inspect the stream, the request does not exist yet -- and the
// inbound cannot have replied, because its handshake has not run. So there is no
// point at which a check can look at the request and still be non-blocking:
//
//   - bufio.Reader.Peek reports "nothing buffered" by READING, so peeking for a
//     request that has not arrived blocks the connection before a single byte is
//     written back. An early revision of this work did exactly that and
//     deadlocked curl;
//   - the buffer is also only filled lazily, so a check that inspects
//     reader.Buffered() sees zero on the first call and would silently decide
//     nothing.
//
// The bytes do pass through one place the caller owns, though: the connection
// the handshake reads from. A guard here sees every byte as it is read, so it
// never has to wait for anything and it cannot miss the request no matter how
// the client fragments it or when it chooses to send it.
//
// # Cost
//
// One comparison per byte until the address type is known, and nothing at all
// afterwards -- the guard stops looking once it has passed the address length.
// It does not copy, does not buffer and does not allocate.
//
// # The malformed read is DISCARDED
//
// The read that delivers the offending length byte reports the error and
// reports zero bytes delivered. Returning the bytes alongside the error would
// not be enough: bufio.Reader has no seam to notice a per-read error, so it
// would hand them to the parser, the parser would misread the address, and the
// connection would already have been routed by the time the error surfaced. The
// malformed request is not useful data, so discarding it costs nothing.
func GuardSOCKS5Address(conn net.Conn) net.Conn {
	return &addressGuard{forwardedConn: forwardedConn{Conn: conn}}
}

type addressGuard struct {
	forwardedConn
	// state is advanced one byte per Read. It stops at stateDone.
	state uint8
	// pending counts the bytes still expected in the field being read.
	pending int
	err     error
}

// Guard states.
const (
	stateVersion uint8 = iota
	stateMethodCount
	stateMethods
	// stateNext is the byte after the method list: the RFC 1929 sub-negotiation
	// version (0x01) when the server selected that method, or the request
	// version (0x05) when it did not.
	stateNext
	stateAuthUsernameLength
	stateAuthUsername
	stateAuthPasswordLength
	stateAuthPassword
	stateRequestVersion
	stateRequestCommand
	stateRequestReserved
	stateRequestAddressType
	// stateRequestAddressLength is the decision point for ATYP=domain.
	stateRequestAddressLength
	stateDone
)

const (
	usernamePasswordVersion byte = 0x01
	addressTypeDomain       byte = 0x03
)

func (g *addressGuard) Read(p []byte) (int, error) {
	if g.err != nil {
		return 0, g.err
	}
	n, err := g.Conn.Read(p)
	for _, b := range p[:n] {
		if scanErr := g.advance(b); scanErr != nil {
			g.err = scanErr
			return 0, scanErr
		}
	}
	return n, err
}

// advance moves the scanner one byte forward and reports a malformed address.
func (g *addressGuard) advance(b byte) error {
	switch g.state {
	case stateVersion:
		if b != 0x05 {
			// Not SOCKS5; correctness for every other version is the parser's.
			g.state = stateDone
			return nil
		}
		g.state = stateMethodCount
	case stateMethodCount:
		g.pending = int(b)
		if g.pending == 0 {
			g.state = stateDone
			return nil
		}
		g.state = stateMethods
	case stateMethods:
		g.pending--
		if g.pending == 0 {
			g.state = stateNext
		}
	case stateNext:
		if b == usernamePasswordVersion {
			g.state = stateAuthUsernameLength
			return nil
		}
		// No sub-negotiation: this byte is the request version.
		g.state = stateRequestCommand
	case stateAuthUsernameLength:
		g.pending = int(b)
		g.state = stateAuthUsername
	case stateAuthUsername:
		g.pending--
		if g.pending <= 0 {
			g.state = stateAuthPasswordLength
		}
	case stateAuthPasswordLength:
		g.pending = int(b)
		g.state = stateAuthPassword
	case stateAuthPassword:
		g.pending--
		if g.pending <= 0 {
			g.state = stateRequestVersion
		}
	case stateRequestVersion:
		if b != 0x05 {
			g.state = stateDone
			return nil
		}
		g.state = stateRequestCommand
	case stateRequestCommand:
		g.state = stateRequestReserved
	case stateRequestReserved:
		g.state = stateRequestAddressType
	case stateRequestAddressType:
		if b != addressTypeDomain {
			// Only a domain name carries a length byte, so only a domain name can
			// be empty. Every other address family is the parser's business.
			g.state = stateDone
			return nil
		}
		g.state = stateRequestAddressLength
	case stateRequestAddressLength:
		g.state = stateDone
		if b == 0 {
			return errEmptyDomain
		}
	}
	return nil
}

// forwardedConn is embedded by wrappers that add no capability of their own, so
// that every optional interface the transport offers stays reachable by a type
// assertion instead of being silently hidden behind a bare net.Conn.
//
// It is the difference between "one more wrapper" and "the shared core's
// splice and zero-copy paths are switched off": the routing layer probes for
// syscall.Conn, io.ReaderFrom, io.WriterTo and half-close, and a wrapper that
// answers none of them costs more than it saves.
type forwardedConn struct {
	net.Conn
}

func (c *forwardedConn) ReadFrom(r io.Reader) (int64, error) {
	if readerFrom, isReaderFrom := c.Conn.(io.ReaderFrom); isReaderFrom {
		return readerFrom.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{c.Conn}, r)
}

func (c *forwardedConn) WriteTo(w io.Writer) (int64, error) {
	if writerTo, isWriterTo := c.Conn.(io.WriterTo); isWriterTo {
		return writerTo.WriteTo(w)
	}
	return io.Copy(w, struct{ io.Reader }{c.Conn})
}

func (c *forwardedConn) CloseRead() error {
	if closer, isCloser := c.Conn.(interface{ CloseRead() error }); isCloser {
		return closer.CloseRead()
	}
	return nil
}

func (c *forwardedConn) CloseWrite() error {
	if closer, isCloser := c.Conn.(interface{ CloseWrite() error }); isCloser {
		return closer.CloseWrite()
	}
	return nil
}

func (c *forwardedConn) ReaderReplaceable() bool {
	replaceable, isReplaceable := c.Conn.(N.ReaderWithUpstream)
	return isReplaceable && replaceable.ReaderReplaceable()
}

func (c *forwardedConn) WriterReplaceable() bool {
	replaceable, isReplaceable := c.Conn.(N.WriterWithUpstream)
	return isReplaceable && replaceable.WriterReplaceable()
}

func (c *forwardedConn) Upstream() any {
	return c.Conn
}
