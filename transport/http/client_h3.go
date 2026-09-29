//go:build with_quic

package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

func init() {
	NewHTTP3Client = newHTTP3Client
}

type http3ClientImpl struct {
	dialer N.Dialer
	// connDialer, when set, replaces the UDP-dial + QUIC-handshake step. See
	// HTTP3ConnDialer. nil means dial directly, which is the previous behaviour.
	connDialer HTTP3ConnDialer
	tlsConfig  aTLS.Config
	server     M.Socksaddr
	authority  string
	// http3Authority is the authority this connection is authenticated for. It is what
	// the generic request path validates against; see Client.validateSameOrigin.
	http3Authority string
	headers        http.Header
	authorization  string
	quicConfig     *quic.Config
	// congestionControl is resolved once in newHTTP3Client. nil means "keep
	// quic-go's default sender", which is what an unset option selects.
	congestionControl func(conn *quic.Conn) congestion.CongestionControl
	transport         *http3.Transport
	access            sync.Mutex
	conn              *http3.ClientConn
	rawConn           net.Conn
}

func newHTTP3Client(options ClientOptions, authorization string) (http3Client, error) {
	if options.TLSConfig == nil {
		return nil, E.New("HTTP/3 requires TLS")
	}
	dialer := options.RawDialer
	if dialer == nil {
		dialer = N.SystemDialer
	}
	quicConfig := httpclient.NewQUICConfig(options.HTTP3Options)
	quicConfig.EnableDatagrams = true
	// Resolve the client congestion control ONCE, at construction, so an
	// unrecognised value is a configuration error reported at load rather than a
	// failure on the first packet. A nil result is the "leave quic-go's default"
	// case and is not an error: that is what an unset option means.
	congestionControl, err := httpclient.NewClientCongestionControl(options.HTTP3Options.CongestionControl)
	if err != nil {
		return nil, err
	}
	headers := options.Headers.Clone()
	authority := options.Server.String()
	if options.Authority != "" {
		authority = options.Authority
	}
	if headers != nil {
		if host := headers.Get("Host"); host != "" {
			authority = host
		}
		headers.Del("Host")
	}
	return &http3ClientImpl{
		dialer:            dialer,
		tlsConfig:         options.TLSConfig,
		server:            options.Server,
		authority:         authority,
		headers:           headers,
		authorization:     authorization,
		quicConfig:        quicConfig,
		congestionControl: congestionControl,
		connDialer:        options.HTTP3ConnDialer,
		transport:         &http3.Transport{EnableDatagrams: true, DisableCompression: true},
	}, nil
}

func (c *http3ClientImpl) acquire(ctx context.Context) (*http3.ClientConn, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.conn != nil && c.conn.Context().Err() == nil {
		return c.conn, nil
	}
	if c.rawConn != nil {
		c.rawConn.Close()
		c.rawConn = nil
	}
	// The dial happens INSIDE each branch, not before them.
	//
	// Dialing first and then asking the hook would create a UDP socket the hook path
	// never uses: it would be overwritten by the hook's return value and leak, because
	// nothing closes it. That is what the first version of this seam did, and the
	// regression test caught it by asserting that the client's own dialer is not called
	// when a hook is set.
	var (
		rawConn  net.Conn
		quicConn *quic.Conn
		err      error
	)
	if c.connDialer != nil {
		// The caller owns candidate selection and returns only a connection whose QUIC
		// handshake has COMPLETED, so this path's winner is the racer's winner. Every
		// step after this point is unchanged, which is what keeps the congestion-control
		// ordering and the memoization identical to the default path.
		rawConn, quicConn, err = c.connDialer(ctx, c.dialer, c.server, c.tlsConfig, c.quicConfig)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, E.Cause1(ErrHTTP3Unavailable, err)
		}
	} else {
		rawConn, err = c.dialer.DialContext(ctx, N.NetworkUDP, c.server)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, E.Cause1(ErrHTTP3Unavailable, err)
		}
		quicConn, err = qtls.DialEarly(ctx, rawConn, c.tlsConfig, c.quicConfig)
		if err != nil {
			rawConn.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, E.Cause1(ErrHTTP3Unavailable, err)
		}
	}
	// The congestion control must be installed on the conn BEFORE the HTTP/3
	// client conn starts using it. SetCongestionControl swaps the sender, so
	// applying it here - immediately after the handshake and before any stream is
	// opened - means not a single packet is sent under the default sender.
	httpclient.ApplyClientCongestionControl(quicConn, c.congestionControl)
	c.conn = c.transport.NewClientConn(quicConn)
	c.rawConn = rawConn
	return c.conn, nil
}

func (c *http3ClientImpl) openStream(ctx context.Context, request *http.Request) (*http3.RequestStream, *http3.ClientConn, error) {
	// The shared primitive does the connection acquisition, stream opening, request
	// sending, response reading and cleanup. What remains here is exactly the
	// CONNECT-specific part: a tunnel is only usable with StatusOK.
	//
	// Keeping the interpretation here rather than inside the primitive is deliberate. A
	// tunnel needs 200; an ordinary request accepts any status. Folding both into one
	// function would mean a mode flag, and the two paths would then be impossible to reason
	// about independently.
	stream, clientConn, response, err := c.openRequestStream(ctx, request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, E.Cause(err, "HTTP/3 CONNECT")
	}
	if response.StatusCode != http.StatusOK {
		stream.CancelRead(0)
		stream.Close()
		return nil, nil, statusError(response)
	}
	return stream, clientConn, nil
}

func (c *http3ClientImpl) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	stream, _, err := c.openStream(ctx, &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: destination.String()},
		Host:   destination.String(),
		Header: buildRequestHeader(c.headers, c.authorization, false),
	})
	if err != nil {
		return nil, err
	}
	return &http3StreamConn{stream: stream, remoteAddr: destination}, nil
}

func (c *http3ClientImpl) OpenTunnel(ctx context.Context, request tunnelRequest) (DatagramStream, error) {
	requestURL := *request.url
	requestURL.Scheme = "https"
	requestURL.Host = c.authority
	header := buildRequestHeader(c.headers, c.authorization, request.originAuthorization)
	header.Set("Capsule-Protocol", "?1")
	stream, clientConn, err := c.openStream(ctx, &http.Request{
		Method: http.MethodConnect,
		Proto:  request.protocol,
		URL:    &requestURL,
		Host:   c.authority,
		Header: header,
	})
	if err != nil {
		return nil, err
	}
	return &http3RequestDatagramStream{stream: stream, datagramsEnabled: clientConn.Settings().EnableDatagrams}, nil
}

func (c *http3ClientImpl) ResetConnection() {
	c.access.Lock()
	defer c.access.Unlock()
	if c.conn != nil {
		c.conn.CloseWithError(0, "")
		c.conn = nil
	}
	if c.rawConn != nil {
		c.rawConn.Close()
		c.rawConn = nil
	}
}

func (c *http3ClientImpl) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.conn != nil {
		c.conn.CloseWithError(0, "")
		c.conn = nil
	}
	if c.rawConn != nil {
		c.rawConn.Close()
		c.rawConn = nil
	}
	return c.transport.Close()
}

type http3StreamConn struct {
	stream      *http3.RequestStream
	remoteAddr  net.Addr
	writeAccess sync.Mutex
	closed      atomic.Bool
}

func (c *http3StreamConn) Read(p []byte) (int, error) {
	n, err := c.stream.Read(p)
	return n, c.wrapError(err)
}

func (c *http3StreamConn) Write(p []byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	n, err := c.stream.Write(p)
	return n, c.wrapError(err)
}

func (c *http3StreamConn) wrapError(err error) error {
	if err == nil {
		return nil
	}
	if c.closed.Load() {
		return net.ErrClosed
	}
	return qtls.WrapError(err)
}

func (c *http3StreamConn) CloseWrite() error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	return c.stream.Close()
}

func (c *http3StreamConn) Close() error {
	c.closed.Store(true)
	c.stream.SetWriteDeadline(time.Now())
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	c.stream.CancelRead(0)
	return c.stream.Close()
}

func (c *http3StreamConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *http3StreamConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http3StreamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *http3StreamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *http3StreamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func (c *http3StreamConn) NeedAdditionalReadDeadline() bool {
	return true
}

type http3RequestDatagramStream struct {
	stream           *http3.RequestStream
	datagramsEnabled bool
}

func (s *http3RequestDatagramStream) Read(p []byte) (int, error) {
	return s.stream.Read(p)
}

func (s *http3RequestDatagramStream) Write(p []byte) (int, error) {
	return s.stream.Write(p)
}

func (s *http3RequestDatagramStream) Close() error {
	s.stream.SetWriteDeadline(time.Now())
	s.stream.CancelRead(0)
	return s.stream.Close()
}

// DatagramsEnabled reports whether the peer negotiated HTTP Datagrams.
func (s *http3RequestDatagramStream) DatagramsEnabled() bool {
	return s.datagramsEnabled
}

func (s *http3RequestDatagramStream) SendDatagram(payload []byte) error {
	if !s.datagramsEnabled {
		return ErrDatagramUnsupported
	}
	err := s.stream.SendDatagram(payload)
	if err == nil {
		return nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return &DatagramTooLargeError{MaxPayloadSize: int(tooLarge.MaxDatagramPayloadSize) - VarintLen(uint64(s.stream.StreamID()/4))}
	}
	return err
}

func (s *http3RequestDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.stream.ReceiveDatagram(ctx)
}

var (
	_ net.Conn       = (*http3StreamConn)(nil)
	_ N.WriteCloser  = (*http3StreamConn)(nil)
	_ DatagramStream = (*http3RequestDatagramStream)(nil)
)
