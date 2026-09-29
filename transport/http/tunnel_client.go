package http

import (
	std_bufio "bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TunnelTransport identifies the protocol a CONNECT-IP tunnel was actually established over.
//
// # Why this is reported rather than inferred
//
// A caller can already ask whether this client is CAPABLE of HTTP/3 and whether it currently
// HOLDS a live HTTP/3 connection, and neither answers the question that matters to MASQUE DNS:
// was THIS tunnel session established over HTTP/3?
//
// They differ because the tunnel path falls back. An HTTP/3 attempt can fail and the session be
// established over HTTP/2, while a perfectly live HTTP/3 connection object remains in place from
// an earlier success. Inferring "the tunnel is HTTP/3" from that object would be wrong, and the
// consequence is specific: a DNS query would be sent as a request stream on an HTTP/3 connection
// that the tunnel traffic does NOT share, which is exactly what draft-ietf-masque-connect-ip-dns-06
// §3.5's coalescing requirement exists to prevent.
//
// So the fact is recorded where it is decided -- at the branch that successfully opened the
// tunnel -- and reported to the caller.
type TunnelTransport uint8

const (
	// TunnelTransportUnknown means no tunnel has been established.
	TunnelTransportUnknown TunnelTransport = iota
	TunnelTransportHTTP1
	TunnelTransportHTTP2
	TunnelTransportHTTP3
)

// String renders a transport for diagnostics.
func (t TunnelTransport) String() string {
	switch t {
	case TunnelTransportHTTP1:
		return "h1"
	case TunnelTransportHTTP2:
		return "h2"
	case TunnelTransportHTTP3:
		return "h3"
	default:
		return "unknown"
	}
}

type tunnelRequest struct {
	protocol            string
	url                 *url.URL
	destination         M.Socksaddr
	originAuthorization bool
}

func (c *Client) OpenTunnel(ctx context.Context, protocol string, path string) (io.ReadWriteCloser, error) {
	stream, _, err := c.OpenTunnelWithInfo(ctx, protocol, path)
	return stream, err
}

// OpenTunnelWithInfo opens a CONNECT-IP tunnel and reports the protocol it was established over.
//
// OpenTunnel remains as a wrapper, so existing callers are unaffected.
func (c *Client) OpenTunnelWithInfo(ctx context.Context, protocol string, path string) (io.ReadWriteCloser, TunnelTransport, error) {
	requestURL, err := url.ParseRequestURI(path)
	if err != nil {
		return nil, TunnelTransportUnknown, E.Cause(err, "parse tunnel path")
	}
	conn, stream, transport, err := c.openTunnel(ctx, tunnelRequest{
		protocol:            protocol,
		url:                 &url.URL{Path: requestURL.Path, RawPath: requestURL.RawPath, RawQuery: requestURL.RawQuery},
		destination:         c.server,
		originAuthorization: true,
	})
	if err != nil {
		return nil, TunnelTransportUnknown, err
	}
	if stream != nil {
		return stream, transport, nil
	}
	return conn, transport, nil
}

// openTunnel returns the transport each successful branch used, so the caller never has to
// infer it from which connection objects happen to exist.
func (c *Client) openTunnel(ctx context.Context, request tunnelRequest) (net.Conn, DatagramStream, TunnelTransport, error) {
	if c.http3Available() {
		stream, err := c.http3.OpenTunnel(ctx, request)
		if err == nil {
			c.clearHTTP3Broken()
			return nil, stream, TunnelTransportHTTP3, nil
		}
		if c.disableVersionFallback || !errors.Is(err, ErrHTTP3Unavailable) {
			return nil, nil, TunnelTransportUnknown, err
		}
		c.markHTTP3Broken()
	}
	if !extendedConnectAvailable && c.tlsDialer != nil && c.disableVersionFallback {
		return nil, nil, TunnelTransportUnknown, errExtendedConnectUnavailable
	}
	if extendedConnectAvailable && c.tlsDialer != nil && !c.http2Unsupported.Load() && !c.http2ExtendedConnectUnsupported.Load() {
		clientConn, conn, err := c.acquireHTTP2(ctx)
		if err != nil {
			return nil, nil, TunnelTransportUnknown, err
		}
		if clientConn != nil {
			streamConn, connectErr := c.openTunnelHTTP2(ctx, clientConn, request)
			if connectErr == nil {
				return streamConn, nil, TunnelTransportHTTP2, nil
			}
			if !errors.Is(connectErr, errExtendedConnectUnsupported) || c.disableVersionFallback {
				return nil, nil, TunnelTransportUnknown, connectErr
			}
			c.http2ExtendedConnectUnsupported.Store(true)
		} else if c.disableVersionFallback {
			conn.Close()
			return nil, nil, TunnelTransportUnknown, ErrHTTP2Unsupported
		} else {
			tunnelConn, _, http1Err := c.openTunnelHTTP1AndClose(ctx, conn, request)
			return tunnelConn, nil, TunnelTransportHTTP1, http1Err
		}
	}
	conn, err := c.http1Dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, nil, TunnelTransportUnknown, err
	}
	tunnelConn, _, http1Err := c.openTunnelHTTP1AndClose(ctx, conn, request)
	return tunnelConn, nil, TunnelTransportHTTP1, http1Err
}

func (c *Client) openTunnelHTTP1AndClose(ctx context.Context, conn net.Conn, request tunnelRequest) (net.Conn, DatagramStream, error) {
	tunnelConn, err := c.openTunnelHTTP1(ctx, conn, request)
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, err
	}
	return tunnelConn, nil, nil
}

func (c *Client) openTunnelHTTP1(ctx context.Context, conn net.Conn, request tunnelRequest) (net.Conn, error) {
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
	})
	defer stop()
	httpRequest := &http.Request{
		Method: http.MethodGet,
		URL:    request.url,
		Host:   c.authority(),
		Header: buildRequestHeader(c.headers, c.authorization, request.originAuthorization),
	}
	httpRequest.Header.Set("Connection", "Upgrade")
	httpRequest.Header.Set("Upgrade", request.protocol)
	httpRequest.Header.Set("Capsule-Protocol", "?1")
	err := httpRequest.Write(conn)
	if err != nil {
		return nil, E.Cause(err, "write request")
	}
	reader := std_bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, httpRequest)
	if err != nil {
		return nil, E.Cause(err, "read response")
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		return nil, statusError(response)
	}
	if !strings.EqualFold(response.Header.Get("Upgrade"), request.protocol) {
		return nil, E.New("unexpected upgrade protocol: ", response.Header.Get("Upgrade"))
	}
	if !stop() {
		return nil, ctx.Err()
	}
	if reader.Buffered() > 0 {
		buffer := buf.NewSize(reader.Buffered())
		_, err = buffer.ReadFullFrom(reader, buffer.FreeLen())
		if err != nil {
			buffer.Release()
			return nil, err
		}
		return bufio.NewCachedConn(conn, buffer), nil
	}
	return conn, nil
}

func (c *Client) openTunnelHTTP2(ctx context.Context, clientConn *http2ClientConn, request tunnelRequest) (net.Conn, error) {
	requestURL := *request.url
	requestURL.Scheme = "https"
	requestURL.Host = c.authority()
	httpRequest := &http.Request{
		Method: http.MethodConnect,
		URL:    &requestURL,
		Host:   c.authority(),
		Header: buildRequestHeader(c.headers, c.authorization, request.originAuthorization),
	}
	httpRequest.Header.Set(":protocol", request.protocol)
	httpRequest.Header.Set("Capsule-Protocol", "?1")
	streamConn, err := c.roundTripHTTP2(ctx, clientConn, httpRequest, request.destination)
	if err != nil {
		return nil, err
	}
	return streamConn, nil
}

func (c *Client) authority() string {
	if c.host != "" {
		return c.host
	}
	if c.authorityOverride != "" {
		return c.authorityOverride
	}
	return c.server.String()
}
