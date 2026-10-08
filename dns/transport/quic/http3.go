package quic

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

var (
	_ adapter.DNSTransport         = (*HTTP3Transport)(nil)
	_ adapter.IdleConnectionKeeper = (*HTTP3Transport)(nil)
)

func RegisterHTTP3Transport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteHTTPSDNSServerOptions](registry, C.DNSTypeHTTP3, NewHTTP3)
}

type HTTP3Transport struct {
	dns.TransportAdapter
	logger          logger.ContextLogger
	dialer          N.Dialer
	destination     *url.URL
	headers         http.Header
	serverAddr      M.Socksaddr
	tlsConfig       *tls.STDConfig
	keepIdle        atomic.Bool
	transportAccess sync.Mutex
	transport       *http3.Transport
}

func NewHTTP3(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteHTTPSDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewRemoteDialer(ctx, options.RemoteDNSServerOptions)
	if err != nil {
		return nil, err
	}
	tlsOptions := common.PtrValueOrDefault(options.TLS)
	tlsOptions.Enabled = true
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, tlsOptions)
	if err != nil {
		return nil, err
	}
	stdConfig, err := tlsConfig.STDConfig()
	if err != nil {
		return nil, err
	}
	headers := options.Headers.Build()
	host := headers.Get("Host")
	if host != "" {
		headers.Del("Host")
	} else {
		if tlsConfig.ServerName() != "" {
			host = tlsConfig.ServerName()
		} else {
			host = options.Server
		}
	}
	destinationURL := url.URL{
		Scheme: "https",
		Host:   host,
	}
	if destinationURL.Host == "" {
		destinationURL.Host = options.Server
	}
	if options.ServerPort != 0 && options.ServerPort != 443 {
		destinationURL.Host = net.JoinHostPort(destinationURL.Host, strconv.Itoa(int(options.ServerPort)))
	}
	path := options.Path
	if path == "" {
		path = "/dns-query"
	}
	err = badhttp.URLSetPath(&destinationURL, path)
	if err != nil {
		return nil, err
	}
	serverAddr := options.DNSServerAddressOptions.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = 443
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}
	t := &HTTP3Transport{
		TransportAdapter: dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeHTTP3, tag, options.RemoteDNSServerOptions),
		logger:           logger,
		dialer:           transportDialer,
		destination:      &destinationURL,
		headers:          headers,
		serverAddr:       serverAddr,
		tlsConfig:        stdConfig,
	}
	t.transport = t.newTransport()
	t.keepIdle.Store(true)
	return t, nil
}

func (t *HTTP3Transport) newTransport() *http3.Transport {
	return &http3.Transport{
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.STDConfig, cfg *quic.Config) (*quic.Conn, error) {
			conn, dialErr := t.dialer.DialContext(ctx, N.NetworkUDP, t.serverAddr)
			if dialErr != nil {
				return nil, dialErr
			}
			quicConn, dialErr := quic.DialEarlyConn(ctx, conn, tlsCfg, cfg)
			if dialErr != nil {
				conn.Close()
				return nil, dialErr
			}
			// quic-go does not take ownership of the packet conn passed to
			// DialEarly: when the connection ends it only stops reading.
			go func() {
				<-quicConn.Context().Done()
				conn.Close()
			}()
			return quicConn, nil
		},
		TLSClientConfig: t.tlsConfig,
	}
}

func (t *HTTP3Transport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(func() error {
		t.transportAccess.Lock()
		defer t.transportAccess.Unlock()
		return t.transport.Close()
	})
	return dialer.InitializeDetour(t.dialer)
}

func (t *HTTP3Transport) Reset() {
	t.transportAccess.Lock()
	defer t.transportAccess.Unlock()
	t.transport.Close()
	t.transport = t.newTransport()
}

// CloseIdleConnections releases HTTP/3 connections that have no request in flight and keeps the
// current *http3.Transport.
//
// # Why the transport is not replaced
//
// Reset closes the *http3.Transport and builds a new one, which is the network-change operation:
// the next Exchange pays a fresh QUIC handshake and every client the old transport had pooled is
// discarded. A trim must not do that. The failure it would create is the one
// common/httpclient/managed_transport.go pins: the trim releases an idle connection and then the
// very next request rebuilds the transport and dials again, so the memory pass ends larger and
// busier than it started.
//
// http3.Transport.CloseIdleConnections takes the transport's own mutex and closes a client conn
// only when its useCount is zero. useCount is incremented under that same mutex in getClient and
// released when RoundTrip returns, so a request that is still waiting for its response headers
// cannot be closed here, and the still-valid state on the transport - the clients that are in use,
// the dial function, the closed flag - is retained for an unchanged network.
//
// The window http3 calls "in use" ends when RoundTrip returns, which is just before this transport
// has read the response body; a trim landing in that gap can abort that one query's body read. That
// is the library's own definition of idle and it is used rather than a private counter, because
// the alternative - holding transportAccess across the whole exchange - would serialize every DoH3
// query behind the trim. A DNS exchange already fails over on error, so the cost of that gap is a
// retry rather than a stall, and nothing dials as a result of the trim itself.
func (t *HTTP3Transport) CloseIdleConnections() {
	t.transportAccess.Lock()
	defer t.transportAccess.Unlock()
	t.transport.CloseIdleConnections()
}

// SetKeepIdleConnections disables retention, not just the connections idle at this instant: a
// later request must not release its connection back into a pool the caller asked to drain. The
// post-exchange sweep in Exchange is the half that enforces that, matching HTTPSTransport.
func (t *HTTP3Transport) SetKeepIdleConnections(keep bool) {
	t.keepIdle.Store(keep)
	if !keep {
		t.CloseIdleConnections()
	}
}

func (t *HTTP3Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	response, err := t.exchange(ctx, message)
	if t.keepIdle.Load() {
		return response, err
	}
	// Retention was turned off, so this query must not leave its connection pooled - and it must
	// also release anything an earlier query parked before the flag was flipped.
	t.CloseIdleConnections()
	return response, err
}

func (t *HTTP3Transport) exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	exMessage := *message
	exMessage.Id = 0
	exMessage.Compress = true
	requestBuffer := buf.NewSize(1 + message.Len())
	rawMessage, err := exMessage.PackBuffer(requestBuffer.FreeBytes())
	if err != nil {
		requestBuffer.Release()
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.destination.String(), bytes.NewReader(rawMessage))
	if err != nil {
		requestBuffer.Release()
		return nil, err
	}
	request.Header = t.headers.Clone()
	request.Header.Set("Content-Type", transport.MimeType)
	request.Header.Set("Accept", transport.MimeType)
	t.transportAccess.Lock()
	currentTransport := t.transport
	t.transportAccess.Unlock()
	response, err := currentTransport.RoundTrip(request)
	requestBuffer.Release()
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, E.New("unexpected status: ", response.Status)
	}
	var responseMessage mDNS.Msg
	if response.ContentLength > 0 {
		responseBuffer := buf.NewSize(int(response.ContentLength))
		defer responseBuffer.Release()
		_, err = responseBuffer.ReadFullFrom(response.Body, int(response.ContentLength))
		if err != nil {
			return nil, err
		}
		err = responseMessage.Unpack(responseBuffer.Bytes())
	} else {
		rawMessage, err = io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		err = responseMessage.Unpack(rawMessage)
	}
	if err != nil {
		return nil, err
	}
	return &responseMessage, nil
}

func (t *HTTP3Transport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}
