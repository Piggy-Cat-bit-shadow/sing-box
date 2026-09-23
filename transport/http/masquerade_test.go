package http

import (
	"context"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type discardHandler struct{}

func (discardHandler) NewConnectionEx(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}
func (discardHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}

func TestHTTP2MasqueradeOnAuthenticationFailure(t *testing.T) {
	masquerade, err := NewMasqueradeHandler(context.Background(), &option.Hysteria2Masquerade{
		Type: "string",
		StringOptions: option.Hysteria2MasqueradeString{
			StatusCode: stdhttp.StatusTeapot,
			Headers:    badoption.HTTPHeader{"Content-Type": {"text/plain"}},
			Content:    "decoy",
		},
	})
	require.NoError(t, err)
	server := NewServer(ServerOptions{
		Authenticator: auth.NewAuthenticator([]auth.User{{Username: "user", Password: "pass"}}),
		Logger:        log.NewNOPFactory().Logger(),
		Masquerade:    masquerade,
	})
	request := httptest.NewRequest(stdhttp.MethodConnect, "https://example.com:443", nil)
	request.ProtoMajor = 2
	response := httptest.NewRecorder()
	(&httpHandler{server: server, handler: discardHandler{}}).ServeHTTP(response, request)
	require.Equal(t, stdhttp.StatusTeapot, response.Code)
	require.Equal(t, "decoy", response.Body.String())
	require.Empty(t, response.Header().Get("Proxy-Authenticate"))
	require.Empty(t, response.Header().Get("WWW-Authenticate"))
}

func TestHTTPMasqueradeRejectsInvalidProxyURL(t *testing.T) {
	_, err := NewMasqueradeHandler(context.Background(), &option.Hysteria2Masquerade{
		Type:         "proxy",
		ProxyOptions: option.Hysteria2MasqueradeProxy{URL: "not-a-url"},
	})
	require.Error(t, err)
}
