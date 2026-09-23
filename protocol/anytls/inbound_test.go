package anytls

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	singanytls "github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type discardHandler struct{}

func (discardHandler) NewConnectionEx(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}

func TestFallbackPreservesAuthenticationProbe(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backend.Close()
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	backendReceived := make(chan []byte, 1)
	go func() {
		conn, acceptErr := backend.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		body := make([]byte, len(payload))
		_, _ = io.ReadFull(conn, body)
		backendReceived <- body
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
	}()
	address := backend.Addr().(*net.TCPAddr)
	fallback := &fallbackHandler{
		destination: M.ParseSocksaddrHostPort(address.IP.String(), uint16(address.Port)),
		logger:      log.NewNOPFactory().Logger(),
	}
	service, err := singanytls.NewService("correct-password", singanytls.ServiceOptions{
		Handler:         discardHandler{},
		FallbackHandler: fallback,
	})
	require.NoError(t, err)
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		_ = service.NewConnection(context.Background(), server, M.Socksaddr{}, func(error) { close(done) })
	}()
	_, err = client.Write(payload)
	require.NoError(t, err)
	response := make([]byte, 40)
	_, err = io.ReadFull(client, response)
	require.NoError(t, err)
	require.Equal(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", string(response))
	select {
	case received := <-backendReceived:
		require.Equal(t, payload, received)
	case <-time.After(time.Second):
		t.Fatal("fallback backend did not receive payload")
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fallback connection did not close")
	}
}

func TestFallbackOptionsRequireDestination(t *testing.T) {
	_, err := NewInbound(context.Background(), nil, log.NewNOPFactory().Logger(), "anytls", option.AnyTLSInboundOptions{
		Fallback: &option.AnyTLSFallbackOptions{},
	})
	require.Error(t, err)
}
