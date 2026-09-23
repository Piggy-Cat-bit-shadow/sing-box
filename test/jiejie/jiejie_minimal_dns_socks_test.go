package jiejie_test

import (
	std_bufio "bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	sbdns "github.com/sagernet/sing-box/dns"
	sbtransport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/stretchr/testify/require"
)

// This file covers two production behaviours that the minimal registry could
// plausibly break:
//
//  1. UDP DNS responses that are truncated are retried over TCP by the UDP
//     transport itself, with no `type: tcp` DNS transport registered. The
//     minimal registry registers only `udp` (plus the `local` transport that
//     box.go requires at startup), so a truncated answer must still resolve.
//
//  2. The residential SOCKS5 outbound carries TCP through an authenticated
//     upstream, which is the only non-direct outbound the production config has.
//
// Both are executed under release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL.

// testDNSServer answers one specific name over both UDP and TCP on the same
// address. The UDP reply is deliberately truncated (TC bit set); the TCP reply
// is a complete answer. That is exactly the situation a real resolver hits when
// an answer exceeds the UDP payload size.
type testDNSServer struct {
	address    string
	tcpAddress string
	udpQueries atomic.Int64
	tcpQueries atomic.Int64
}

func startTruncatingDNSServer(t *testing.T, name string, ipv4 net.IP) *testDNSServer {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tcpListener, err := net.Listen("tcp", udpConn.LocalAddr().String())
	require.NoError(t, err)
	t.Cleanup(func() {
		udpConn.Close()
		tcpListener.Close()
	})

	server := &testDNSServer{
		address:    udpConn.LocalAddr().String(),
		tcpAddress: tcpListener.Addr().String(),
	}

	// UDP: reply with the TC bit set and no answer records.
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, addr, readErr := udpConn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			server.udpQueries.Add(1)
			response := buildDNSResponse(buffer[:n], name, nil, true)
			if response != nil {
				_, _ = udpConn.WriteToUDP(response, addr)
			}
		}
	}()

	// TCP: reply with the full answer.
	go func() {
		for {
			conn, acceptErr := tcpListener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				lengthBuffer := make([]byte, 2)
				if _, readErr := io.ReadFull(conn, lengthBuffer); readErr != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(lengthBuffer))
				if _, readErr := io.ReadFull(conn, query); readErr != nil {
					return
				}
				server.tcpQueries.Add(1)
				response := buildDNSResponse(query, name, []net.IP{ipv4}, false)
				if response == nil {
					return
				}
				framed := make([]byte, 2+len(response))
				binary.BigEndian.PutUint16(framed, uint16(len(response)))
				copy(framed[2:], response)
				_, _ = conn.Write(framed)
			}()
		}
	}()

	return server
}

// buildDNSResponse constructs a minimal DNS reply. When truncated is true the TC
// flag is set and the answer section is empty.
func buildDNSResponse(query []byte, name string, answers []net.IP, truncated bool) []byte {
	if len(query) < 12 {
		return nil
	}
	question := query[12:]
	header := make([]byte, 12)
	copy(header, query[:2]) // transaction ID
	header[2] = 0x81        // QR=1, RD=1
	header[3] = 0x80        // RA=1
	if truncated {
		header[2] |= 0x02 // TC
	}
	binary.BigEndian.PutUint16(header[4:], 1)                    // QDCOUNT
	binary.BigEndian.PutUint16(header[6:], uint16(len(answers))) // ANCOUNT

	response := append([]byte{}, header...)
	response = append(response, question...)
	for _, ip := range answers {
		// Name pointer back to the question at offset 12.
		response = append(response, 0xC0, 0x0C)
		response = append(response, 0x00, 0x01) // TYPE A
		response = append(response, 0x00, 0x01) // CLASS IN
		response = append(response, 0x00, 0x00, 0x00, 0x3C)
		response = append(response, 0x00, 0x04)
		response = append(response, ip.To4()...)
	}
	return response
}

// TestJiejieMinimalDNSTruncatedTCPFallback is the regression test for dropping
// the registered `type: tcp` DNS transport from the production registry.
//
// dns/transport/udp.go Exchange() inspects response.Truncated and calls its own
// exchangeTCP(), which dials TCP through the same dialer and never consults the
// transport registry. This test exercises that path directly against a mock
// resolver whose UDP answer carries the TC bit and whose TCP answer is complete,
// so it proves the truncation fallback works with no `type: tcp` transport
// registered.
func TestJiejieMinimalDNSTruncatedTCPFallback(t *testing.T) {
	const queryName = "truncated.example.test"
	resolvedIP := net.IPv4(192, 0, 2, 123)
	server := startTruncatingDNSServer(t, queryName, resolvedIP)
	require.True(t, server.hasTCPListener(), "the mock resolver must accept TCP")

	// A UDP-only transport, exactly as the production registry registers it.
	udpTransport := newTestUDPTransport(t, server.address)
	// The multiplexer keeps a background goroutine alive; close it so the suite's
	// goroutine-leak check stays clean.
	t.Cleanup(func() { _ = udpTransport.Close() })

	message := new(mDNS.Msg)
	message.SetQuestion(mDNS.Fqdn(queryName), mDNS.TypeA)
	message.RecursionDesired = true

	exchangeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	response, err := udpTransport.Exchange(exchangeCtx, message)
	require.NoError(t, err, "a truncated UDP answer must still resolve via the transport's own TCP retry")
	require.False(t, response.Truncated, "the final answer must not be truncated")
	require.NotEmpty(t, response.Answer, "the TCP retry must return the address records")

	found := false
	for _, answer := range response.Answer {
		if record, isA := answer.(*mDNS.A); isA && record.A.String() == resolvedIP.String() {
			found = true
		}
	}
	require.True(t, found, "the resolved address must come from the TCP answer")

	require.GreaterOrEqual(t, server.udpQueries.Load(), int64(1),
		"the resolver must have been queried over UDP first")
	require.GreaterOrEqual(t, server.tcpQueries.Load(), int64(1),
		"a truncated UDP answer must trigger a TCP retry")
}

// TestJiejieMinimalResidentialSOCKSOutbound proves the minimal registry's SOCKS
// outbound carries an authenticated session to a target through a SOCKS5
// upstream. Only direct and socks are registered in the production registry.
func TestJiejieMinimalResidentialSOCKSOutbound(t *testing.T) {
	origin := startMinimalHTTPOrigin(t)
	upstreamPort, requestCount := startAuthenticatedSOCKS5Upstream(t, "residential-user", "residential-pass")

	// The entry point is a Shadowsocks 2022 inbound, which the minimal registry
	// does register; the socks inbound is deliberately absent, so the test drives
	// the path with a real SS2022 client instead.
	entryPort := reserveTCPPort(t)
	entryPassword := mkBase64(t, 16)
	const entryMethod = "2022-blake3-aes-128-gcm"
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeShadowsocks,
			Tag:  "entry-in",
			Options: &option.ShadowsocksInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
					ListenPort: entryPort,
				},
				Method:   entryMethod,
				Password: entryPassword,
			},
		}},
		Outbounds: []option.Outbound{
			{Type: C.TypeDirect, Tag: "direct"},
			{
				Type: C.TypeSOCKS,
				Tag:  "residential-socks",
				Options: &option.SOCKSOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: upstreamPort,
					},
					Version:  "5",
					Username: "residential-user",
					Password: "residential-pass",
				},
			},
		},
		Route: &option.RouteOptions{
			Rules: []option.Rule{{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{Inbound: []string{"entry-in"}},
					RuleAction: option.RuleAction{
						Action:       C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{Outbound: "residential-socks"},
					},
				},
			}},
			Final: "direct",
		},
	})

	// Real Shadowsocks 2022 client into the production entry inbound.
	methodConfig, err := shadowaead_2022.NewWithPassword(entryMethod, entryPassword, time.Now)
	require.NoError(t, err)
	rawConn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(entryPort)), 5*time.Second)
	require.NoError(t, err)
	defer rawConn.Close()
	conn, err := methodConfig.DialConn(rawConn, M.ParseSocksaddr(origin))
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: origin\r\n\r\n"))
	require.NoError(t, err)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response, err := http.ReadResponse(std_bufio.NewReader(conn), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.GreaterOrEqual(t, requestCount(), 1,
		"the residential SOCKS5 upstream must have carried the connection")
}

// hasTCPListener reports whether the mock resolver accepted a TCP listener.
func (s *testDNSServer) hasTCPListener() bool {
	return s.tcpAddress != ""
}

// newTestUDPTransport builds a real UDP DNS transport pointed at the mock
// resolver, using only UDP. No `type: tcp` transport is constructed, which is
// what the minimal production registry does.
func newTestUDPTransport(t *testing.T, address string) *sbtransport.UDPTransport {
	t.Helper()
	host, portString, err := net.SplitHostPort(address)
	require.NoError(t, err)
	port, err := strconv.ParseUint(portString, 10, 16)
	require.NoError(t, err)
	serverAddr := M.ParseSocksaddrHostPort(host, uint16(port))
	remoteOptions := option.RemoteDNSServerOptions{
		DNSServerAddressOptions: option.DNSServerAddressOptions{
			Server:     host,
			ServerPort: uint16(port),
		},
	}
	transport := sbtransport.NewUDPRaw(
		log.NewNOPFactory().Logger(),
		sbdns.NewTransportAdapterWithRemoteOptions(C.DNSTypeUDP, "local-agh", remoteOptions),
		N.SystemDialer,
		serverAddr,
	)
	require.NotNil(t, transport)
	return transport
}

// startAuthenticatedSOCKS5Upstream starts a minimal SOCKS5 server that requires
// username/password authentication and forwards to the requested target. It
// returns the listen port and a counter of successfully authenticated requests.
func startAuthenticatedSOCKS5Upstream(t *testing.T, username, password string) (uint16, func() int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	var served atomic.Int64

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Greeting: offer username/password auth only.
				greeting := make([]byte, 2)
				if _, readErr := io.ReadFull(conn, greeting); readErr != nil {
					return
				}
				methods := make([]byte, int(greeting[1]))
				if _, readErr := io.ReadFull(conn, methods); readErr != nil {
					return
				}
				if _, writeErr := conn.Write([]byte{0x05, 0x02}); writeErr != nil {
					return
				}
				// Username/password sub-negotiation (RFC 1929).
				authHeader := make([]byte, 2)
				if _, readErr := io.ReadFull(conn, authHeader); readErr != nil {
					return
				}
				authUser := make([]byte, int(authHeader[1]))
				if _, readErr := io.ReadFull(conn, authUser); readErr != nil {
					return
				}
				passwordLength := make([]byte, 1)
				if _, readErr := io.ReadFull(conn, passwordLength); readErr != nil {
					return
				}
				authPassword := make([]byte, int(passwordLength[0]))
				if _, readErr := io.ReadFull(conn, authPassword); readErr != nil {
					return
				}
				if string(authUser) != username || string(authPassword) != password {
					_, _ = conn.Write([]byte{0x01, 0x01})
					return
				}
				if _, writeErr := conn.Write([]byte{0x01, 0x00}); writeErr != nil {
					return
				}
				// CONNECT request.
				requestHeader := make([]byte, 4)
				if _, readErr := io.ReadFull(conn, requestHeader); readErr != nil {
					return
				}
				var targetHost string
				switch requestHeader[3] {
				case 0x01:
					address := make([]byte, 4)
					if _, readErr := io.ReadFull(conn, address); readErr != nil {
						return
					}
					targetHost = net.IP(address).String()
				case 0x03:
					length := make([]byte, 1)
					if _, readErr := io.ReadFull(conn, length); readErr != nil {
						return
					}
					domain := make([]byte, int(length[0]))
					if _, readErr := io.ReadFull(conn, domain); readErr != nil {
						return
					}
					targetHost = string(domain)
				default:
					return
				}
				portBuffer := make([]byte, 2)
				if _, readErr := io.ReadFull(conn, portBuffer); readErr != nil {
					return
				}
				targetPort := int(portBuffer[0])<<8 | int(portBuffer[1])

				upstream, dialErr := net.DialTimeout("tcp",
					net.JoinHostPort(targetHost, strconv.Itoa(targetPort)), 5*time.Second)
				if dialErr != nil {
					_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer upstream.Close()
				if _, writeErr := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); writeErr != nil {
					return
				}
				served.Add(1)
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(upstream, conn); done <- struct{}{} }()
				go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
				<-done
			}()
		}
	}()

	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	return port, func() int { return int(served.Load()) }
}
