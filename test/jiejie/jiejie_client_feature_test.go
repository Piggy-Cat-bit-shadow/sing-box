//go:build !jiejie_server_minimal

package jiejie_test

// Client-feature integration tests for the Jiejie Server Edition fork.
//
// These exercise the CLIENT-side enhancements — the HTTP/3 connection pool, the
// configurable fallback backoff, and H3 -> H2 fallback. They require `http`
// OUTBOUNDS and the full protocol registry, which the production minimal build
// deliberately does not register, so this file is excluded from
// jiejie_server_minimal and runs under the upstream/default tag set instead.
//
// The production server behaviour is covered by jiejie_minimal_runtime_test.go
// under release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL. These tests never substitute
// for those.

import (
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// D. H3 -> H2 fallback and configurable backoff
// ---------------------------------------------------------------------------

// TestJiejieH3FallbackBackoffConfiguration checks the client accepts the new
// backoff and pool schema and that the values round-trip through config.
func TestJiejieH3FallbackBackoffConfiguration(t *testing.T) {
	config := `{
		"outbounds": [{
			"type": "http",
			"server": "127.0.0.1",
			"server_port": 443,
			"version": 3,
			"username": "sekai",
			"password": "password",
			"http3_fallback": {
				"initial_backoff": "5s",
				"max_backoff": "5m",
				"multiplier": 2,
				"reset_on_success": true
			},
			"http3_connection_pool": {"size": 2, "strategy": "round_robin"},
			"tls": {"enabled": true, "server_name": "example.org"}
		}]
	}`
	options, err := parseJiejieOptions(t, config)
	require.NoError(t, err)
	require.Len(t, options.Outbounds, 1)
	outbound, loaded := options.Outbounds[0].Options.(*option.HTTPOutboundOptions)
	require.True(t, loaded)
	require.NotNil(t, outbound.HTTP3Options.HTTP3Fallback)
	require.Equal(t, badoption.Duration(5*time.Second), outbound.HTTP3Options.HTTP3Fallback.InitialBackoff)
	require.Equal(t, badoption.Duration(5*time.Minute), outbound.HTTP3Options.HTTP3Fallback.MaxBackoff)
	require.Equal(t, 2.0, outbound.HTTP3Options.HTTP3Fallback.Multiplier)
	require.NotNil(t, outbound.HTTP3Options.HTTP3ConnectionPool)
	require.Equal(t, 2, outbound.HTTP3Options.HTTP3ConnectionPool.Size)
	require.Equal(t, option.HTTP3PoolStrategyRoundRobin, outbound.HTTP3Options.HTTP3ConnectionPool.Strategy)
}

// TestJiejieHTTP3UnavailableFallsBackToH2 exercises a version=3 client whose
// HTTP/3 endpoint is not reachable, confirming it still serves traffic over
// HTTP/2 when version fallback is allowed.
func TestJiejieHTTP3UnavailableFallsBackToH2(t *testing.T) {
	decoyAddr, targetAddr := startDecoyOrigins(t)
	// The H2 listener runs on TCP, the client is told to use version 3. Since
	// no H3 listener exists on the UDP port, the client must fall back.
	h2Port := startJiejieMASQUEH2(t, decoyAddr)

	proxyPort := reserveTCPPort(t)
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			// SOCKS rather than mixed, so this works under the minimal build too.
			Type: C.TypeSOCKS,
			Options: &option.SocksInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
					ListenPort: proxyPort,
				},
			},
		}},
		Outbounds: []option.Outbound{
			{Type: C.TypeDirect, Tag: "direct"},
			{
				Type: C.TypeHTTP,
				Tag:  "masque-out",
				Options: &option.HTTPOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: h2Port,
					},
					Username:               jiejieTestUser,
					Password:               jiejieTestPassword,
					Version:                3,
					DisableVersionFallback: false,
					HTTP3Options: option.QUICOptions{
						HTTP3Fallback: &option.HTTP3FallbackOptions{
							InitialBackoff: badoption.Duration(5 * time.Second),
							MaxBackoff:     badoption.Duration(5 * time.Minute),
							Multiplier:     2,
						},
					},
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:    true,
							ServerName: "example.org",
						},
					},
				},
			},
		},
		Route: &option.RouteOptions{
			Rules: []option.Rule{{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{Inbound: []string{"socks-in"}},
					RuleAction: option.RuleAction{
						Action:       C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{Outbound: "masque-out"},
					},
				},
			}},
			Final: "direct",
		},
	})

	proxyURL, err := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(int(proxyPort)))
	require.NoError(t, err)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   20 * time.Second,
	}
	response, err := client.Get("http://" + targetAddr + "/")
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "proxy-target-ok", string(body))
}

// ---------------------------------------------------------------------------
// E. HTTP/3 connection pool configuration
// ---------------------------------------------------------------------------

// TestJiejieHTTP3PoolConfiguration checks the pool schema, including that the
// default is size 1 (upstream behaviour) and that invalid sizes are rejected.
func TestJiejieHTTP3PoolConfiguration(t *testing.T) {
	t.Run("absent pool keeps upstream behaviour", func(t *testing.T) {
		options, err := parseJiejieOptions(t, `{
			"outbounds": [{
				"type": "http", "server": "127.0.0.1", "server_port": 443,
				"version": 3, "username": "sekai", "password": "password",
				"tls": {"enabled": true, "server_name": "example.org"}
			}]
		}`)
		require.NoError(t, err)
		outbound := options.Outbounds[0].Options.(*option.HTTPOutboundOptions)
		require.Nil(t, outbound.HTTP3Options.HTTP3ConnectionPool)
		size, err := outbound.HTTP3Options.HTTP3ConnectionPool.Build()
		require.NoError(t, err)
		require.Equal(t, 1, size, "an absent pool must behave as one transport")
	})

	t.Run("size 2 is accepted", func(t *testing.T) {
		options, err := parseJiejieOptions(t, `{
			"outbounds": [{
				"type": "http", "server": "127.0.0.1", "server_port": 443,
				"version": 3, "username": "sekai", "password": "password",
				"http3_connection_pool": {"size": 2, "strategy": "round_robin"},
				"tls": {"enabled": true, "server_name": "example.org"}
			}]
		}`)
		require.NoError(t, err)
		outbound := options.Outbounds[0].Options.(*option.HTTPOutboundOptions)
		size, err := outbound.HTTP3Options.HTTP3ConnectionPool.Build()
		require.NoError(t, err)
		require.Equal(t, 2, size)
	})

	t.Run("oversized pool is rejected by validation", func(t *testing.T) {
		pool := &option.HTTP3ConnectionPoolOptions{Size: 64}
		_, err := pool.Build()
		require.Error(t, err)
	})
}

// TestJiejieAnyTLSAuthenticatedStillWorks is the other half of the contract:
// adding fallback must not break legitimate AnyTLS traffic.
func TestJiejieAnyTLSAuthenticatedStillWorks(t *testing.T) {
	_, targetAddr := startDecoyOrigins(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	anytlsPort := reserveTCPPort(t)
	clientPort := reserveTCPPort(t)

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeAnyTLS,
				Options: &option.AnyTLSInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
						ListenPort: anytlsPort,
					},
					Users: []option.AnyTLSUser{{Name: jiejieTestUser, Password: jiejieTestPassword}},
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
							KeyPath:         keyPem,
						},
					},
					Fallback: &option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: reserveTCPPort(t),
					},
				},
			},
			{
				// A SOCKS inbound is used as the local test client because it
				// exists in the full, jiejie and jiejie-minimal builds, whereas
				// the mixed inbound is deliberately absent from the minimal
				// server build.
				Type: C.TypeSOCKS,
				Options: &option.SocksInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
						ListenPort: clientPort,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{Type: C.TypeDirect, Tag: "direct"},
			{
				Type: C.TypeAnyTLS,
				Tag:  "anytls-out",
				Options: &option.AnyTLSOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: anytlsPort,
					},
					Password: jiejieTestPassword,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:    true,
							ServerName: "example.org",
						},
					},
				},
			},
		},
		Route: &option.RouteOptions{
			Rules: []option.Rule{{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						Inbound: []string{"socks-in"},
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: "anytls-out",
						},
					},
				},
			}},
			Final: "direct",
		},
	})

	// Drive a request through the AnyTLS outbound and confirm it reaches the
	// target, proving authenticated AnyTLS data flow is intact.
	proxyURL, err := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(int(clientPort)))
	require.NoError(t, err)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   15 * time.Second,
	}
	response, err := client.Get("http://" + targetAddr + "/")
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "proxy-target-ok", string(body))
}
