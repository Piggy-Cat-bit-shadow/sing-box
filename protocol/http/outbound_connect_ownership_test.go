package http

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Destination DNS ownership on the HTTP CONNECT wire
// ---------------------------------------------------------------------------
//
// # Why the CONNECT authority is the whole question
//
// For a TCP proxy the wiredestination IS the CONNECT request's authority:
//
//	CONNECT example.com:443 HTTP/1.1
//
// A peer that receives a hostname there resolves the user's destination itself. Under
// `destination_dns_ownership` this fork's DNS policy plane owns that name, so what must cross the
// boundary is an address:
//
//	CONNECT 203.0.113.10:443 HTTP/1.1
//	CONNECT [2001:db8::10]:443 HTTP/1.1
//
// The IPv6 form is bracketed because the port separator is a colon, and an unbracketed
// `2001:db8::10:443` is not a valid authority - which is why the assertion below is on the exact
// authority string rather than on "the address appears somewhere".
//
// # Why a real loopback proxy
//
// The promise is about what a PEER receives, so the observation has to be the bytes decoded by
// something that parses an HTTP request line. `http.ReadRequest` on a real socket is that, and it
// also proves the request the client produced is well formed enough for the standard parser.

const connectWireTimeout = 10 * time.Second

// connectObservation is one CONNECT request as the proxy decoded it.
type connectObservation struct {
	method    string
	authority string
	// requestURI is the target as it appeared on the wire. For a CONNECT that is the authority, so a
	// failure can distinguish "the authority was wrong" from "the request line was malformed".
	requestURI string
	proto      string
	headers    stdhttp.Header
	err        error
}

// connectProxy is a loopback TCP listener that answers every CONNECT it receives with 200 and then
// holds the tunnel open. It records each request, so one fixture serves a whole table of cases.
type connectProxy struct {
	listener net.Listener
	// observations is buffered generously: each case dials once.
	observations chan connectObservation
	// tunnels counts accepted connections that reached a 200, so a test can tell "the request was
	// sent" from "the request was answered".
	tunnels chan struct{}
}

func newConnectProxy(t *testing.T) *connectProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	proxy := &connectProxy{
		listener:     listener,
		observations: make(chan connectObservation, 16),
		tunnels:      make(chan struct{}, 16),
	}
	go proxy.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return proxy
}

func (p *connectProxy) address() M.Socksaddr {
	return M.SocksaddrFromNet(p.listener.Addr()).Unwrap()
}

func (p *connectProxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *connectProxy) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(connectWireTimeout))

	reader := bufio.NewReader(conn)
	request, err := stdhttp.ReadRequest(reader)
	if err != nil {
		select {
		case p.observations <- connectObservation{err: err}:
		default:
		}
		return
	}
	authority := request.URL.Host
	if authority == "" {
		authority = request.Host
	}
	select {
	case p.observations <- connectObservation{
		method:     request.Method,
		authority:  authority,
		requestURI: request.URL.RequestURI(),
		proto:      request.Proto,
		headers:    request.Header.Clone(),
	}:
	default:
	}

	// A CONNECT is answered 200 and the connection then becomes the tunnel. The client stops caring
	// about the body, so the response is written and the socket is drained.
	if _, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	select {
	case p.tunnels <- struct{}{}:
	default:
	}
	_, _ = io.Copy(io.Discard, reader)
}

func (p *connectProxy) awaitObservation(t *testing.T) connectObservation {
	t.Helper()
	select {
	case observation := <-p.observations:
		require.NoError(t, observation.err,
			"the proxy could not parse the request the client sent, so there is no authority to assert on")
		return observation
	case <-time.After(connectWireTimeout):
		t.Fatal("the proxy never received a CONNECT")
		return connectObservation{}
	}
}

// ---------------------------------------------------------------------------
// The fixture: an HTTP outbound whose destination DNS is owned locally
// ---------------------------------------------------------------------------

type httpOwnershipHarness struct {
	outbound  *Outbound
	proxy     *connectProxy
	router    *stubDNSRouter
	lookups   []string
	answers   []netip.Addr
	lookupErr error
}

// stubDNSRouter records what the outbound asked and answers with what the test decided.
//
// It is a stub rather than a real router because the question is what the OUTBOUND does with an
// answer, not how the answer was obtained; the real router's own behaviour is covered by dns/.
type stubDNSRouter struct {
	adapter.DNSRouter
}

func newHTTPOwnershipHarness(t *testing.T, ownership bool, proxyHost string, answers ...netip.Addr) *httpOwnershipHarness {
	t.Helper()
	harness := &httpOwnershipHarness{answers: answers, router: &stubDNSRouter{}}
	harness.proxy = newConnectProxy(t)

	var headers badoption.HTTPHeader
	if proxyHost != "" {
		headers = badoption.HTTPHeader{"Host": badoption.Listable[string]{proxyHost}}
	}
	instance, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(),
		"downstream-http", option.HTTPOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     harness.proxy.address().AddrString(),
				ServerPort: harness.proxy.address().Port,
			},
			Headers: headers,
			DialerOptions: option.DialerOptions{
				DestinationDNSOwnership: ownership,
			},
		})
	require.NoError(t, err)
	harness.outbound = instance.(*Outbound)
	harness.outbound.dnsRouter = harness.router

	previous := lookupDestinationAddresses
	lookupDestinationAddresses = func(ctx context.Context, router adapter.DNSRouter, options adapter.DNSQueryOptions, domain string) ([]netip.Addr, error) {
		harness.lookups = append(harness.lookups, domain)
		if harness.lookupErr != nil {
			return nil, harness.lookupErr
		}
		return harness.answers, nil
	}
	t.Cleanup(func() { lookupDestinationAddresses = previous })
	return harness
}

// dialAsync runs one CONNECT dial without blocking, so the test can assert on the proxy's side while
// the dial is still in flight.
func (h *httpOwnershipHarness) dialAsync(ctx context.Context, destination M.Socksaddr) chan error {
	done := make(chan error, 1)
	go func() {
		conn, err := h.outbound.DialContext(ctx, N.NetworkTCP, destination)
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	return done
}

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------

// TestHTTPConnectAuthorityIsAnAddressNotADomain is the reproduction, for both families.
//
// The assertion is on the authority the standard parser produced, which is exactly what a real proxy
// routes on: not "the address appears in the request", but "the authority IS the address".
func TestHTTPConnectAuthorityIsAnAddressNotADomain(t *testing.T) {
	cases := []struct {
		name      string
		answer    netip.Addr
		authority string
		comment   string
	}{
		{
			name: "IPv4", answer: netip.MustParseAddr("203.0.113.10"), authority: "203.0.113.10:443",
			comment: "the plain form",
		},
		{
			name: "IPv6", answer: netip.MustParseAddr("2001:db8::10"), authority: "[2001:db8::10]:443",
			comment: "an IPv6 authority must be BRACKETED: an unbracketed 2001:db8::10:443 is not " +
				"a valid authority, and a proxy that parsed it would read a different port",
		},
		{
			name: "a v4-mapped answer", answer: netip.MustParseAddr("::ffff:203.0.113.11"),
			authority: "[::ffff:203.0.113.11]:443",
			comment: "whatever the resolver returned is what goes on the wire; the AUTHORITY form " +
				"still has to be a valid one. This case exists so the bracketing rule is applied on " +
				"family, not on a guess about the bytes",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newHTTPOwnershipHarness(t, true, "", testCase.answer)

			done := harness.dialAsync(context.Background(),
				M.ParseSocksaddrHostPort("user-destination.example", 443))
			observation := harness.proxy.awaitObservation(t)

			require.Equal(t, "CONNECT", observation.method)
			require.Equal(t, testCase.authority, observation.authority, testCase.comment)
			require.False(t, strings.Contains(observation.authority, "user-destination.example"),
				"the user's DOMAIN reached the CONNECT authority, which means the peer resolves it: %q",
				observation.authority)
			require.Equal(t, []string{"user-destination.example"}, harness.lookups,
				"the destination must have been resolved locally, exactly once")

			select {
			case err := <-done:
				require.NoError(t, err, "the dial must succeed against a proxy that answered 200")
			case <-time.After(connectWireTimeout):
				t.Fatal("the dial never returned after the proxy answered")
			}
		})
	}
}

// TestHTTPConnectWithoutOwnershipKeepsTheDomain is the control. The declaration is what changes the
// wire; an ordinary single-hop HTTP proxy must keep receiving the hostname, because its own resolver
// picks the right CDN edge and this fork has no business overriding that.
func TestHTTPConnectWithoutOwnershipKeepsTheDomain(t *testing.T) {
	harness := newHTTPOwnershipHarness(t, false, "", netip.MustParseAddr("203.0.113.10"))

	done := harness.dialAsync(context.Background(),
		M.ParseSocksaddrHostPort("single-hop.example", 8443))
	observation := harness.proxy.awaitObservation(t)

	require.Equal(t, "single-hop.example:8443", observation.authority,
		"without the declaration the hostname must still reach the proxy")
	require.Empty(t, harness.lookups, "and nothing may be resolved locally for it")

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(connectWireTimeout):
		t.Fatal("the dial never returned after the proxy answered")
	}
}

// TestHTTPConnectOwnershipFailsClosed is the fail-closed contract, and the decisive half is asserted on
// the PEER's side: after a refused resolution the proxy must have received nothing at all. An
// implementation that logged an error and then sent `CONNECT example.com:443` would satisfy every
// assertion made on the returned error alone.
func TestHTTPConnectOwnershipFailsClosed(t *testing.T) {
	cases := []struct {
		name      string
		answers   []netip.Addr
		lookupErr error
		comment   string
	}{
		{
			name: "the resolver refused", lookupErr: errors.New("test: resolver refused"),
			comment: "a resolution failure must not be silently upgraded to a remote resolution",
		},
		{
			name: "the resolver answered with nothing", answers: nil,
			comment: "an empty answer is the same case as a failure: there is no address to send",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newHTTPOwnershipHarness(t, true, "", testCase.answers...)
			harness.lookupErr = testCase.lookupErr

			conn, err := harness.outbound.DialContext(context.Background(), N.NetworkTCP,
				M.ParseSocksaddrHostPort("unresolvable.example", 443))
			require.Error(t, err, testCase.comment)
			require.Nil(t, conn)

			select {
			case observation := <-harness.proxy.observations:
				t.Fatalf("the proxy received a request (%s %s) after the local resolution failed: "+
					"the unresolved name was carried to the peer anyway",
					observation.method, observation.authority)
			case <-time.After(200 * time.Millisecond):
			}
		})
	}
}

// TestHTTPConnectOwnershipRefusesAHostOverride pins the combination that cannot be honoured.
//
// With `headers.Host` configured, an HTTP/1 CONNECT carries the operator's value as its authority and
// the destination travels nowhere - the proxy resolves whatever the operator wrote. Replacing the
// authority with our address would not remove the peer's resolution, it would only move it, while
// silently discarding a header the configuration asked for. So it is refused rather than half-honoured,
// and refused BEFORE anything is sent.
func TestHTTPConnectOwnershipRefusesAHostOverride(t *testing.T) {
	harness := newHTTPOwnershipHarness(t, true, "override.example", netip.MustParseAddr("203.0.113.10"))

	conn, err := harness.outbound.DialContext(context.Background(), N.NetworkTCP,
		M.ParseSocksaddrHostPort("user-destination.example", 443))
	require.Error(t, err,
		"a Host override makes the PEER resolve the operator's host, so ownership cannot be honoured")
	require.Nil(t, conn)
	require.Contains(t, err.Error(), "override.example",
		"the error must name the override, so the operator can find the field responsible")
	require.Contains(t, err.Error(), "destination DNS ownership",
		"and it must name the option, so the two halves of the conflict are both visible")

	select {
	case observation := <-harness.proxy.observations:
		t.Fatalf("the proxy received a request (%s %s) although the combination is refused",
			observation.method, observation.authority)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestHTTPConnectOwnershipLeavesAnAddressDestinationAlone pins that the option is about DOMAINS. A
// literal destination is already an address, and resolving it would be inventing a name by reverse
// lookup.
func TestHTTPConnectOwnershipLeavesAnAddressDestinationAlone(t *testing.T) {
	harness := newHTTPOwnershipHarness(t, true, "", netip.MustParseAddr("198.51.100.7"))

	done := harness.dialAsync(context.Background(),
		M.ParseSocksaddrHostPort("198.51.100.7", 443))
	observation := harness.proxy.awaitObservation(t)

	require.Equal(t, "198.51.100.7:443", observation.authority)
	require.Empty(t, harness.lookups, "a literal destination must not be resolved")

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(connectWireTimeout):
		t.Fatal("the dial never returned after the proxy answered")
	}
}

// TestHTTPConnectOwnershipUsesTheFirstAddress pins the candidate rule, and it is asserted on the wire
// rather than on the metadata: the client cannot retry a CONNECT per address without producing several
// requests, so the FIRST answer is the one that travels. A build that picked the last, or that sorted
// by family, would send a different authority here.
func TestHTTPConnectOwnershipUsesTheFirstAddress(t *testing.T) {
	harness := newHTTPOwnershipHarness(t, true, "",
		netip.MustParseAddr("203.0.113.20"),
		netip.MustParseAddr("2001:db8::20"),
		netip.MustParseAddr("203.0.113.21"),
	)

	done := harness.dialAsync(context.Background(),
		M.ParseSocksaddrHostPort("ordered-destination.example", 443))
	observation := harness.proxy.awaitObservation(t)

	require.Equal(t, "203.0.113.20:443", observation.authority,
		"the candidate order the local policy produced must decide, not a preference for a family")

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(connectWireTimeout):
		t.Fatal("the dial never returned after the proxy answered")
	}
}

// TestHTTPConnectOwnershipKeepsThePort pins that the rewrite touches only the ADDRESS. The port is part
// of the user's destination and has nothing to do with DNS, so a fix that reconstructed the authority
// from the resolved address alone would silently retarget the connection.
func TestHTTPConnectOwnershipKeepsThePort(t *testing.T) {
	for _, port := range []uint16{80, 443, 8080, 65535} {
		t.Run(portName(port), func(t *testing.T) {
			harness := newHTTPOwnershipHarness(t, true, "", netip.MustParseAddr("203.0.113.30"))
			done := harness.dialAsync(context.Background(),
				M.ParseSocksaddrHostPort("port-destination.example", port))
			observation := harness.proxy.awaitObservation(t)

			require.Equal(t, "203.0.113.30:"+portName(port), observation.authority)

			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(connectWireTimeout):
				t.Fatal("the dial never returned after the proxy answered")
			}
		})
	}
}

// TestHTTPConnectOwnershipIsPerDialNotPerOutbound pins that the resolution happens on the DIAL path.
// An outbound is a long-lived object shared by every flow; a cache of one address would serve the first
// flow's answer to every later flow, and would keep serving it across a network change.
func TestHTTPConnectOwnershipIsPerDialNotPerOutbound(t *testing.T) {
	harness := newHTTPOwnershipHarness(t, true, "", netip.MustParseAddr("203.0.113.40"))

	for _, expected := range []string{"first.example", "second.example"} {
		done := harness.dialAsync(context.Background(),
			M.ParseSocksaddrHostPort(expected, 443))
		observation := harness.proxy.awaitObservation(t)
		require.Equal(t, "203.0.113.40:443", observation.authority)

		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(connectWireTimeout):
			t.Fatal("the dial never returned after the proxy answered")
		}
	}

	require.Equal(t, []string{"first.example", "second.example"}, harness.lookups,
		"each flow must ask the local policy for ITS destination; a per-outbound cache would "+
			"answer the second flow with the first one's address")
}

// portName renders a port without importing strconv into the test's namespace twice.
func portName(port uint16) string {
	if port == 0 {
		return "0"
	}
	var digits [6]byte
	position := len(digits)
	for port > 0 {
		position--
		digits[position] = byte('0' + port%10)
		port /= 10
	}
	return string(digits[position:])
}

// TestTheHTTPOutboundDoesNotShareOwnershipWithTheStreamSuite is a naming guard rather than a behaviour
// one: it fails to compile if the seam this file substitutes disappears, which is the only way the
// assertions above could silently stop exercising the real decision.
func TestTheHTTPOutboundDoesNotShareOwnershipWithTheStreamSuite(t *testing.T) {
	require.NotNil(t, lookupDestinationAddresses,
		"the lookup seam must exist; if it was removed, the tests above no longer drive the "+
			"production decision and would pass for the wrong reason")
	var waitGroup sync.WaitGroup
	waitGroup.Wait()
}
