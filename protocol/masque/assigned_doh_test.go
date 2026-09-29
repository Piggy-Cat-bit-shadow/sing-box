package masque

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"

	dnsTransport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// Tests for same-connection DoH on the assigned resolver.
//
// # The property that matters
//
// draft-ietf-masque-connect-ip-dns-06 §3.5 says that when the proxy is authoritative for a
// DoH origin, the client SHOULD send its queries as independent HTTPS requests coalesced
// over the SAME HTTPS connection the CONNECT-IP tunnel uses. That is the whole reason the
// generic HTTP/3 request API exists.
//
// A test that only checks "the query was answered" would pass even if the client quietly
// opened a second connection, or fell back to UDP, so these tests count connections and
// record the requests that actually arrived.

// errTestDoHUnavailable stands in for a transport failure on the same-connection DoH path.
var errTestDoHUnavailable = E.New("test: same-connection DoH unavailable")

// countingDoHClient stands in for the endpoint's HTTP/3 client. It counts the requests it
// is asked to carry so a test can tell same-connection DoH apart from the UDP fallback,
// which would send nothing through this type at all.
type countingDoHClient struct {
	access   sync.Mutex
	requests []*http.Request
	bodies   [][]byte
	// response is the DNS response payload handed back, already packed.
	response []byte
	// status overrides the HTTP status, for the failure tests.
	status int
	// err, when set, makes the round trip fail as a transport error.
	err error
	// delay is applied before answering, used by the cancellation test.
	beforeAnswer func()
}

func (c *countingDoHClient) RoundTripHTTP3(ctx context.Context, request *http.Request) (*http.Response, error) {
	if c.beforeAnswer != nil {
		c.beforeAnswer()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.err != nil {
		return nil, c.err
	}
	body, readErr := io.ReadAll(request.Body)
	if readErr != nil {
		return nil, readErr
	}
	c.access.Lock()
	c.requests = append(c.requests, request)
	c.bodies = append(c.bodies, body)
	c.access.Unlock()

	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		// A real HTTP client formats Status as "403 Forbidden"; the transport quotes it
		// verbatim, so the double must produce the same shape.
		Status: strconv.Itoa(status) + " " + http.StatusText(status),
		Header: make(http.Header),
		Body:   io.NopCloser(strings.NewReader(string(c.response))),
	}, nil
}

func (c *countingDoHClient) requestCount() int {
	c.access.Lock()
	defer c.access.Unlock()
	return len(c.requests)
}

func (c *countingDoHClient) firstRequest() *http.Request {
	c.access.Lock()
	defer c.access.Unlock()
	if len(c.requests) == 0 {
		return nil
	}
	return c.requests[0]
}

// dohTestAnswer packs a minimal DNS response for the given query so a test can assert that
// what came back is the answer the DoH server sent, not a canned value.
func dohTestAnswer(t *testing.T, query *mDNS.Msg, address string) []byte {
	t.Helper()
	response := new(mDNS.Msg)
	response.SetReply(query)
	response.Answer = append(response.Answer, &mDNS.AAAA{
		Hdr: mDNS.RR_Header{
			Name:   query.Question[0].Name,
			Rrtype: mDNS.TypeAAAA,
			Class:  mDNS.ClassINET,
			Ttl:    60,
		},
		AAAA: net.IP(netip.MustParseAddr(address).AsSlice()),
	})
	packed, err := response.Pack()
	require.NoError(t, err)
	return packed
}

// dohAssignment builds an assignment advertising a dohpath, which is what selects the DoH
// path over the UDP one.
func dohAssignment(t *testing.T, dohPath string, nameserver string) masque.DNSConfiguration {
	t.Helper()
	return masque.DNSConfiguration{
		Nameservers: []masque.DNSNameserver{
			{
				ServicePriority:          1,
				IPv6Addresses:            []netip.Addr{netip.MustParseAddr(nameserver)},
				AuthenticationDomainName: "dns.example.test.",
				ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
					// h2, length-prefixed per RFC 9460 section 7.1.
					dnsmessage.SVCParamKey(1): {0x02, 'h', '2'},
					dnsmessage.SVCParamKey(9): []byte(dohPath), // dohpath
				},
			},
		},
	}
}

// udpAssignment builds an assignment with no encrypted transport advertised, so the plain
// UDP path is the only one available.
func udpAssignment(t *testing.T, nameserver string) masque.DNSConfiguration {
	t.Helper()
	return masque.DNSConfiguration{
		Nameservers: []masque.DNSNameserver{
			{
				ServicePriority: 1,
				IPv6Addresses:   []netip.Addr{netip.MustParseAddr(nameserver)},
			},
		},
	}
}

// newDoHTransport builds a transport with a DoH client attached, with the assignment
// already applied.
func newDoHTransport(t *testing.T, client dohRoundTripper, configuration masque.DNSConfiguration) *assignedDNSTransport {
	t.Helper()
	transport := newAssignedDNSTransport(logger.NOP(), &recordingDialer{}, "test")
	transport.setDoHClient(client)
	transport.apply(oneConfiguration(configuration), nil)
	return transport
}

// ---------------------------------------------------------------------------
// Same-connection DoH
// ---------------------------------------------------------------------------

// TestAssignedDNSUsesDoHWhenAdvertised is the core Stage 7 test.
//
// A dohpath in the assignment must select DoH, and the query must travel through the
// same-connection round tripper rather than the device's UDP dialer. The UDP dialer is
// asserted to have seen ZERO dials: if it were used, the query would be going somewhere
// other than the coalesced connection, which is the property being claimed.
func TestAssignedDNSUsesDoHWhenAdvertised(t *testing.T) {
	t.Parallel()

	query := new(mDNS.Msg)
	query.SetQuestion("inner.example.test.", mDNS.TypeAAAA)
	packed, err := query.Pack()
	require.NoError(t, err)

	client := &countingDoHClient{response: dohTestAnswer(t, query, "2001:db8::5")}
	dialer := &recordingDialer{}
	transport := newAssignedDNSTransport(logger.NOP(), dialer, "test")
	transport.setDoHClient(client)
	transport.apply(oneConfiguration(dohAssignment(t, "/dns-query{?dns}", "2001:db8::53")), nil)

	response, err := transport.Exchange(context.Background(), query)
	require.NoError(t, err)
	require.Len(t, response.Answer, 1, "the DoH server's answer must be returned")
	require.Equal(t, 1, client.requestCount(), "the query must travel over the DoH path")
	require.Equal(t, 0, dialer.dials,
		"the UDP dialer must not be used when DoH is available: a dial here would mean the query left the coalesced connection")
	require.Equal(t, uint16(mDNS.TypeAAAA), response.Question[0].Qtype)

	request := client.firstRequest()
	require.NotNil(t, request)
	require.Equal(t, http.MethodPost, request.Method, "RFC 8484 DoH queries are POSTed")
	require.Equal(t, "/dns-query", request.URL.Path,
		"the RFC 9461 URI Template placeholder must be stripped to leave a usable path")
	require.Equal(t, "dns.example.test.", request.URL.Host,
		"the request must name the authentication domain exactly as the resolver advertised it")
	require.Equal(t, dnsTransport.MimeType, request.Header.Get("Content-Type"))
	require.Equal(t, dnsTransport.MimeType, request.Header.Get("Accept"))
	require.Equal(t, int64(len(packed)), request.ContentLength,
		"the body length must be stated so a truncated query is rejected rather than parsed")
}

// TestAssignedDNSSendsTheQueryBodyVerbatim proves the wire query is what was sent, since a
// DoH POST carries the DNS message opaquely and a mangled body would still "work" against a
// permissive server.
func TestAssignedDNSSendsTheQueryBodyVerbatim(t *testing.T) {
	t.Parallel()

	query := new(mDNS.Msg)
	query.SetQuestion("verbatim.example.test.", mDNS.TypeA)
	packed, err := query.Pack()
	require.NoError(t, err)

	client := &countingDoHClient{response: dohTestAnswer(t, query, "2001:db8::6")}
	transport := newDoHTransport(t, client, dohAssignment(t, "/dns-query", "2001:db8::53"))

	_, err = transport.Exchange(context.Background(), query)
	require.NoError(t, err)

	client.access.Lock()
	defer client.access.Unlock()
	require.Len(t, client.bodies, 1)
	require.Equal(t, packed, client.bodies[0],
		"the request body must be exactly the packed DNS query")
}

// TestAssignedDNSDoHFailureDoesNotFallBackToHostSocket keeps the fail-closed guarantee in
// the presence of the new code path.
//
// The DoH path is inside the tunnel; the UDP path is also inside the tunnel. Neither may
// become a host socket. When the DoH client reports a transport failure the exchange must
// fail, not resolve, and above all not dial anything that is not the device.
func TestAssignedDNSDoHFailureDoesNotFallBackToHostSocket(t *testing.T) {
	t.Parallel()

	query := new(mDNS.Msg)
	query.SetQuestion("fails.example.test.", mDNS.TypeAAAA)
	client := &countingDoHClient{err: errTestDoHUnavailable}
	dialer := &recordingDialer{}
	transport := newAssignedDNSTransport(logger.NOP(), dialer, "test")
	transport.setDoHClient(client)
	transport.apply(oneConfiguration(dohAssignment(t, "/dns-query", "2001:db8::53")), nil)

	_, err := transport.Exchange(context.Background(), query)
	require.Error(t, err)
	require.ErrorIs(t, err, errTestDoHUnavailable)
	require.Equal(t, 0, dialer.dials,
		"a failed DoH query must not silently become a UDP query to a different transport")
}

// TestAssignedDNSWithoutDoHClientUsesUDPInsideTheTunnel covers a resolver that advertises
// no encrypted transport at all.
//
// Plain UDP is the right transport here, and the test pins that it is the DEVICE that is
// dialed, so this path cannot drift into a host socket.
//
// Note the contrast with TestAssignedDNSRefusesToDowngradeWhenDoHIsAdvertised below: a
// resolver that DID advertise DoH would refuse rather than take this path.
func TestAssignedDNSWithoutDoHClientUsesUDPInsideTheTunnel(t *testing.T) {
	t.Parallel()

	query := new(mDNS.Msg)
	query.SetQuestion("udp.example.test.", mDNS.TypeAAAA)
	packed, err := query.Pack()
	require.NoError(t, err)

	response := new(mDNS.Msg)
	response.SetReply(query)
	response.Answer = append(response.Answer, &mDNS.AAAA{
		Hdr:  mDNS.RR_Header{Name: query.Question[0].Name, Rrtype: mDNS.TypeAAAA, Class: mDNS.ClassINET, Ttl: 60},
		AAAA: net.IP(netip.MustParseAddr("2001:db8::7").AsSlice()),
	})
	answer, err := response.Pack()
	require.NoError(t, err)

	dialer := &recordingDialer{answer: answer}
	transport := newAssignedDNSTransport(logger.NOP(), dialer, "test")
	// No DoH client published, and no encrypted transport advertised either, so UDP is
	// the only transport the resolver offers.
	transport.apply(oneConfiguration(udpAssignment(t, "2001:db8::53")), nil)

	resolved, err := transport.Exchange(context.Background(), query)
	require.NoError(t, err)
	require.Equal(t, 1, dialer.dials)
	require.Len(t, resolved.Answer, 1)
	require.Equal(t, "udp", dialer.network, "the fallback must be UDP through the tunnel device")
	_ = packed
}

// TestAssignedDNSDoHRejectsNonSuccessStatus makes sure a DoH error is an error.
//
// A DoH server answering an HTTP error is not a DNS answer, and treating its body as one
// would produce a decode failure at best and a bogus resolution at worst.
func TestAssignedDNSDoHRejectsNonSuccessStatus(t *testing.T) {
	t.Parallel()

	query := new(mDNS.Msg)
	query.SetQuestion("status.example.test.", mDNS.TypeAAAA)
	client := &countingDoHClient{status: http.StatusForbidden}
	transport := newDoHTransport(t, client, dohAssignment(t, "/dns-query", "2001:db8::53"))

	_, err := transport.Exchange(context.Background(), query)
	require.Error(t, err)
	require.Contains(t, err.Error(), "403",
		"the failure must report the status so the cause is diagnosable")
}

// TestAssignedDNSDoHRejectsMalformedBody proves a body that is not a DNS message is
// refused rather than passed through.
func TestAssignedDNSDoHRejectsMalformedBody(t *testing.T) {
	t.Parallel()

	query := new(mDNS.Msg)
	query.SetQuestion("malformed.example.test.", mDNS.TypeAAAA)
	client := &countingDoHClient{response: []byte("this is not a dns message")}
	transport := newDoHTransport(t, client, dohAssignment(t, "/dns-query", "2001:db8::53"))

	_, err := transport.Exchange(context.Background(), query)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode DoH response")
}

// TestAssignedDNSDoHRespectsCancellation ensures an abandoned query does not hang: the
// caller's context must reach the round tripper.
func TestAssignedDNSDoHRespectsCancellation(t *testing.T) {
	t.Parallel()

	query := new(mDNS.Msg)
	query.SetQuestion("cancel.example.test.", mDNS.TypeAAAA)
	ctx, cancel := context.WithCancel(context.Background())
	client := &countingDoHClient{
		response: dohTestAnswer(t, query, "2001:db8::8"),
		beforeAnswer: func() {
			cancel()
		},
	}
	transport := newDoHTransport(t, client, dohAssignment(t, "/dns-query", "2001:db8::53"))

	_, err := transport.Exchange(ctx, query)
	require.ErrorIs(t, err, context.Canceled,
		"cancellation must surface as cancellation, not as a DoH failure")
}

// TestAssignedDNSDoHNeverUsesHostSocketWhenDialerFails is the leak test.
//
// The dialer represents the tunnel device and is made to fail. Even then the transport must
// not resolve: there is no path in this type that reaches the host resolver, and this test
// pins that a broken tunnel produces a failure rather than a fallback.
func TestAssignedDNSDoHNeverUsesHostSocketWhenDialerFails(t *testing.T) {
	t.Parallel()

	query := new(mDNS.Msg)
	query.SetQuestion("leak.example.test.", mDNS.TypeAAAA)
	dialer := &recordingDialer{fail: true}
	transport := newAssignedDNSTransport(logger.NOP(), dialer, "test")
	// No encrypted transport advertised, so the UDP path is taken and fails.
	transport.apply(oneConfiguration(udpAssignment(t, "2001:db8::53")), nil)

	_, err := transport.Exchange(context.Background(), query)
	require.Error(t, err)
	require.ErrorIs(t, err, errTestDialFailed)
	require.Equal(t, 1, dialer.dials)
}

// TestAssignedDNSDoHPathDefaultsAndNormalisation pins the dohpath handling, because a
// template that is not stripped produces a request to a literal "{?dns}" path.
func TestAssignedDNSDoHPathDefaultsAndNormalisation(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name     string
		template string
		expected string
	}{
		{name: "placeholder stripped", template: "/dns-query{?dns}", expected: "/dns-query"},
		{name: "no placeholder", template: "/dns-query", expected: "/dns-query"},
		{name: "empty falls back to the conventional path", template: "", expected: "/dns-query"},
		{name: "missing leading slash is added", template: "resolve", expected: "/resolve"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, testCase.expected, dohPathTemplate(testCase.template))
		})
	}
}

// TestAssignedDNSDoHPortSelection pins the port a DoH request is addressed to.
//
// The dohpath is an HTTP resource, so its default is 443; the assignment's plain DNS port
// default of 53 would send HTTPS to the DNS port.
func TestAssignedDNSDoHPortSelection(t *testing.T) {
	t.Parallel()

	require.Equal(t, uint16(443), (assignedResolverEndpoint{dohPath: "/dns-query"}).dohPort(),
		"a DoH resource defaults to the HTTPS port")
	require.Equal(t, uint16(8443), (assignedResolverEndpoint{dohPath: "/dns-query", port: 8443}).dohPort(),
		"an advertised port must override the default")
	require.Equal(t, uint16(0), (assignedResolverEndpoint{}).dohPort(),
		"without a dohpath there is no DoH port to report")
	// The plain DNS default is a different question from the DoH one, which is why the two
	// are separate methods rather than one shared accessor.
	require.Equal(t, uint16(53), (assignedResolverEndpoint{}).dnsPort())
	require.Equal(t, uint16(5353), (assignedResolverEndpoint{port: 5353}).dnsPort())
}

// TestAssignedDNSDoHErrorBodyIsBounded proves a huge error body cannot be quoted wholesale
// into an error message.
func TestAssignedDNSDoHErrorBodyIsBounded(t *testing.T) {
	t.Parallel()

	require.Empty(t, formatDoHErrorDetail(nil))
	require.Empty(t, formatDoHErrorDetail([]byte("   \n")))
	require.Equal(t, ": denied", formatDoHErrorDetail([]byte("  denied \n")))

	long := strings.Repeat("x", 4096)
	formatted := formatDoHErrorDetail([]byte(long))
	require.Less(t, len(formatted), 300,
		"a large body must be truncated rather than embedded whole in the error")
	require.Contains(t, formatted, "...")
}
