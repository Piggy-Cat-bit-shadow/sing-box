package group

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// End-to-end tests for the request/identity split through the automatic group path.
//
// # The defect these pin
//
// Measure separates RequestURL (what is fetched), ScopeURL (the health identity) and Destination
// (what is dialled). The group path undid that separation: it stored `scope.URL` as its link, and
// URLTestOutboundsWithTarget then did `link = scope.URL` before measuring. The canonical form
// therefore became the request target, so a group configured with
//
//	https://EXAMPLE.com:443/a?z=1&a=2
//
// fetched the canonicalised spelling instead of what the operator wrote.
//
// The assertion is on what a REAL server received, driven through the whole chain:
//
//	URLTestGroup -> URLTestOutboundsWithTarget -> Measure -> HTTP server
//
// Testing ParseMeasurementTarget alone would not catch this, because the helper was already correct;
// it was the group that discarded its result.

// observingOutbound dials a real target and records the request authority it was asked to reach.
type observingOutbound struct {
	adapter.Outbound
	tag string

	access  sync.Mutex
	dialed  []string
	dialNum int
}

func (o *observingOutbound) Type() string      { return "observing" }
func (o *observingOutbound) Tag() string       { return o.tag }
func (o *observingOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *observingOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.access.Lock()
	o.dialed = append(o.dialed, destination.String())
	o.dialNum++
	o.access.Unlock()

	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (o *observingOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}

func (o *observingOutbound) lastDial() string {
	o.access.Lock()
	defer o.access.Unlock()
	if len(o.dialed) == 0 {
		return ""
	}
	return o.dialed[len(o.dialed)-1]
}

// recordedRequest is what a server observed.
type recordedRequest struct {
	Host       string
	RequestURI string
	Path       string
	RawQuery   string
}

// recordingServer is a real HTTP server capturing what it received.
type recordingServer struct {
	address string

	access   sync.Mutex
	requests []recordedRequest
	ready    chan struct{}
	once     sync.Once
}

func newRecordingServer(t *testing.T) *recordingServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &recordingServer{address: listener.Addr().String(), ready: make(chan struct{})}

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go server.serve(conn)
		}
	}()

	t.Cleanup(func() { listener.Close() })
	return server
}

// serve reads one HTTP request and answers 204.
func (s *recordingServer) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buffer := make([]byte, 4096)
	total := 0
	for {
		read, err := conn.Read(buffer[total:])
		if read > 0 {
			total += read
			if containsHeaderEnd(buffer[:total]) {
				break
			}
		}
		if err != nil {
			return
		}
	}

	raw := string(buffer[:total])
	recorded := parseRequestLine(raw)
	recorded.Host = headerValue(raw, "Host")
	s.access.Lock()
	s.requests = append(s.requests, recorded)
	s.access.Unlock()
	s.once.Do(func() { close(s.ready) })

	// Answer with a HEAD response, since the measurement sends HEAD.
	_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"))
}

func containsHeaderEnd(data []byte) bool {
	for index := 0; index+3 < len(data); index++ {
		if data[index] == '\r' && data[index+1] == '\n' && data[index+2] == '\r' && data[index+3] == '\n' {
			return true
		}
	}
	return false
}

func parseRequestLine(raw string) recordedRequest {
	line := raw
	for index := 0; index < len(raw); index++ {
		if raw[index] == '\r' {
			line = raw[:index]
			break
		}
	}
	var method, uri, version string
	fields := splitFields(line)
	if len(fields) > 0 {
		method = fields[0]
	}
	if len(fields) > 1 {
		uri = fields[1]
	}
	if len(fields) > 2 {
		version = fields[2]
	}
	_ = method
	_ = version

	path, query := uri, ""
	for index := 0; index < len(uri); index++ {
		if uri[index] == '?' {
			path, query = uri[:index], uri[index+1:]
			break
		}
	}
	return recordedRequest{RequestURI: uri, Path: path, RawQuery: query}
}

// headerValue extracts a header from a raw request, case-insensitively.
func headerValue(raw string, name string) string {
	lines := splitLines(raw)
	for _, line := range lines {
		colon := -1
		for index := 0; index < len(line); index++ {
			if line[index] == ':' {
				colon = index
				break
			}
		}
		if colon < 0 {
			continue
		}
		if !equalFold(line[:colon], name) {
			continue
		}
		value := line[colon+1:]
		for len(value) > 0 && value[0] == ' ' {
			value = value[1:]
		}
		return value
	}
	return ""
}

func splitLines(raw string) []string {
	var lines []string
	current := ""
	for index := 0; index < len(raw); index++ {
		if raw[index] == '\n' {
			lines = append(lines, current)
			current = ""
			continue
		}
		if raw[index] != '\r' {
			current += string(raw[index])
		}
	}
	lines = append(lines, current)
	return lines
}

func equalFold(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := 0; index < len(left); index++ {
		a, b := left[index], right[index]
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

func splitFields(line string) []string {
	var fields []string
	current := ""
	for index := 0; index < len(line); index++ {
		if line[index] == ' ' {
			if current != "" {
				fields = append(fields, current)
				current = ""
			}
			continue
		}
		current += string(line[index])
	}
	if current != "" {
		fields = append(fields, current)
	}
	return fields
}

func (s *recordingServer) firstRequest() (recordedRequest, bool) {
	s.access.Lock()
	defer s.access.Unlock()
	if len(s.requests) == 0 {
		return recordedRequest{}, false
	}
	return s.requests[0], true
}

// TestGroupMeasurementUsesRequestURLNotScopeURL is the release blocker for problem 1.
//
// The group is configured with a target whose request spelling differs from its canonical identity.
// What the server receives must be the spelling that was configured.
func TestGroupMeasurementUsesRequestURLNotScopeURL(t *testing.T) {
	server := newRecordingServer(t)

	// The request spelling carries a NON-default port and a query whose order must survive.
	link := "http://127.0.0.1:" + portOf(t, server.address) + "/a?z=1&a=2"

	outbound := &observingOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, link, outbound)

	group.CheckOutbounds(group.ctx, true)

	select {
	case <-server.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the group never reached the server")
	}

	request, loaded := server.firstRequest()
	require.True(t, loaded)
	require.Equal(t, "/a", request.Path,
		"the path must be the one configured, not a canonicalised rewrite")
	require.Equal(t, "z=1&a=2", request.RawQuery,
		"the query must arrive in the order it was configured; canonicalising it for the health "+
			"identity must not reorder the request")

	// And the identity is the canonical form.
	require.Equal(t, link, group.scope.URL,
		"the health identity stays the canonical ScopeURL")
}

// TestGroupMeasurementPreservesExplicitDefaultPort is §7.
//
// A group configured with the default port written out explicitly, and a host in mixed case, must
// still REQUEST what was written. Only the identity is canonicalised.
func TestGroupMeasurementPreservesExplicitDefaultPort(t *testing.T) {
	server := newRecordingServer(t)

	port := portOf(t, server.address)
	// Upper-case host and explicit non-default port: the request must keep both spellings.
	link := "http://LOCALHOST:" + port + "/mixed/Case?B=2&a=1"

	outbound := &observingOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, link, outbound)

	// The identity must be canonicalised...
	require.Equal(t, "http://localhost:"+port+"/mixed/Case?B=2&a=1", group.scope.URL,
		"the health identity lowercases the host")

	// ...while the request keeps the configured spelling.
	require.Equal(t, link, group.link,
		"the group must keep the ORIGINAL request target; storing scope.URL here is what made the "+
			"automatic path fetch a rewritten request")

	group.CheckOutbounds(group.ctx, true)

	select {
	case <-server.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the group never reached the server")
	}

	request, loaded := server.firstRequest()
	require.True(t, loaded)
	require.Equal(t, "/mixed/Case", request.Path,
		"the path case must be preserved; it is part of the request")
	require.Equal(t, "B=2&a=1", request.RawQuery,
		"the query order must be preserved")
	require.Equal(t, "LOCALHOST:"+port, request.Host,
		"the Host header must be the spelling that was configured. Scope canonicalisation "+
			"lowercases the host for IDENTITY, and the group path was feeding that canonical form "+
			"back in as the request target - so the server saw a different authority than the one "+
			"the operator wrote")
}

// TestGroupDialTargetIsTheResolvedDestination checks the dial still carries the port.
func TestGroupDialTargetIsTheResolvedDestination(t *testing.T) {
	server := newRecordingServer(t)
	port := portOf(t, server.address)

	outbound := &observingOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, "http://127.0.0.1:"+port+"/a", outbound)

	group.CheckOutbounds(group.ctx, true)

	require.Eventually(t, func() bool { return outbound.lastDial() != "" },
		5*time.Second, 5*time.Millisecond)
	require.Equal(t, "127.0.0.1:"+port, outbound.lastDial(),
		"the dial target is the resolved destination, independent of the request spelling")
}

func portOf(t *testing.T, address string) string {
	t.Helper()
	for index := len(address) - 1; index >= 0; index-- {
		if address[index] == ':' {
			return address[index+1:]
		}
	}
	t.Fatalf("no port in %q", address)
	return ""
}
