package jiejie_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Controlled DNS server
//
// The DNS rebinding scenarios must not depend on public DNS. This server
// answers from a scripted sequence so a name can resolve to an allowed address
// on the first query and a forbidden one afterwards, in a controlled order.
// ---------------------------------------------------------------------------

type scriptedDNS struct {
	conn      *net.UDPConn
	sequence  map[string][]net.IP // name -> answers, last entry repeats
	queries   atomic.Int64
	answersOf sync.Map // name -> *atomic.Int64 (index consumed)
}

func startScriptedDNS(t *testing.T, script map[string][]net.IP) (*scriptedDNS, string) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	server := &scriptedDNS{conn: conn, sequence: script}
	t.Cleanup(func() { _ = conn.Close() })
	go server.serve()
	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	require.NoError(t, err)
	return server, port
}

func (s *scriptedDNS) nextIndex(name string) int {
	value, _ := s.answersOf.LoadOrStore(name, &atomic.Int64{})
	return int(value.(*atomic.Int64).Add(1)) - 1
}

func (s *scriptedDNS) serve() {
	buffer := make([]byte, 1500)
	for {
		n, addr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		s.queries.Add(1)
		response := s.buildResponse(buffer[:n])
		if response != nil {
			_, _ = s.conn.WriteToUDP(response, addr)
		}
	}
}

// buildResponse produces a minimal A/AAAA response. It deliberately does NOT
// implement compression pointers beyond the name echo, which is all the client
// needs to parse it.
func (s *scriptedDNS) buildResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	name, offset, ok := parseDNSName(query, 12)
	if !ok || offset+4 > len(query) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[offset : offset+2])

	answers, scripted := s.sequence[name]
	if !scripted {
		return nil // let the client treat it as NXDOMAIN-ish / no answer
	}
	index := s.nextIndex(name)
	if index >= len(answers) {
		index = len(answers) - 1
	}
	answer := answers[index]

	wantType := uint16(1)
	if answer.To4() == nil {
		wantType = 28
	}
	if qtype != wantType {
		// The scripted address family does not match the query: answer empty.
		return s.emptyResponse(query, offset, qtype)
	}

	header := make([]byte, 12)
	copy(header, query[:2]) // transaction id
	header[2] = 0x81        // QR + RD
	header[3] = 0x80        // RA
	header[5] = 0x01        // ANCOUNT = 1
	binary.BigEndian.PutUint16(header[6:8], 1)

	body := append([]byte{}, query[12:offset+4]...) // question section
	body = append(body, 0xC0, 0x0C)                 // name pointer to offset 12
	record := make([]byte, 10)
	binary.BigEndian.PutUint16(record[0:2], wantType)
	binary.BigEndian.PutUint16(record[2:4], 1) // IN
	binary.BigEndian.PutUint32(record[4:8], 1) // TTL 1s so it can change
	recordTypeLen := 4
	if wantType == 28 {
		recordTypeLen = 16
	}
	binary.BigEndian.PutUint16(record[8:10], uint16(recordTypeLen))
	body = append(body, record...)
	if wantType == 1 {
		body = append(body, answer.To4()...)
	} else {
		body = append(body, answer.To16()...)
	}
	return append(header, body...)
}

func (s *scriptedDNS) emptyResponse(query []byte, offset int, qtype uint16) []byte {
	header := make([]byte, 12)
	copy(header, query[:2])
	header[2] = 0x81
	header[3] = 0x80
	binary.BigEndian.PutUint16(header[6:8], 0)
	body := append([]byte{}, query[12:offset+4]...)
	return append(header, body...)
}

func parseDNSName(message []byte, offset int) (string, int, bool) {
	var builder strings.Builder
	for {
		if offset >= len(message) {
			return "", 0, false
		}
		length := int(message[offset])
		offset++
		if length == 0 {
			break
		}
		if length&0xC0 != 0 {
			return "", 0, false
		}
		if offset+length > len(message) {
			return "", 0, false
		}
		builder.Write(message[offset : offset+length])
		builder.WriteByte('.')
		offset += length
	}
	return strings.TrimSuffix(builder.String(), "."), offset, true
}

// ---------------------------------------------------------------------------
// Counting origin
// ---------------------------------------------------------------------------

type countingOrigin struct {
	addr      string
	conns     atomic.Int64
	packets   atomic.Int64
	tcpServer net.Listener
	udpServer net.PacketConn
}

// startCountingTCPOrigin accepts TCP and counts every accepted connection.
func startCountingTCPOrigin(t *testing.T) *countingOrigin {
	t.Helper()
	return startTCPOriginOn(t, "127.0.0.1:0")
}

// startCountingUDPOrigin counts every datagram it receives on loopback.
func startCountingUDPOrigin(t *testing.T) *countingOrigin {
	t.Helper()
	return startUDPOriginOn(t, "127.0.0.1:0")
}

// startUDPOriginOn counts every datagram it receives on a specific address.
func startUDPOriginOn(t *testing.T, address string) *countingOrigin {
	t.Helper()
	conn, err := net.ListenPacket("udp", address)
	require.NoError(t, err)
	origin := &countingOrigin{addr: conn.LocalAddr().String(), udpServer: conn}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, addr, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			origin.packets.Add(1)
			_, _ = conn.WriteTo([]byte("pong"), addr)
			_ = n
		}
	}()
	return origin
}

func (o *countingOrigin) port() uint16 {
	_, port, err := net.SplitHostPort(o.addr)
	if err != nil {
		return 0
	}
	value, _ := strconv.Atoi(port)
	return uint16(value)
}

// ---------------------------------------------------------------------------
// Instance builder
// ---------------------------------------------------------------------------

type aclInstance struct {
	port       uint16
	dnsPort    string
	dnsServer  *scriptedDNS
	tcpOrigin  *countingOrigin
	udpOrigin  *countingOrigin
	rejectList []string
}

// startACLInstance builds a Naive inbound whose route rejects the given CIDRs,
// resolving domain targets first. The resolve rule placement is the thing under
// test, so it is a parameter.
func startACLInstance(t *testing.T, rejectCIDRs []string, withResolve bool) *aclInstance {
	t.Helper()
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")

	tcpOrigin := startCountingTCPOrigin(t)
	udpOrigin := startCountingUDPOrigin(t)

	// "forbidden.test" resolves to loopback (a service that must stay out of
	// reach); "allowed.test" resolves to a public address.
	dnsServer, dnsPort := startScriptedDNS(t, map[string][]net.IP{
		"forbidden.test": {net.IPv4(127, 0, 0, 1)},
		"rebind.test":    {net.IPv4(93, 184, 216, 34), net.IPv4(127, 0, 0, 1)},
		"allowed.test":   {net.IPv4(93, 184, 216, 34)},
	})

	port := reserveTCPPort(t)

	rules := []string{}
	if withResolve {
		rules = append(rules, `{"action": "resolve"}`)
	}
	rules = append(rules, `{"ip_cidr": [`+quotedCIDRs(rejectCIDRs)+`], "action": "reject"}`)

	config := `{
		"log": {"level": "debug"},
		"dns": {
			"servers": [{"tag": "scripted", "type": "udp", "server": "127.0.0.1", "server_port": ` + dnsPort + `}],
			"final": "scripted",
			"strategy": "ipv4_only",
			"independent_cache": true
		},
		"inbounds": [{
			"type": "naive",
			"tag": "naive-in",
			"listen": "127.0.0.1",
			"listen_port": ` + strconv.Itoa(int(port)) + `,
			"network": "tcp",
			"users": [{"username": "` + naiveTestUser + `", "password": "` + naiveTestPassword + `"}],
			"tls": {
				"enabled": true,
				"server_name": "naive.test",
				"certificate_path": "` + certPem + `",
				"key_path": "` + keyPem + `"
			}
		}],
		"outbounds": [{"type": "direct", "tag": "direct", "domain_resolver": "scripted"}],
		"route": {
			"rules": [` + strings.Join(rules, ",") + `],
			"final": "direct"
		}
	}`

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)

	return &aclInstance{
		port:       port,
		dnsPort:    dnsPort,
		dnsServer:  dnsServer,
		tcpOrigin:  tcpOrigin,
		udpOrigin:  udpOrigin,
		rejectList: rejectCIDRs,
	}
}

func defaultRejectCIDRs() []string {
	return []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "0.0.0.0/8",
		"::1/128", "fc00::/7", "fe80::/10", "::/128",
	}
}

// ---------------------------------------------------------------------------
// TCP: domain targets must not slip past the IP rules
// ---------------------------------------------------------------------------

// TestJiejieTargetACLDirectIPIsRejected is the baseline: a literal loopback address
// is refused, proving the rule itself works.
func TestJiejieTargetACLDirectIPIsRejected(t *testing.T) {
	env := startACLInstance(t, defaultRejectCIDRs(), true)
	origin := startCountingTCPOrigin(t)

	conn := naiveTLSConn(t, env.port)
	response, err := naiveWriteConnect(t, conn, origin.addr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})

	reached := probeTunnelStillReaches(t, conn, response, err)
	require.False(t, reached, "a literal loopback CONNECT target must be refused")
	require.EqualValues(t, 0, origin.conns.Load(),
		"the refused origin must never see a TCP connection")
}

// TestJiejieTargetACLDomainTargetResolvesToRejectedIP is the core of the reported
// bug: a DOMAIN that resolves to loopback must be refused exactly like the
// literal address.
func TestJiejieTargetACLDomainTargetResolvesToRejectedIP(t *testing.T) {
	env := startACLInstance(t, defaultRejectCIDRs(), true)

	conn := naiveTLSConn(t, env.port)
	response, err := naiveWriteConnect(t, conn, "forbidden.test:80", map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})

	reached := probeTunnelStillReaches(t, conn, response, err)
	require.False(t, reached,
		"CONNECT forbidden.test:80 resolves to 127.0.0.1 and must be refused")
}

// TestJiejieTargetACLDomainTargetWithoutResolveRule measures what a resolve action is
// actually buying.
//
// A "not reached" result here would be worthless on its own, because the domain
// might simply have failed to resolve. The test therefore first proves that a
// domain target IS resolvable and reachable in this very instance (via a name
// pointing at the allowed origin), and only then checks the forbidden name.
func TestJiejieTargetACLDomainTargetWithoutResolveRule(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")

	// "ok.test" points at a real reachable origin; "forbidden.test" at loopback.
	allowedOrigin := startCountingTCPOrigin(t)
	forbiddenOrigin := startCountingTCPOrigin(t)
	allowedHost, _, err := net.SplitHostPort(allowedOrigin.addr)
	require.NoError(t, err)

	dnsServer, dnsPort := startScriptedDNS(t, map[string][]net.IP{
		"forbidden.test": {net.IPv4(127, 0, 0, 1)},
		"ok.test":        {net.ParseIP(allowedHost)},
	})

	port := reserveTCPPort(t)
	// NO resolve action: only the ip_cidr reject rule is present.
	config := `{
		"log": {"level": "debug"},
		"dns": {
			"servers": [{"tag": "scripted", "type": "udp", "server": "127.0.0.1", "server_port": ` + dnsPort + `}],
			"final": "scripted",
			"strategy": "ipv4_only",
			"independent_cache": true
		},
		"inbounds": [{
			"type": "naive",
			"tag": "naive-in",
			"listen": "127.0.0.1",
			"listen_port": ` + strconv.Itoa(int(port)) + `,
			"network": "tcp",
			"users": [{"username": "` + naiveTestUser + `", "password": "` + naiveTestPassword + `"}],
			"tls": {
				"enabled": true,
				"server_name": "naive.test",
				"certificate_path": "` + certPem + `",
				"key_path": "` + keyPem + `"
			}
		}],
		"outbounds": [{"type": "direct", "tag": "direct", "domain_resolver": "scripted"}],
		"route": {
			"rules": [{"ip_cidr": ["127.0.0.0/8"], "action": "reject"}],
			"final": "direct"
		}
	}`

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)

	// Control 1: a domain target that must be allowed really is reachable, so
	// name resolution and the tunnel both work in this instance.
	control := naiveTLSConn(t, port)
	controlResponse, controlErr := naiveWriteConnect(t, control, "ok.test:"+strconv.Itoa(int(allowedOrigin.port())), map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	controlReached := probeTunnelStillReaches(t, control, controlResponse, controlErr)
	require.True(t, controlReached,
		"the sanity control must prove domain targets resolve and connect here, "+
			"otherwise the forbidden-domain result below proves nothing")
	t.Logf("control: domain ok.test reached=%v queries=%d",
		controlReached, dnsServer.queries.Load())

	// Control 2: the forbidden domain. Its address is loopback, which the rule
	// rejects - but with no resolve action the rule has no address to match.
	conn := naiveTLSConn(t, port)
	response, err := naiveWriteConnect(t, conn, "forbidden.test:"+strconv.Itoa(int(forbiddenOrigin.port())), map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	reached := probeTunnelStillReaches(t, conn, response, err)
	t.Logf("without a resolve action, CONNECT forbidden.test reached=%v, "+
		"forbidden origin connections=%d", reached, forbiddenOrigin.conns.Load())

	if reached {
		t.Logf("CONFIRMED: with no resolve action an ip_cidr rule does not apply " +
			"to a domain target, so the request reaches a loopback service")
	} else {
		t.Logf("NOT REPRODUCED here: the domain form was also refused; the " +
			"resolve action is still required for correctness but this test did " +
			"not observe a bypass")
	}
}

// TestJiejieTargetACLRebindingCannotBypass covers the check/dial consistency gap:
// the same name first resolves to an allowed address (so the rule passes) and
// only later to a forbidden one. Whatever the caching layer does, the address
// actually dialled must satisfy the policy.
func TestJiejieTargetACLRebindingCannotBypass(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")

	// The "allowed" answer is a REAL reachable origin, chosen from OUTSIDE the
	// rejected CIDRs. The reject list itself stays intact, so phase 1 proves
	// the name is genuinely routable while phase 2 still faces the full policy.
	//
	// This matters: on many machines the LAN address is itself inside 172.16/12
	// or 10/8, and using it blindly would make the allowed phase fail for
	// reasons unrelated to the behaviour under test.
	// The reject list for THIS test is deliberately narrow - it rejects only
	// loopback plus the specific family being exercised - so a reachable
	// allowed address exists on any machine. The policy being tested (does a
	// rebound name get re-checked at dial time) does not depend on the list
	// being long, only on it correctly covering the second answer.
	rebindReject := []string{"127.0.0.0/8", "::1/128"}
	allowedAddress := lanAddressOutside(t, rebindReject)
	allowedOrigin := startTCPOriginOn(t, net.JoinHostPort(allowedAddress.String(), "0"))
	forbiddenOrigin := startCountingTCPOrigin(t)

	dnsServer, dnsPort := startScriptedDNS(t, map[string][]net.IP{
		"rebind.test": {allowedAddress, net.IPv4(127, 0, 0, 1)},
	})

	port := reserveTCPPort(t)
	config := `{
		"log": {"level": "debug"},
		"dns": {
			"servers": [{"tag": "scripted", "type": "udp", "server": "127.0.0.1", "server_port": ` + dnsPort + `}],
			"final": "scripted",
			"strategy": "ipv4_only",
			"independent_cache": true
		},
		"inbounds": [{
			"type": "naive",
			"tag": "naive-in",
			"listen": "127.0.0.1",
			"listen_port": ` + strconv.Itoa(int(port)) + `,
			"network": "tcp",
			"users": [{"username": "` + naiveTestUser + `", "password": "` + naiveTestPassword + `"}],
			"tls": {
				"enabled": true,
				"server_name": "naive.test",
				"certificate_path": "` + certPem + `",
				"key_path": "` + keyPem + `"
			}
		}],
		"outbounds": [{"type": "direct", "tag": "direct", "domain_resolver": "scripted"}],
		"route": {
			"rules": [
				{"action": "resolve"},
				{"ip_cidr": [` + quotedCIDRs(rebindReject) + `], "action": "reject"}
			],
			"final": "direct"
		}
	}`

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)

	// Phase 1: the name resolves to the allowed LAN address and the tunnel must
	// genuinely reach the origin. This proves the name itself is routable, so a
	// later refusal is a policy decision, not a transport failure.
	first := naiveTLSConn(t, port)
	firstResponse, firstErr := naiveWriteConnect(t, first, "rebind.test:"+strconv.Itoa(int(allowedOrigin.port())), map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	firstReached := probeTunnelStillReaches(t, first, firstResponse, firstErr)
	require.True(t, firstReached,
		"the first resolution answers with an allowed address and must reach the origin")
	require.EqualValues(t, 1, allowedOrigin.conns.Load())
	t.Logf("rebind.test first resolution (allowed address) reached=%v queries=%d",
		firstReached, dnsServer.queries.Load())

	// Phase 2: the same name now resolves to loopback. It must be refused even
	// though this exact name was just allowed.
	//
	// The DNS cache would otherwise serve the first answer again, which would
	// make this test vacuous - it would only prove the cached ALLOWED address
	// is still allowed. Clearing the cache forces a real second resolution so
	// the rebound (forbidden) answer is what the router actually sees.
	service.FromContext[adapter.DNSRouter](globalCtx).ClearCache()
	t.Logf("flushed DNS cache to force a genuine rebind")

	second := naiveTLSConn(t, port)
	secondResponse, secondErr := naiveWriteConnect(t, second, "rebind.test:"+strconv.Itoa(int(forbiddenOrigin.port())), map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	secondReached := probeTunnelStillReaches(t, second, secondResponse, secondErr)
	t.Logf("rebind.test second resolution (loopback) reached=%v queries=%d",
		secondReached, dnsServer.queries.Load())

	require.False(t, secondReached,
		"after the name rebinds to loopback the request must be refused")
	require.EqualValues(t, 0, forbiddenOrigin.conns.Load(),
		"the loopback origin must never receive a TCP connection")
}

func quotedCIDRs(cidrs []string) string {
	quoted := make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		quoted = append(quoted, `"`+cidr+`"`)
	}
	return strings.Join(quoted, ",")
}

// lanAddress returns a host IPv4 address that is REACHABLE but lies OUTSIDE
// the rejected CIDRs, so it can serve as the "allowed" phase of a test.
//
// This matters: on many machines the LAN address is itself inside 172.16/12 or
// 10/8, so blindly using it would make the "allowed" phase fail for reasons
// that have nothing to do with the behaviour under test.
func lanAddressOutside(t *testing.T, rejected []string) net.IP {
	t.Helper()
	var rejectedPrefixes []netip.Prefix
	for _, cidr := range rejected {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		rejectedPrefixes = append(rejectedPrefixes, prefix)
	}
	interfaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}
			address, ok := netip.AddrFromSlice(ip4)
			if !ok {
				continue
			}
			if slices.ContainsFunc(rejectedPrefixes, func(prefix netip.Prefix) bool {
				return prefix.Contains(address)
			}) {
				continue
			}
			return ip4
		}
	}
	t.Skip("no reachable non-loopback IPv4 address outside the rejected CIDRs " +
		"is available on this machine")
	return nil
}

// startTCPOriginOn starts a counting HTTP origin on a specific local address.
func startTCPOriginOn(t *testing.T, address string) *countingOrigin {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	require.NoError(t, err)
	origin := &countingOrigin{addr: listener.Addr().String(), tcpServer: listener}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			origin.conns.Add(1)
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				reader := bufio.NewReader(conn)
				_, _ = reader.ReadString('\n')
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\norigin-ok"))
			}()
		}
	}()
	return origin
}

// TestJiejieTargetACLPublicStillWorks is the non-regression control: ordinary public
// destinations must remain reachable.
func TestJiejieTargetACLPublicStillWorks(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")

	dnsServer, dnsPort := startScriptedDNS(t, map[string][]net.IP{
		"allowed.test": {net.IPv4(127, 0, 0, 1)},
	})
	_ = dnsServer

	// The origin stands in for a public server; the rule only rejects the
	// loopback CIDR, so this test uses a rule that does NOT cover it to prove
	// allowed traffic flows while the same instance rejects other traffic.
	origin := startCountingTCPOrigin(t)
	port := reserveTCPPort(t)

	config := `{
		"log": {"level": "debug"},
		"dns": {
			"servers": [{"tag": "scripted", "type": "udp", "server": "127.0.0.1", "server_port": ` + dnsPort + `}],
			"final": "scripted",
			"strategy": "ipv4_only",
			"independent_cache": true
		},
		"inbounds": [{
			"type": "naive",
			"tag": "naive-in",
			"listen": "127.0.0.1",
			"listen_port": ` + strconv.Itoa(int(port)) + `,
			"network": "tcp",
			"users": [{"username": "` + naiveTestUser + `", "password": "` + naiveTestPassword + `"}],
			"tls": {
				"enabled": true,
				"server_name": "naive.test",
				"certificate_path": "` + certPem + `",
				"key_path": "` + keyPem + `"
			}
		}],
		"outbounds": [{"type": "direct", "tag": "direct", "domain_resolver": "scripted"}],
		"route": {
			"rules": [
				{"action": "resolve"},
				{"ip_cidr": ["203.0.113.0/24"], "action": "reject"}
			],
			"final": "direct"
		}
	}`

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)

	conn := naiveTLSConn(t, port)
	response, err := naiveWriteConnect(t, conn, origin.addr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	reached := probeTunnelStillReaches(t, conn, response, err)
	require.True(t, reached,
		"a destination outside the rejected CIDRs must still be reachable")
	require.EqualValues(t, 1, origin.conns.Load())
}

// ---------------------------------------------------------------------------
// UoT: the real UDP target must be policed per datagram
// ---------------------------------------------------------------------------

// TestJiejieTargetACLUoTV1MultiTargetChecksEachDatagram is the highest risk case: a
// v1 session whose first datagram goes to an allowed target and whose second
// goes to a forbidden one. Allowing the first must not authorise the second.
func TestJiejieTargetACLUoTV1MultiTargetChecksEachDatagram(t *testing.T) {
	// Loopback is rejected; other addresses are not. This isolates the question
	// under test - is each datagram's OWN destination checked - from whether a
	// particular address is reachable.
	env := startACLInstance(t, []string{"127.0.0.0/8"}, true)
	forbiddenOrigin := startCountingUDPOrigin(t)
	allowedOrigin := startUDPOriginOn(t, net.JoinHostPort(lanAddressOutside(t, []string{"127.0.0.0/8"}).String(), "0"))

	conn := naiveTLSConn(t, env.port)
	magic := uot.RequestDestination(uot.Version).String()
	response := naiveWriteConnectOK(t, conn, magic, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	defer response.Body.Close()

	// The session header carries a reachable ALLOWED destination. This is the
	// essence of the v1 risk: the session is authorised on this address, but
	// every datagram carries its own destination.
	allowedTarget := metadata.ParseSocksaddr(allowedOrigin.addr)

	// The session address must itself pass the policy, so use an address the
	// rules allow to establish the session, then rely on per-datagram targets.
	sessionTarget := metadata.ParseSocksaddr("93.184.216.34:443")
	writer := &sliceWriter{}
	require.NoError(t, metadata.SocksaddrSerializer.WriteAddrPort(writer, sessionTarget))
	_, err := conn.Write(append([]byte{0}, writer.data...))
	require.NoError(t, err)

	// Datagram 1: to the allowed loopback-free target. This proves the session
	// is genuinely live, so the zero count later is not just a dead session.
	writeUoTDatagramToLoopback(t, conn, allowedTarget, []byte("first"))
	time.Sleep(300 * time.Millisecond)

	t.Logf("allowed datagram delivered=%d", allowedOrigin.packets.Load())
	require.EqualValues(t, 1, allowedOrigin.packets.Load(),
		"the datagram to an allowed destination must be delivered: this proves "+
			"the session is live and the check discriminates rather than "+
			"blocking every datagram")

	// Datagram 2: a DIFFERENT loopback port on the SAME session.
	forbiddenTarget := metadata.ParseSocksaddr("127.0.0.1:" + strconv.Itoa(int(forbiddenOrigin.port())))
	writeUoTDatagramToLoopback(t, conn, forbiddenTarget, []byte("second"))
	time.Sleep(500 * time.Millisecond)

	t.Logf("UoT v1: allowed loopback origin received %d, forbidden received %d",
		allowedOrigin.packets.Load(), forbiddenOrigin.packets.Load())

	require.EqualValues(t, 0, forbiddenOrigin.packets.Load(),
		"a datagram addressed to a different loopback port must not be delivered "+
			"even after an allowed datagram on the same UoT session")
}

// TestJiejieTargetACLUoTV2ConnectTargetIsChecked covers the v2 Connect form, where
// the session carries a single fixed destination.
func TestJiejieTargetACLUoTV2ConnectTargetIsChecked(t *testing.T) {
	env := startACLInstance(t, defaultRejectCIDRs(), true)
	forbiddenOrigin := startCountingUDPOrigin(t)

	conn := naiveTLSConn(t, env.port)
	magic := uot.RequestDestination(uot.Version).String()
	response := naiveWriteConnectOK(t, conn, magic, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	defer response.Body.Close()

	// v2 request header: isConnect byte followed by the address.
	target := metadata.ParseSocksaddr("127.0.0.1:" + strconv.Itoa(int(forbiddenOrigin.port())))
	writer := &sliceWriter{}
	require.NoError(t, metadata.SocksaddrSerializer.WriteAddrPort(writer, target))
	_, err := conn.Write(naivePaddingFrame(append([]byte{1}, writer.data...), 0))
	require.NoError(t, err)

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, 4)
	_, err = conn.Write(naivePaddingFrame(append(length, []byte("ping")...), 0))
	require.NoError(t, err)

	// A v2 connect session expects a CONNECT reply code before data flows; read
	// defensively and then wait for any leak.
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = conn.Read(make([]byte, 64))
	time.Sleep(300 * time.Millisecond)

	t.Logf("UoT v2 connect: forbidden origin received %d packets",
		forbiddenOrigin.packets.Load())
	require.EqualValues(t, 0, forbiddenOrigin.packets.Load(),
		"a v2 connect session to loopback must not deliver UDP")
}

// TestJiejieTargetACLUoTV2NonConnectMultiTarget covers v2 without connect, where the
// destination is encoded per datagram.
func TestJiejieTargetACLUoTV2NonConnectMultiTarget(t *testing.T) {
	env := startACLInstance(t, []string{"127.0.0.0/8"}, true)
	forbiddenOrigin := startCountingUDPOrigin(t)
	allowedOrigin := startUDPOriginOn(t, net.JoinHostPort(lanAddressOutside(t, []string{"127.0.0.0/8"}).String(), "0"))

	conn := naiveTLSConn(t, env.port)
	magic := uot.RequestDestination(uot.Version).String()
	response := naiveWriteConnectOK(t, conn, magic, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	defer response.Body.Close()

	// Non-connect v2: isConnect = 0, then a session address the rules allow.
	writer := &sliceWriter{}
	require.NoError(t, metadata.SocksaddrSerializer.WriteAddrPort(writer, metadata.ParseSocksaddr("93.184.216.34:443")))
	// Raw over HTTP/1, like the datagrams above.
	_, err := conn.Write(append([]byte{0}, writer.data...))
	require.NoError(t, err)

	// Positive control: a datagram to a REACHABLE address must be delivered,
	// otherwise the zero below would only prove the session is dead.
	allowedTarget := metadata.ParseSocksaddr(allowedOrigin.addr)
	writeUoTDatagramToLoopback(t, conn, allowedTarget, []byte("allowed"))
	time.Sleep(300 * time.Millisecond)
	t.Logf("v2 non-connect allowed datagram delivered=%d", allowedOrigin.packets.Load())
	require.EqualValues(t, 1, allowedOrigin.packets.Load(),
		"the datagram to an allowed destination must be delivered, proving the "+
			"guard discriminates instead of blocking everything")

	// Record the counts BEFORE the forbidden datagram so a later increment can
	// only have come from the forbidden one.
	allowedBefore := allowedOrigin.packets.Load()
	forbiddenBefore := forbiddenOrigin.packets.Load()

	target := metadata.ParseSocksaddr("127.0.0.1:" + strconv.Itoa(int(forbiddenOrigin.port())))
	writeUoTDatagramToLoopback(t, conn, target, []byte("nonconnect"))
	time.Sleep(500 * time.Millisecond)

	t.Logf("UoT v2 non-connect: allowed %d->%d, forbidden %d->%d",
		allowedBefore, allowedOrigin.packets.Load(),
		forbiddenBefore, forbiddenOrigin.packets.Load())
	require.EqualValues(t, 0, forbiddenOrigin.packets.Load(),
		"a v2 non-connect datagram to a different loopback port must not be delivered")
}

// writeUoTDatagramToLoopback frames one v1-style datagram: address, length,
// payload. The address is written with the UoT per-datagram codec.
func writeUoTDatagramToLoopback(t *testing.T, conn net.Conn, target metadata.Socksaddr, payload []byte) {
	t.Helper()
	body := make([]byte, 0, 32)
	body = appendUoTAddr(t, body, target)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	body = append(body, length...)
	body = append(body, payload...)
	// Written unwrapped: this helper drives an HTTP/1 tunnel, which is RAW in the
	// reference (serveHijack -> dualStream(..., false)). UoT's own address and
	// length prefixes are a separate layer and are preserved.
	_, err := conn.Write(body)
	require.NoError(t, err)
}

// appendUoTAddr encodes a per-datagram UoT destination.
func appendUoTAddr(t *testing.T, body []byte, target metadata.Socksaddr) []byte {
	t.Helper()
	var buffer bytes.Buffer
	require.NoError(t, uot.AddrParser.WriteAddrPort(&buffer, target))
	return append(body, buffer.Bytes()...)
}

// writeUoTDatagram frames one v1-style datagram: address, length, payload.
func writeUoTDatagram(t *testing.T, conn net.Conn, target metadata.Socksaddr, payload []byte) {
	t.Helper()
	writer := &sliceWriter{}
	require.NoError(t, metadata.SocksaddrSerializer.WriteAddrPort(writer, target))
	body := append([]byte{}, writer.data...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	body = append(body, length...)
	body = append(body, payload...)
	_, err := conn.Write(naivePaddingFrame(body, 0))
	require.NoError(t, err)
}

// probeTunnelStillReaches reports whether an established CONNECT tunnel really
// carries traffic to its destination. A refused route may still answer 200 and
// then close, so the status code alone is not evidence.
func probeTunnelStillReaches(t *testing.T, conn net.Conn, response *http.Response, err error) bool {
	t.Helper()
	if err != nil {
		return false
	}
	if response == nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false
	}

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	// RAW over HTTP/1. This helper drives H1 tunnels, and HTTP/1 is unframed in
	// the reference (serveHijack -> dualStream(..., false)); a Naive frame here
	// would be read by the server as arbitrary payload.
	_, writeErr := conn.Write(
		[]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	if writeErr != nil {
		return false
	}
	body, readErr := io.ReadAll(conn)
	if readErr != nil {
		return false
	}
	return strings.Contains(string(body), "origin-ok")
}

var _ = context.Background

// ---------------------------------------------------------------------------
// Server-internal connections must not be affected by the client target ACL
// ---------------------------------------------------------------------------

// TestJiejieTargetACLDoesNotBreakMasqueradeBackend is the guard against over-blocking.
//
// The Naive masquerade proxies ordinary web requests to a FIXED local backend
// (127.0.0.1:28437 in production). That connection is made by the server on its
// own behalf, not requested by the client, so the target ACL that rejects
// client-chosen loopback destinations must not interfere with it.
//
// This runs the real masquerade against a loopback decoy in an instance whose
// rules DO reject loopback for the Naive inbound, and asserts the decoy is
// still reached while a client CONNECT to the same loopback is refused.
func TestJiejieTargetACLDoesNotBreakMasqueradeBackend(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")

	// A decoy stands in for the production Web masquerade backend. It lives on
	// loopback, exactly like the real one at 127.0.0.1:28437.
	decoyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	decoyBackend := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "text/html")
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, "<html><body>DECOY</body></html>")
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = decoyBackend.Serve(decoyListener) }()
	t.Cleanup(func() { _ = decoyBackend.Close() })
	decoy := "http://" + decoyListener.Addr().String()
	clientOrigin := startCountingTCPOrigin(t)

	port := reserveTCPPort(t)
	config := `{
		"log": {"level": "debug"},
		"inbounds": [{
			"type": "naive",
			"tag": "naive-in",
			"listen": "127.0.0.1",
			"listen_port": ` + strconv.Itoa(int(port)) + `,
			"network": "tcp",
			"users": [{"username": "` + naiveTestUser + `", "password": "` + naiveTestPassword + `"}],
			"masquerade": {"type": "proxy", "url": "` + decoy + `", "rewrite_host": true},
			"tls": {
				"enabled": true,
				"server_name": "naive.test",
				"certificate_path": "` + certPem + `",
				"key_path": "` + keyPem + `"
			}
		}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {
			"rules": [
				{"inbound": ["naive-in"], "action": "resolve"},
				{"inbound": ["naive-in"], "ip_cidr": ["127.0.0.0/8"], "action": "reject"}
			],
			"final": "direct"
		}
	}`

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)

	// 1. An ordinary browser-shaped request must still be served by the decoy,
	//    even though the decoy lives on loopback which the rules reject.
	plainConn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 10*time.Second)
	require.NoError(t, err)
	tlsConn := tls.Client(plainConn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
	require.NoError(t, tlsConn.Handshake())
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = io.WriteString(tlsConn, "GET /probe HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	browserResponse, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	require.NoError(t, err, "the masquerade must still answer ordinary web traffic")
	body, _ := io.ReadAll(browserResponse.Body)
	_ = browserResponse.Body.Close()
	_ = plainConn.Close()
	require.Equal(t, http.StatusOK, browserResponse.StatusCode,
		"the masquerade backend on loopback must remain reachable by the server itself")
	t.Logf("masquerade served %d bytes from the loopback backend", len(body))

	// 2. The same loopback range must still be refused when the CLIENT asks for
	//    it as a proxy target, which is what the ACL exists to prevent.
	clientConn := naiveTLSConn(t, port)
	response, connectErr := naiveWriteConnect(t, clientConn, clientOrigin.addr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	reached := probeTunnelStillReaches(t, clientConn, response, connectErr)
	require.False(t, reached, "a client CONNECT to loopback must still be refused")
	require.EqualValues(t, 0, clientOrigin.conns.Load(),
		"the client-chosen loopback origin must never be connected to")
}

// ---------------------------------------------------------------------------
// IPv6 and IPv4-mapped forms
// ---------------------------------------------------------------------------

// TestJiejieTargetACLIPv6AndMappedFormsAreRejected verifies that the loops in the
// rules cannot be walked around by writing the same forbidden destination in a
// different but equivalent notation.
func TestJiejieTargetACLIPv6AndMappedFormsAreRejected(t *testing.T) {
	env := startACLInstance(t, []string{
		"::1/128", "fc00::/7", "fe80::/10", "127.0.0.0/8",
	}, true)

	for _, target := range []struct {
		name      string
		authority string
	}{
		{"IPv6 loopback", "[::1]:9"},
		{"IPv6 loopback expanded", "[0:0:0:0:0:0:0:1]:9"},
		{"IPv6 ULA", "[fd00::1]:9"},
		{"IPv6 link-local", "[fe80::1]:9"},
		{"IPv4-mapped loopback", "[::ffff:127.0.0.1]:9"},
	} {
		t.Run(target.name, func(t *testing.T) {
			conn := naiveTLSConn(t, env.port)
			response, err := naiveWriteConnect(t, conn, target.authority, map[string]string{
				"Proxy-Authorization": naiveBasicAuth(),
				"Padding":             "~~~~~~~~",
			})
			reached := probeTunnelStillReaches(t, conn, response, err)
			require.False(t, reached,
				"%s must be refused: it denotes a forbidden destination", target.name)
		})
	}
}

// TestJiejieTargetACLLoopbackIPv6UDPIsRejected covers the UDP side for IPv6, since the
// guard decides on the decoded datagram address rather than the session one.
func TestJiejieTargetACLLoopbackIPv6UDPIsRejected(t *testing.T) {
	env := startACLInstance(t, []string{"::1/128", "127.0.0.0/8"}, true)

	conn := naiveTLSConn(t, env.port)
	magic := uot.RequestDestination(uot.Version).String()
	response := naiveWriteConnectOK(t, conn, magic, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	defer response.Body.Close()

	writer := &sliceWriter{}
	require.NoError(t, metadata.SocksaddrSerializer.WriteAddrPort(writer, metadata.ParseSocksaddr("93.184.216.34:443")))
	// Raw over HTTP/1, like the datagrams above.
	_, err := conn.Write(append([]byte{0}, writer.data...))
	require.NoError(t, err)

	// A reachable allowed target proves the session works, so the IPv6 result
	// below is about the policy and not about a dead session.
	allowedOrigin := startUDPOriginOn(t, net.JoinHostPort(lanAddressOutside(t, []string{"::1/128", "127.0.0.0/8"}).String(), "0"))
	writeUoTDatagramToLoopback(t, conn, metadata.ParseSocksaddr(allowedOrigin.addr), []byte("allowed"))
	time.Sleep(300 * time.Millisecond)
	require.EqualValues(t, 1, allowedOrigin.packets.Load(),
		"the allowed datagram must be delivered, proving the session is live")

	// The forbidden IPv6 loopback datagram must be dropped by the guard. A real
	// IPv6 listener is bound so that a leak would be observed rather than
	// inferred from a connect failure.
	listener, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback is unavailable, so the leak cannot be observed")
	}
	var received atomic.Int64
	go func() {
		buffer := make([]byte, 512)
		for {
			if _, _, readErr := listener.ReadFrom(buffer); readErr != nil {
				return
			}
			received.Add(1)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })

	target := metadata.ParseSocksaddr(listener.LocalAddr().String())
	writeUoTDatagramToLoopback(t, conn, target, []byte("ipv6"))
	time.Sleep(500 * time.Millisecond)

	require.EqualValues(t, 0, received.Load(),
		"a datagram addressed to IPv6 loopback must not be delivered")
}

// ---------------------------------------------------------------------------
// The shipped production rule shape
// ---------------------------------------------------------------------------

// TestJiejieTargetACLProductionRuleShapeEnforces is the acceptance test for the
// configuration actually shipped in release/jiejie-production-topology.json.
//
// It reproduces that rule block verbatim (same CIDRs, same order, same inbound
// scoping) so the delivered config is verified by execution rather than by
// inspection, and checks a forbidden destination in both its literal and its
// domain form while confirming an allowed destination still works.
func TestJiejieTargetACLProductionRuleShapeEnforces(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")

	forbiddenOrigin := startCountingTCPOrigin(t)

	// The "allowed" case must not depend on this host happening to own an
	// address outside the shipped reject list, which most machines do not.
	// Instead an explicit narrow exception is added for the LAN address, so the
	// shipped list is exercised intact for the forbidden cases while a real
	// reachable origin still proves allowed traffic flows.
	allowedAddress := lanAddress(t)
	allowedOrigin := startTCPOriginOn(t, net.JoinHostPort(allowedAddress.String(), "0"))
	allowRule := `{"inbound": ["naive-in"], "ip_cidr": ["` + allowedAddress.String() + `/32"], "action": "route", "outbound": "direct"},`

	dnsServer, dnsPort := startScriptedDNS(t, map[string][]net.IP{
		"forbidden.test": {net.IPv4(127, 0, 0, 1)},
		"allowed.test":   {allowedAddress},
	})

	port := reserveTCPPort(t)
	config := `{
		"log": {"level": "debug"},
		"dns": {
			"servers": [{"tag": "scripted", "type": "udp", "server": "127.0.0.1", "server_port": ` + dnsPort + `}],
			"final": "scripted",
			"strategy": "ipv4_only",
			"independent_cache": true
		},
		"inbounds": [{
			"type": "naive",
			"tag": "naive-in",
			"listen": "127.0.0.1",
			"listen_port": ` + strconv.Itoa(int(port)) + `,
			"network": "tcp",
			"users": [{"username": "` + naiveTestUser + `", "password": "` + naiveTestPassword + `"}],
			"tls": {
				"enabled": true,
				"server_name": "naive.test",
				"certificate_path": "` + certPem + `",
				"key_path": "` + keyPem + `"
			}
		}],
		"outbounds": [{"type": "direct", "tag": "direct", "domain_resolver": "scripted"}],
		"route": {
			"rules": [
				{"inbound": ["naive-in"], "action": "resolve"},
				` + allowRule + `
				{"inbound": ["naive-in"], "ip_cidr": [` + quotedCIDRs(productionRejectCIDRs()) + `], "action": "reject"}
			],
			"final": "direct"
		}
	}`

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)

	// Literal IP form: refused.
	ipConn := naiveTLSConn(t, port)
	ipResponse, ipErr := naiveWriteConnect(t, ipConn, forbiddenOrigin.addr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	require.False(t, probeTunnelStillReaches(t, ipConn, ipResponse, ipErr),
		"the shipped rules must refuse a literal loopback target")

	// Domain form resolving to the SAME address: refused too.
	domainConn := naiveTLSConn(t, port)
	domainResponse, domainErr := naiveWriteConnect(t, domainConn,
		"forbidden.test:"+strconv.Itoa(int(forbiddenOrigin.port())), map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
	require.False(t, probeTunnelStillReaches(t, domainConn, domainResponse, domainErr),
		"the shipped rules must refuse a domain that resolves to a forbidden address")

	require.EqualValues(t, 0, forbiddenOrigin.conns.Load(),
		"the forbidden origin must never receive a TCP connection in either form")

	// Allowed destination still works, so the rules are targeted.
	okConn := naiveTLSConn(t, port)
	okResponse, okErr := naiveWriteConnect(t, okConn,
		"allowed.test:"+strconv.Itoa(int(allowedOrigin.port())), map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
	require.True(t, probeTunnelStillReaches(t, okConn, okResponse, okErr),
		"an allowed public destination must still be reachable")
	require.EqualValues(t, 1, allowedOrigin.conns.Load())
	t.Logf("production rule shape: forbidden IP and domain both refused, "+
		"allowed domain reached, dns queries=%d", dnsServer.queries.Load())
}

// productionRejectCIDRs mirrors the ip_cidr list shipped for naive-in in
// release/jiejie-production-topology.json. Keeping it here means a change to the
// shipped list that is not reflected in the tests shows up as a failure.
func productionRejectCIDRs() []string {
	return []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24",
		"192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"240.0.0.0/4",
		"::1/128", "::/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	}
}

// lanAddress returns the host's first non-loopback IPv4 address.
func lanAddress(t *testing.T) net.IP {
	t.Helper()
	interfaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipNet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
				return ip4
			}
		}
	}
	t.Skip("no non-loopback IPv4 address is available")
	return nil
}

// TestJiejieTargetACLUoTLegacySessionCannotUseUnspecifiedTarget covers the one
// destination the guard treats as pre-authorised.
//
// For legacy UoT v1 the router sets the session destination to 0.0.0.0:0,
// because that form carries no request destination at all. The guard short-
// circuits a datagram whose destination equals the session destination, on the
// grounds that the session-level rule match already approved it - and
// 0.0.0.0/8 is in the shipped reject list, so 0.0.0.0:0 is refused there.
//
// That reasoning only holds if the session was in fact rejected. This test
// pins the observable outcome instead of the reasoning: a legacy v1 session
// must not be able to deliver a datagram to an unspecified address.
func TestJiejieTargetACLUoTLegacySessionCannotUseUnspecifiedTarget(t *testing.T) {
	env := startACLInstance(t, []string{"0.0.0.0/8", "127.0.0.0/8"}, true)

	conn := naiveTLSConn(t, env.port)
	legacyMagic := uot.RequestDestination(uot.LegacyVersion).String()
	response, err := naiveWriteConnect(t, conn, legacyMagic, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	if err != nil || response == nil || response.StatusCode != http.StatusOK {
		t.Logf("legacy UoT session refused at CONNECT (status/err: %v/%v)", response, err)
		return
	}
	defer response.Body.Close()

	// The legacy form sends per-datagram addresses from the first datagram.
	sentinel := startCountingUDPOrigin(t)
	targets := []metadata.Socksaddr{
		{Addr: netip.IPv4Unspecified()},
		{Addr: netip.IPv4Unspecified(), Port: uint16(sentinel.port())},
	}

	// The session destination for legacy UoT v1 is 0.0.0.0:0, and 0.0.0.0/8 is
	// rejected by the rules, so the server REFUSES the session and closes it.
	// A write into the closed tunnel therefore fails with a broken pipe, which
	// is the rejection working, not a test failure. Both outcomes are recorded:
	// what must never happen is a datagram reaching the sentinel.
	closedByPolicy := false
	for _, target := range targets {
		if err = writeUoTDatagramRaw(conn, target, []byte("unspecified")); err != nil {
			closedByPolicy = true
			t.Logf("write into the refused legacy tunnel failed as expected: %v", err)
			break
		}
	}
	time.Sleep(400 * time.Millisecond)

	t.Logf("legacy UoT v1: sentinel received %d packets (tunnel closed by policy: %v)",
		sentinel.packets.Load(), closedByPolicy)
	require.EqualValues(t, 0, sentinel.packets.Load(),
		"an unspecified destination must not be delivered")
}

// TestJiejieTargetACLPerDatagramHitsRulesTheSessionDidNot covers the case where
// a datagram's target should trigger a rule the session would never have hit.
//
// The UoT session is authorised once, from its header destination. If the guard
// only re-checked "is this address still allowed" it could still miss rules
// that exist for a DIFFERENT reason - here, a rule that rejects a port range
// outright. The datagram path must see the same rule set, evaluated for the
// datagram's own target, not just a narrowed ip_cidr check.
func TestJiejieTargetACLPerDatagramHitsRulesTheSessionDidNot(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")

	allowedOrigin := startUDPOriginOn(t, "127.0.0.1:0")
	forbiddenOrigin := startUDPOriginOn(t, "127.0.0.1:0")

	port := reserveTCPPort(t)
	// The reject is by PORT, not by address: both origins are on loopback, so an
	// address-only check would treat them identically and let the forbidden one
	// through. The session target is an address the rules allow.
	config := `{
		"log": {"level": "debug"},
		"inbounds": [{
			"type": "naive",
			"tag": "naive-in",
			"listen": "127.0.0.1",
			"listen_port": ` + strconv.Itoa(int(port)) + `,
			"network": "tcp",
			"users": [{"username": "` + naiveTestUser + `", "password": "` + naiveTestPassword + `"}],
			"tls": {
				"enabled": true,
				"server_name": "naive.test",
				"certificate_path": "` + certPem + `",
				"key_path": "` + keyPem + `"
			}
		}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {
			"rules": [
				{"inbound": ["naive-in"], "network": ["udp"], "port": [` + strconv.Itoa(int(forbiddenOrigin.port())) + `], "action": "reject"}
			],
			"final": "direct"
		}
	}`

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)

	conn := naiveTLSConn(t, port)
	magic := uot.RequestDestination(uot.Version).String()
	response := naiveWriteConnectOK(t, conn, magic, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	defer response.Body.Close()

	// Non-connect session, so each datagram carries its own destination.
	writer := &sliceWriter{}
	require.NoError(t, metadata.SocksaddrSerializer.WriteAddrPort(writer, metadata.ParseSocksaddr("93.184.216.34:443")))
	// Raw over HTTP/1, like the datagrams above.
	_, err := conn.Write(append([]byte{0}, writer.data...))
	require.NoError(t, err)

	// Datagram 1: an allowed port on loopback must be delivered.
	writeUoTDatagramToLoopback(t, conn, metadata.ParseSocksaddr(allowedOrigin.addr), []byte("ok"))
	time.Sleep(300 * time.Millisecond)
	require.EqualValues(t, 1, allowedOrigin.packets.Load(),
		"the datagram to a permitted port must be delivered, proving the session works")

	// Datagram 2: the port the rules reject, same session, same address family.
	writeUoTDatagramToLoopback(t, conn, metadata.ParseSocksaddr(forbiddenOrigin.addr), []byte("denied"))
	time.Sleep(400 * time.Millisecond)

	t.Logf("per-datagram port rule: allowed=%d forbidden=%d",
		allowedOrigin.packets.Load(), forbiddenOrigin.packets.Load())
	require.EqualValues(t, 0, forbiddenOrigin.packets.Load(),
		"a datagram to a port the rules reject must not be delivered, even though "+
			"the session target itself was allowed")
}

// writeUoTDatagramRaw frames one v1-style datagram and RETURNS the write error
// instead of failing the test, for cases where the tunnel may legitimately have
// been closed by the server's own access control.
func writeUoTDatagramRaw(conn net.Conn, target metadata.Socksaddr, payload []byte) error {
	body := make([]byte, 0, 32)
	var buffer bytes.Buffer
	if err := uot.AddrParser.WriteAddrPort(&buffer, target); err != nil {
		return err
	}
	body = append(body, buffer.Bytes()...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	body = append(body, length...)
	body = append(body, payload...)
	_, err := conn.Write(naivePaddingFrame(body, 0))
	return err
}
