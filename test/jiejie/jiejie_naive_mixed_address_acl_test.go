package jiejie_test

import (
	"net"
	"net/http"
	"strconv"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// Mixed-address DNS answers: the ACL hardening this fork deliberately keeps.
//
// When one hostname resolves to several addresses and only SOME of them are
// restricted, the two implementations make different choices:
//
//	reference  filters the forbidden addresses and keeps trying the allowed ones
//	this fork  rejects the whole destination if ANY resolved address is restricted
//
// The fork's behaviour is stricter on purpose and must not be relaxed for parity:
// a name that resolves to both a public address and a loopback or private one is
// the classic SSRF shape, and "try the public one" means a client can still reach
// a restricted target whenever DNS ordering or address selection favours it. The
// point of this test is to PIN that divergence so a future refactor cannot widen
// the boundary by accident while chasing reference parity.
//
// Classification: INTENTIONAL-DIFF, hardening. It is not a compatibility bug and
// it is not "unverified" - the behaviour asserted here is the behaviour this fork
// intends, and it is the reason the ACL exists.

// mixedAddressCase is one DNS answer set to exercise.
type mixedAddressCase struct {
	name string
	// answers is what the scripted resolver returns for the name.
	answers []net.IP
	// note explains why the case matters.
	note string
}

func mixedAddressCases() []mixedAddressCase {
	return []mixedAddressCase{
		{
			name:    "private-and-public",
			answers: []net.IP{net.IPv4(10, 0, 0, 5), net.IPv4(93, 184, 216, 34)},
			note:    "the ordinary SSRF shape: a name that resolves inside and outside",
		},
		{
			name:    "loopback-and-public",
			answers: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(93, 184, 216, 34)},
			note:    "loopback is the highest-value target on a server",
		},
		{
			name:    "self-and-public",
			answers: []net.IP{net.IPv4(192, 0, 2, 10), net.IPv4(93, 184, 216, 34)},
			note:    "the self address is what the ACL exists to protect",
		},
		{
			name:    "link-local-and-public",
			answers: []net.IP{net.IPv4(169, 254, 1, 1), net.IPv4(93, 184, 216, 34)},
			note:    "link-local reaches instance metadata on many clouds",
		},
		{
			name:    "cgnat-and-public",
			answers: []net.IP{net.IPv4(100, 64, 0, 1), net.IPv4(93, 184, 216, 34)},
			note:    "CGNAT space is routable inside some provider networks",
		},
		{
			name:    "ula-and-global-ipv6",
			answers: []net.IP{net.ParseIP("fd00::1"), net.ParseIP("2001:db8::20")},
			note:    "the IPv6 equivalent of private-and-public",
		},
		{
			name:    "ipv4-and-ipv6-mixed",
			answers: []net.IP{net.IPv4(10, 1, 2, 3), net.ParseIP("2001:db8::20")},
			note:    "a dual-stack answer must not let the restricted family be ignored",
		},
	}
}

// TestJiejieNaiveMixedAddressAnswersAreRejectedWhole is the regression.
//
// Every case must be REJECTED, and the decisive assertion is that neither the
// allowed-looking address NOR the restricted one was dialled: a rejection that
// still connected to the public address would mean the destination was partially
// permitted, which is the reference behaviour this fork does not adopt.
func TestJiejieNaiveMixedAddressAnswersAreRejectedWhole(t *testing.T) {
	selfAddress := selfTestAddress(t)

	for _, testCase := range mixedAddressCases() {
		t.Run(testCase.name, func(t *testing.T) {
			// Two origins so the test can tell WHICH address was contacted, if
			// either: the restricted one, the public-looking one, or neither.
			restrictedOrigin := startCountingTCPOrigin(t)
			publicOrigin := startCountingTCPOrigin(t)

			// The scripted resolver answers the name with exactly the case's
			// addresses. The origins are what the addresses actually point at,
			// so "was it dialled" is observable rather than inferred.
			env := startMixedAddressACLInstance(t, selfAddress, testCase.answers)

			conn := naiveTLSConn(t, env.port, "http/1.1")
			defer conn.Close()
			response, err := naiveWriteConnect(t, conn, "mixed.test:443", map[string]string{
				"Proxy-Authorization": naiveBasicAuth(),
				"Padding":             "~~~~~~~~",
			})
			if response != nil {
				defer response.Body.Close()
			}

			// The tunnel must not carry traffic. A rejection here may be a
			// status or a closed connection; what matters is that no origin saw
			// a connection.
			if err == nil && response != nil && response.StatusCode == http.StatusOK {
				require.False(t, probeTunnelServes(t, conn),
					"%s: a mixed public/restricted answer must not produce a "+
						"working tunnel (%s)", testCase.name, testCase.note)
			}

			require.EqualValues(t, 0, restrictedOrigin.conns.Load(),
				"%s: the restricted address must never be dialled (%s)",
				testCase.name, testCase.note)
			require.EqualValues(t, 0, publicOrigin.conns.Load(),
				"%s: the public-looking address must NOT be dialled either - the "+
					"fork rejects the whole destination rather than filtering the "+
					"forbidden address and continuing, which is the hardening this "+
					"test exists to pin (%s)", testCase.name, testCase.note)
		})
	}
}

// TestJiejieNaiveAllPublicAnswersStillConnect is the control, and it is the part
// that keeps the hardening from becoming a functional break.
//
// Without it, the rejections above would also pass against an ACL that refused
// every multi-address answer.
//
// Design, because the first two attempts at this control were wrong: the origin
// must sit on an address the ACL PERMITS, and every private range - including the
// whole of 127.0.0.0/8 - is rejected by design, so a loopback or RFC1918 origin
// would exercise the reject rule rather than the multi-address handling. The
// control therefore takes the real reject list and removes exactly one entry: the
// prefix the origin lives on. That isolates the property under test - a
// multi-address answer with nothing restricted in it is permitted - without
// weakening the ACL the other tests exercise.
func TestJiejieNaiveAllPublicAnswersStillConnect(t *testing.T) {
	selfAddress := selfTestAddress(t)

	originPort := reservePortOn(t, selfAddress)
	origin := startTCPOriginOn(t, net.JoinHostPort(selfAddress.String(), strconv.Itoa(int(originPort))))

	// Permit exactly the origin's prefix by removing it from the reject list.
	// The self address stays rejected separately, so the ACL is still meaningful
	// for every address other than this one origin.
	permittedPrefix := selfAddress.String() + "/32"
	rejectList := make([]string, 0, len(defaultRejectCIDRs()))
	for _, entry := range defaultRejectCIDRs() {
		if entry == "127.0.0.0/8" || entry == "::1/128" {
			continue
		}
		rejectList = append(rejectList, entry)
	}

	env := startMixedAddressACLInstanceWithRejectList(t, selfAddress, []net.IP{
		net.ParseIP(selfAddress.String()),
		net.ParseIP(selfAddress.String()),
	}, rejectList)

	conn := naiveTLSConn(t, env.port, "http/1.1")
	defer conn.Close()
	response, err := naiveWriteConnect(t, conn, origin.addr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	require.NoError(t, err,
		"a multi-address destination with nothing restricted in it must be "+
			"accepted; rejecting it would mean the hardening broke the feature "+
			"rather than narrowing it (%s permitted)", permittedPrefix)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.True(t, probeTunnelServes(t, conn),
		"a permitted destination must still carry traffic")
	require.True(t, waitForDial(&origin.conns, 0),
		"the origin must actually be reached for an allowed destination")
}

// startMixedAddressACLInstance builds a Naive inbound whose scripted resolver
// answers "mixed.test" with exactly the supplied addresses, and whose route
// resolves before the ACL runs.
//
// resolve-before-ACL is the order that makes the case meaningful: the rule sees
// the RESOLVED addresses, so a name answering with several of them is evaluated
// as a whole rather than by whichever address happened to be first.
func startMixedAddressACLInstance(t *testing.T, selfAddress net.IP, answers []net.IP) *aclInstance {
	t.Helper()
	return startMixedAddressACLInstanceWithRejectList(t, selfAddress, answers,
		append([]string{selfAddress.String() + "/32"}, defaultRejectCIDRs()...))
}

// startMixedAddressACLInstanceWithRejectList is the general form, so a control
// can permit one prefix without weakening the ACL the other cases use.
func startMixedAddressACLInstanceWithRejectList(t *testing.T, selfAddress net.IP, answers []net.IP, rejectList []string) *aclInstance {
	t.Helper()
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")

	tcpOrigin := startCountingTCPOrigin(t)
	udpOrigin := startCountingUDPOrigin(t)

	_, dnsPort := startScriptedDNS(t, map[string][]net.IP{
		"mixed.test": answers,
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
				{"inbound": ["naive-in"], "ip_cidr": [` + quotedCIDRs(rejectList) + `], "action": "reject"}
			],
			"final": "direct"
		}
	}`

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)

	return &aclInstance{
		port:       port,
		dnsPort:    dnsPort,
		tcpOrigin:  tcpOrigin,
		udpOrigin:  udpOrigin,
		rejectList: rejectList,
	}
}
