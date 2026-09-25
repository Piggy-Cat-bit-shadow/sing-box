package jiejie_test

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// STUN over Naive UoT, end to end.
//
// Why this is not just "another UDP echo": STUN is the protocol a VPN client
// uses to discover its own reflexive address, and it is carried over UDP/443 in
// many deployments. Running a real RFC 5389 Binding exchange through the Naive
// UoT tunnel exercises things a plain echo does not:
//
//   - the UoT datagram payload is a well-formed STUN message rather than an
//     arbitrary blob, so any truncation or reordering that an echo would hide
//     shows up as a parse failure;
//   - the transaction ID must survive the round trip byte for byte, which is a
//     stronger integrity check than comparing a payload to itself;
//   - the response carries an XOR-MAPPED-ADDRESS attribute that must be parsed,
//     so the reply path is validated structurally, not just observed;
//   - the server sees the request as a genuine Binding Request, so the test
//     would catch a payload-length or framing regression that a self-comparing
//     echo cannot.
//
// The STUN wire format is implemented here rather than imported, so the test
// validates the bytes on the wire instead of round-tripping through the same
// library that produced them.

const (
	stunTestHeaderSize         = 20
	stunTestMagicCookie        = 0x2112A442
	stunTestBindingRequestType = 0x0001
	stunTestBindingSuccess     = 0x0101
	stunTestAttrXORMappedAddr  = 0x0020
)

// buildSTUNTestBindingRequest builds an RFC 5389 Binding Request with a fresh
// transaction ID.
func buildSTUNTestBindingRequest(t *testing.T) ([]byte, [12]byte) {
	t.Helper()
	var transactionID [12]byte
	_, err := rand.Read(transactionID[:])
	require.NoError(t, err)

	message := make([]byte, stunTestHeaderSize)
	binary.BigEndian.PutUint16(message[0:2], stunTestBindingRequestType)
	binary.BigEndian.PutUint16(message[2:4], 0) // no attributes
	binary.BigEndian.PutUint32(message[4:8], stunTestMagicCookie)
	copy(message[8:20], transactionID[:])
	return message, transactionID
}

// parseSTUNTestResponse validates a Binding Success Response and returns the
// resolved address from its XOR-MAPPED-ADDRESS attribute.
//
// Every field is checked, so a truncated or corrupted reply fails here rather
// than being accepted as "some bytes came back".
func parseSTUNTestResponse(message []byte, wantTransaction [12]byte) (stunTestAddrPort, error) {
	if len(message) < stunTestHeaderSize {
		return stunTestAddrPort{}, stunTestErrorf("message shorter than the 20-byte header", len(message))
	}
	messageType := binary.BigEndian.Uint16(message[0:2])
	if messageType != stunTestBindingSuccess {
		return stunTestAddrPort{}, stunTestErrorf("not a Binding Success Response", messageType)
	}
	declaredLength := int(binary.BigEndian.Uint16(message[2:4]))
	if stunTestHeaderSize+declaredLength > len(message) {
		return stunTestAddrPort{}, stunTestErrorf("declared length exceeds the datagram", declaredLength)
	}
	if cookie := binary.BigEndian.Uint32(message[4:8]); cookie != stunTestMagicCookie {
		return stunTestAddrPort{}, stunTestErrorf("magic cookie mismatch", cookie)
	}
	if got := message[8:20]; string(got) != string(wantTransaction[:]) {
		return stunTestAddrPort{}, stunTestErrorf("transaction ID mismatch", got)
	}

	// Walk the attributes looking for XOR-MAPPED-ADDRESS.
	offset := stunTestHeaderSize
	end := stunTestHeaderSize + declaredLength
	for offset+4 <= end {
		attributeType := binary.BigEndian.Uint16(message[offset : offset+2])
		attributeLength := int(binary.BigEndian.Uint16(message[offset+2 : offset+4]))
		valueStart := offset + 4
		if valueStart+attributeLength > len(message) {
			return stunTestAddrPort{}, stunTestErrorf("attribute overruns the message", attributeType)
		}
		if attributeType == stunTestAttrXORMappedAddr {
			return parseSTUNTestXORMappedAddress(message[valueStart:valueStart+attributeLength], wantTransaction)
		}
		// Attributes are padded to a 4-byte boundary.
		offset = valueStart + attributeLength
		if remainder := attributeLength % 4; remainder != 0 {
			offset += 4 - remainder
		}
	}
	return stunTestAddrPort{}, stunTestErrorf("no XOR-MAPPED-ADDRESS attribute", 0)
}

// parseSTUNTestXORMappedAddress decodes the XOR-MAPPED-ADDRESS attribute.
func parseSTUNTestXORMappedAddress(value []byte, transaction [12]byte) (stunTestAddrPort, error) {
	if len(value) < 4 {
		return stunTestAddrPort{}, stunTestErrorf("XOR-MAPPED-ADDRESS too short", len(value))
	}
	family := value[1]
	xorPort := binary.BigEndian.Uint16(value[2:4])
	port := xorPort ^ uint16(stunTestMagicCookie>>16)

	var address [16]byte
	switch family {
	case 0x01: // IPv4
		if len(value) < 8 {
			return stunTestAddrPort{}, stunTestErrorf("IPv4 XOR-MAPPED-ADDRESS too short", len(value))
		}
		cookieBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(cookieBytes, stunTestMagicCookie)
		for index := range 4 {
			address[index] = value[4+index] ^ cookieBytes[index]
		}
		return stunTestAddrPort{address: address, length: 4, port: port}, nil
	case 0x02: // IPv6
		if len(value) < 20 {
			return stunTestAddrPort{}, stunTestErrorf("IPv6 XOR-MAPPED-ADDRESS too short", len(value))
		}
		cookieBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(cookieBytes, stunTestMagicCookie)
		for index := range 4 {
			address[index] = value[4+index] ^ cookieBytes[index]
		}
		for index := range 12 {
			address[4+index] = value[8+index] ^ transaction[index]
		}
		return stunTestAddrPort{address: address, length: 16, port: port}, nil
	default:
		return stunTestAddrPort{}, stunTestErrorf("unknown address family", family)
	}
}

// stunTestAddrPort is a small carrier so this file does not need a netip import
// purely for the return value.
type stunTestAddrPort struct {
	address [16]byte
	length  int
	port    uint16
}

func (a stunTestAddrPort) String() string {
	if a.length == 4 {
		return net.JoinHostPort(
			net.IPv4(a.address[0], a.address[1], a.address[2], a.address[3]).String(),
			stunTestItoa(int(a.port)))
	}
	return net.JoinHostPort(net.IP(a.address[:]).String(), stunTestItoa(int(a.port)))
}

func stunTestItoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [8]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}

// stunTestErrorf formats a STUN validation error with the offending value.
func stunTestErrorf(reason string, value any) error {
	return &stunTestError{reason: reason, value: value}
}

type stunTestError struct {
	reason string
	value  any
}

func (e *stunTestError) Error() string {
	return "STUN validation failed: " + e.reason + " (value=" + stunTestValueToString(e.value) + ")"
}

func stunTestValueToString(value any) string {
	switch typed := value.(type) {
	case int:
		return stunTestItoa(typed)
	case uint16:
		return stunTestItoa(int(typed))
	case uint32:
		return stunTestItoa(int(typed))
	case []byte:
		return net.IP(typed).String()
	default:
		return "?"
	}
}

// startSTUNServer runs a minimal RFC 5389 Binding server on loopback.
//
// It answers a Binding Request with a Binding Success Response carrying
// XOR-MAPPED-ADDRESS for the source it observed, which is what a real STUN
// server reports.
func startSTUNServer(t *testing.T) (address string, requests *countingOrigin) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	counter := &countingOrigin{addr: conn.LocalAddr().String(), udpServer: conn}
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, from, readErr := conn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			if n < stunTestHeaderSize {
				continue // not a STUN message; ignore like a real server would
			}
			if binary.BigEndian.Uint16(buffer[0:2]) != stunTestBindingRequestType {
				continue
			}
			counter.packets.Add(1)

			var transaction [12]byte
			copy(transaction[:], buffer[8:20])
			response := buildSTUNTestBindingResponse(transaction, from)
			_, _ = conn.WriteToUDP(response, from)
		}
	}()
	return conn.LocalAddr().String(), counter
}

// buildSTUNTestBindingResponse encodes a Binding Success Response with
// XOR-MAPPED-ADDRESS for the observed source.
func buildSTUNTestBindingResponse(transaction [12]byte, from *net.UDPAddr) []byte {
	ip4 := from.IP.To4()
	attribute := make([]byte, 4+8)
	binary.BigEndian.PutUint16(attribute[0:2], stunTestAttrXORMappedAddr)
	binary.BigEndian.PutUint16(attribute[2:4], 8)
	attribute[4] = 0 // reserved
	attribute[5] = 0x01
	binary.BigEndian.PutUint16(attribute[6:8], uint16(from.Port)^uint16(stunTestMagicCookie>>16))
	cookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cookieBytes, stunTestMagicCookie)
	for index := range 4 {
		attribute[8+index] = ip4[index] ^ cookieBytes[index]
	}

	message := make([]byte, stunTestHeaderSize+len(attribute))
	binary.BigEndian.PutUint16(message[0:2], stunTestBindingSuccess)
	binary.BigEndian.PutUint16(message[2:4], uint16(len(attribute)))
	binary.BigEndian.PutUint32(message[4:8], stunTestMagicCookie)
	copy(message[8:20], transaction[:])
	copy(message[stunTestHeaderSize:], attribute)
	return message
}

// TestJiejieNaiveUoTSTUNBindingEndToEnd runs a real STUN Binding exchange over
// the Naive UoT tunnel, for both UoT versions.
//
// This is a LOCAL STUN server on loopback inside the test process. It validates
// the protocol handling through the tunnel; it does NOT validate NAT traversal
// behaviour against a public STUN server on the internet, which this
// environment cannot do. That distinction is stated here so the result is not
// over-read.
func TestJiejieNaiveUoTSTUNBindingEndToEnd(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	stunAddress, stunServer := startSTUNServer(t)

	for _, version := range []struct {
		name    string
		version uint8
	}{
		{"v1", uot.LegacyVersion},
		{"v2", uot.Version},
	} {
		t.Run(version.name, func(t *testing.T) {
			session := dialUoT(t, env.port, version.version, stunAddress, true)
			defer session.Close()

			request, transactionID := buildSTUNTestBindingRequest(t)
			session.writeDatagram(t, version.version, stunAddress, request)

			reply := session.readDatagram(t, version.version)
			require.NotEmpty(t, reply, "a STUN Binding Request must be answered")

			observed, err := parseSTUNTestResponse(reply, transactionID)
			require.NoError(t, err,
				"the reply must be a well-formed Binding Success Response whose "+
					"transaction ID matches the request")
			t.Logf("%s STUN Binding: request %d bytes, reply %d bytes, "+
				"XOR-MAPPED-ADDRESS=%s", version.name, len(request), len(reply), observed)
		})
	}

	t.Logf("STUN server received %d Binding Requests", stunServer.packets.Load())
	require.GreaterOrEqual(t, stunServer.packets.Load(), int64(2),
		"both UoT versions must have delivered a Binding Request to the server")
}

// TestJiejieNaiveUoTSTUNTargetObeysTargetACL proves the STUN case is not exempt
// from the access-control policy.
//
// A test that reached a loopback STUN server would be worthless if the way it
// achieved that was by permanently exempting loopback. Here the STUN server is
// on loopback and the rules reject loopback, so the session must be refused -
// and the server must observe nothing.
func TestJiejieNaiveUoTSTUNTargetObeysTargetACL(t *testing.T) {
	env := startACLInstance(t, []string{"127.0.0.0/8"}, true)
	stunAddress, stunServer := startSTUNServer(t)

	conn := naiveTLSConn(t, env.port)
	magic := uot.RequestDestination(uot.Version).String()
	response, err := naiveWriteConnect(t, conn, magic, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	if err != nil || response == nil || response.StatusCode != 200 {
		t.Logf("STUN-over-UoT refused at CONNECT under the loopback policy")
		return
	}
	defer response.Body.Close()

	writer := &sliceWriter{}
	require.NoError(t, metadata.SocksaddrSerializer.WriteAddrPort(
		writer, metadata.ParseSocksaddr("93.184.216.34:443")))
	_, err = conn.Write(naivePaddingFrame(append([]byte{0}, writer.data...), 0))
	require.NoError(t, err)

	request, _ := buildSTUNTestBindingRequest(t)
	stunTarget := metadata.ParseSocksaddr(stunAddress)
	_ = writeUoTDatagramRaw(conn, stunTarget, request)
	time.Sleep(500 * time.Millisecond)

	t.Logf("STUN server on rejected loopback received %d requests",
		stunServer.packets.Load())
	require.EqualValues(t, 0, stunServer.packets.Load(),
		"a STUN Binding Request to a rejected loopback target must not be "+
			"delivered; STUN is not exempt from the target ACL")
}
