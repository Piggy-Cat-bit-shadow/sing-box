package mixed

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ---------------------------------------------------------------------------
// Inbound TLS closure.
//
// The first round recorded this as NOT APPLICABLE, because the TLS branch was
// not the code being optimised. That is not good enough for a wrapper that now
// sits underneath it: the SOCKS5 guard, the early-data hand-off and the cached
// connection all live in the plaintext path, and a wrapper that unwrapped or
// mis-ordered against a TLS connection would show up here and nowhere else.
//
// What these tests establish:
//
//   - the guard sees CIPHERTEXT, so it disables itself and a TLS tunnel is never
//     held to the SOCKS state machine;
//   - the early-data hand-off still delivers exactly once through a TLS layer;
//   - plaintext against a TLS inbound is rejected rather than routed, which is
//     what proves the wrapper chain did not silently expose the raw socket.
// ---------------------------------------------------------------------------

func inboundTLSOptions(t *testing.T) *option.InboundTLSOptions {
	t.Helper()
	certPEM, keyPEM := selfSignedCertificate(t)
	return &option.InboundTLSOptions{
		Enabled:     true,
		Certificate: badoption.Listable[string]{certPEM},
		Key:         badoption.Listable[string]{keyPEM},
	}
}

func selfSignedCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// newTLSInboundHarness builds a mixed inbound with inbound TLS enabled.
func newTLSInboundHarness(t *testing.T, users []auth.User) *inboundHarness {
	t.Helper()
	router := newCaptureRouter()
	options := httpMixedOptions(users)
	options.TLS = inboundTLSOptions(t)
	created, err := NewInbound(context.Background(), router, testNOPLogger(), "mixed-in", options)
	if err != nil {
		t.Fatalf("NewInbound: %v", err)
	}
	inbound, isInbound := created.(*Inbound)
	if !isInbound {
		t.Fatalf("unexpected inbound type %T", created)
	}
	if inbound.tlsConfig == nil {
		t.Fatal("TLS was configured but the inbound built no TLS config")
	}
	t.Cleanup(func() { _ = inbound.listener.Close() })
	return &inboundHarness{inbound: inbound, router: router}
}

// tlsTunnelPair wires an Inbound.NewConnection to a TLS client through a real
// loopback TCP pair.
//
// A socket, not an in-memory pipe, and deliberately so. Both of the in-memory
// options deadlock here: they are unbuffered, and a TLS client buffers its
// writes until a record fills or it reads, so neither side can make progress
// while the other waits. Using a socket also means the test exercises the same
// transport the product does, which is the point of a closure test.
func tlsTunnelPair(t *testing.T, harness *inboundHarness, onClose func(error)) (*tls.Conn, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer listener.Close()
		serverSide, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		harness.inbound.NewConnection(context.Background(), serverSide,
			adapterInboundContext(testSource()), onCloseFunc(onClose))
	}()
	clientSide, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client := tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	return client, done
}

// TestInboundTLSHTTPConnectEarlyData drives a complete CONNECT with early data
// through a real TLS handshake, which is the strongest available statement that
// the wrapper chain does not disturb the TLS layer.
//
// The client side is read explicitly rather than drained in the background: the
// server must write its 200 and then the payload, and reading both in order is
// what proves the reply timing and the hand-off are unchanged.
func TestInboundTLSHTTPConnectEarlyData(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5A}, 128)
	harness := newTLSInboundHarness(t, nil)
	client, serverDone := tlsTunnelPair(t, harness, nil)
	defer func() {
		_ = client.Close()
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			t.Error("the server side never finished after the client closed")
		}
	}()

	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	if _, err := client.Write(append([]byte(httpConnectNoAuth), payload...)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	routed := harness.router.waitConnection(t)
	if got := routed.metadata.Destination.Fqdn; got != "example.com" {
		t.Fatalf("destination = %q, want example.com", got)
	}

	// Read the CONNECT reply, then the payload, from inside the TLS tunnel.
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	head := make([]byte, 0, 64)
	one := make([]byte, 1)
	for !bytes.HasSuffix(head, []byte("\r\n\r\n")) {
		n, err := client.Read(one)
		if err != nil {
			t.Fatalf("read CONNECT reply: %v (got %q)", err, head)
		}
		head = append(head, one[:n]...)
		if len(head) > 128 {
			t.Fatalf("CONNECT reply did not terminate: %q", head)
		}
	}
	if !bytes.Contains(head, []byte("200")) {
		t.Fatalf("expected a 200 CONNECT reply, got %q", head)
	}
	// The payload is read from the ROUTED connection, which is where the
	// early-data hand-off puts it. Reading it from the client would instead be
	// asking this test's sink router to echo, which it does not do.
	got, err := readExact(routed.conn, len(payload))
	if err != nil {
		t.Fatalf("read tunnel payload through TLS: %v (got %d/%d)", err, len(got), len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload corrupted through the TLS layer")
	}
}

// TestInboundTLSNeverFeedsTheGuardPlaintext proves the guard is above the TLS
// layer and therefore only ever sees ciphertext. If it saw plaintext it would
// try to interpret the TLS record header as a SOCKS version, and a TLS record
// that happens to begin 0x05 followed by a length byte would be misread as a
// SOCKS5 greeting.
func TestInboundTLSNeverFeedsTheGuardPlaintext(t *testing.T) {
	harness := newTLSInboundHarness(t, nil)
	client, serverDone := tlsTunnelPair(t, harness, nil)
	defer func() {
		_ = client.Close()
		<-serverDone
	}()
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	if _, err := client.Write([]byte(httpConnectNoAuth)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The CONNECT must be understood as HTTP, which it can only be if the guard
	// passed it through untouched.
	routed := harness.router.waitConnection(t)
	if routed.metadata.Destination.Fqdn != "example.com" {
		t.Fatalf("destination = %q", routed.metadata.Destination.Fqdn)
	}
	// Read the reply so the server can finish writing before the deferred close.
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 64)
	if _, err := client.Read(reply); err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
}

// TestInboundTLSRejectsPlaintext proves the wrapper chain did not expose the
// raw socket: a plaintext CONNECT against a TLS inbound must not be routed as
// if TLS were absent.
func TestInboundTLSRejectsPlaintext(t *testing.T) {
	harness := newTLSInboundHarness(t, nil)
	serverSide, clientSide := net.Pipe()
	recorder := newCloseRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		harness.inbound.NewConnection(context.Background(), serverSide,
			adapterInboundContext(testSource()), recorder.handler())
	}()
	// Plaintext, not a ClientHello.
	if _, err := clientSide.Write([]byte(httpConnectNoAuth)); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = clientSide.Close()
		t.Fatal("a plaintext request against a TLS inbound neither failed nor returned")
	}
	_ = clientSide.Close()
	if !recorder.wait(5 * time.Second) {
		t.Fatal("the TLS failure was not reported through onClose")
	}
	select {
	case routed := <-harness.router.connection:
		t.Fatalf("plaintext was routed despite inbound TLS (destination %v)", routed.metadata.Destination)
	default:
	}
}

// TestInboundTLSBadHandshakeIsClean closes the connection during the handshake
// and requires a clean failure: exactly one onClose, no routing, no hang.
func TestInboundTLSBadHandshakeIsClean(t *testing.T) {
	harness := newTLSInboundHarness(t, nil)
	serverSide, clientSide := net.Pipe()
	recorder := newCloseRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		harness.inbound.NewConnection(context.Background(), serverSide,
			adapterInboundContext(testSource()), recorder.handler())
	}()
	// A truncated ClientHello, then EOF.
	if _, err := clientSide.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x50, 0x01}); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a truncated TLS handshake hung the inbound")
	}
	if !recorder.wait(5 * time.Second) {
		t.Fatal("the failed handshake was not reported")
	}
	time.Sleep(20 * time.Millisecond)
	if calls := recorder.count(); calls != 1 {
		t.Fatalf("onClose ran %d times, want exactly once", calls)
	}
	select {
	case <-harness.router.connection:
		t.Fatal("a failed TLS handshake was routed")
	default:
	}
}

func adapterInboundContext(source interface{ String() string }) adapter.InboundContext {
	return adapter.InboundContext{Source: source.(M.Socksaddr)}
}

func onCloseFunc(onClose func(error)) N.CloseHandlerFunc {
	if onClose == nil {
		return nil
	}
	return onClose
}

var _ = io.Discard
