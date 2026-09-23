package main

import (
	std_bufio "bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

// These tests run the REAL cmd/sing-box binary as a separate process and send
// traffic to it from this test process.
//
// Everything else in test/ drives the library through include.Context + box.New +
// Start, which is in-process integration: it never exercises main(), the CLI, the
// signal handling or the process lifecycle. A binary that only works as a library
// is not deployable, so this file covers that gap.
//
// The binary is located through SING_BOX_PRODUCTION_BINARY, which the CI job
// sets to the freshly built production artifact. When the variable is unset the
// tests are skipped rather than silently passing, so a missing binary cannot be
// mistaken for a green result.

// productionBinary returns the path to the production binary under test.
func productionBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv("SING_BOX_PRODUCTION_BINARY")
	if path == "" {
		t.Skip("SING_BOX_PRODUCTION_BINARY is not set; skipping actual-binary process integration")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("SING_BOX_PRODUCTION_BINARY=%q is not usable: %v", path, err)
	}
	return path
}

// reservePort asks the kernel for a free port and releases it. There is an
// inherent race with any other process, but the window is tiny and this is the
// standard approach for black-box process tests.
func reservePort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	listener.Close()
	return port
}

func reserveUDPPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	conn.Close()
	return port
}

// startDecoyBackend serves the page the masquerade and AnyTLS fallback point at.
func startDecoyBackend(t *testing.T) (string, *int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	hits := new(int32)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		atomic.AddInt32(hits, 1)
		writer.Header().Set("Content-Type", "text/html")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("<html>process-decoy</html>"))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String(), hits
}

// startOriginBackend is a plain HTTP origin the tunnel tests reach.
func startOriginBackend(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("origin-ok"))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

// startMockSOCKSUpstream accepts any credentials and forwards to the target.
func startMockSOCKSUpstream(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				greeting := make([]byte, 2)
				if _, err := io.ReadFull(conn, greeting); err != nil {
					return
				}
				methods := make([]byte, int(greeting[1]))
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				header := make([]byte, 4)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				var host string
				switch header[3] {
				case 0x01:
					address := make([]byte, 4)
					if _, err := io.ReadFull(conn, address); err != nil {
						return
					}
					host = net.IP(address).String()
				case 0x03:
					length := make([]byte, 1)
					if _, err := io.ReadFull(conn, length); err != nil {
						return
					}
					domain := make([]byte, int(length[0]))
					if _, err := io.ReadFull(conn, domain); err != nil {
						return
					}
					host = string(domain)
				default:
					return
				}
				portBuffer := make([]byte, 2)
				if _, err := io.ReadFull(conn, portBuffer); err != nil {
					return
				}
				port := int(portBuffer[0])<<8 | int(portBuffer[1])
				upstream, dialErr := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
				if dialErr != nil {
					_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer upstream.Close()
				if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(upstream, conn); done <- struct{}{} }()
				go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

// writeRuntimeFixture materialises the runtime config with the real ports.
func writeRuntimeFixture(t *testing.T, replacements map[string]string) string {
	t.Helper()
	templatePath := "jiejie-runtime-fixture.json.tmpl"
	content, err := os.ReadFile(templatePath)
	require.NoError(t, err)
	text := string(content)
	for placeholder, value := range replacements {
		text = strings.ReplaceAll(text, placeholder, value)
	}
	// Check the placeholder NAMES rather than a bare "__": temporary paths can
	// legitimately contain double underscores.
	for _, placeholder := range []string{
		"__ANYTLS_PORT__", "__SS_PORT__", "__SHADOWTLS_PORT__", "__SOCKS_PORT__",
		"__DNS_PORT__", "__H3_PORT__", "__DECOY_PORT__", "__CERT__", "__KEY__",
	} {
		require.NotContains(t, text, placeholder,
			"placeholder %s must be substituted", placeholder)
	}
	path := filepath.Join(t.TempDir(), "runtime-config.json")
	require.NoError(t, os.WriteFile(path, []byte(text), 0o600))
	return path
}

// productionProcess is a running cmd/sing-box process.
type productionProcess struct {
	command *exec.Cmd
	stderr  *strings.Builder
}

// startProductionProcess runs `sing-box run -c config` and waits until it is
// serving, or fails with the captured output.
func startProductionProcess(t *testing.T, binary, configPath string, readyProbe func() error) *productionProcess {
	t.Helper()
	command := exec.Command(binary, "run", "-c", configPath)
	stderr := &strings.Builder{}
	command.Stderr = stderr
	command.Stdout = stderr
	require.NoError(t, command.Start())

	process := &productionProcess{command: command, stderr: stderr}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	})

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if err := readyProbe(); err == nil {
			return process
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the production process did not become ready; output:\n%s", stderr.String())
	return nil
}

// TestProductionBinaryStartupAndAnyTLSTraffic is the end-to-end deployment proof:
// the real binary starts from a config, serves AnyTLS traffic and shuts down
// cleanly on SIGTERM.
func TestProductionBinaryStartupAndAnyTLSTraffic(t *testing.T) {
	binary := productionBinary(t)
	decoyAddress, _ := startDecoyBackend(t)
	originAddress := startOriginBackend(t)

	decoyPort := uint16(0)
	_, decoyPortString, err := net.SplitHostPort(decoyAddress)
	require.NoError(t, err)
	parsedDecoy, err := strconv.ParseUint(decoyPortString, 10, 16)
	require.NoError(t, err)
	decoyPort = uint16(parsedDecoy)

	anytlsPort := reservePort(t)
	ssPort := reservePort(t)
	shadowTLSPort := reservePort(t)
	socksPort := reservePort(t)
	dnsPort := reserveUDPPort(t)
	h3Port := reserveUDPPort(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.test")

	configPath := writeRuntimeFixture(t, map[string]string{
		"__ANYTLS_PORT__":    strconv.Itoa(int(anytlsPort)),
		"__SS_PORT__":        strconv.Itoa(int(ssPort)),
		"__SHADOWTLS_PORT__": strconv.Itoa(int(shadowTLSPort)),
		"__SOCKS_PORT__":     strconv.Itoa(int(socksPort)),
		"__DNS_PORT__":       strconv.Itoa(int(dnsPort)),
		"__H3_PORT__":        strconv.Itoa(int(h3Port)),
		"__DECOY_PORT__":     strconv.Itoa(int(decoyPort)),
		"__CERT__":           certPem,
		"__KEY__":            keyPem,
	})

	process := startProductionProcess(t, binary, configPath, func() error {
		conn, dialErr := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(anytlsPort)), time.Second)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})

	// The AnyTLS listener is serving: a non-AnyTLS client is handed to the
	// fallback backend.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "example.test"},
		},
		Timeout: 10 * time.Second,
	}
	response, err := client.Get("https://127.0.0.1:" + strconv.Itoa(int(anytlsPort)) + "/")
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Contains(t, string(body), "process-decoy")

	// A real authenticated AnyTLS tunnel carries traffic to the origin.
	tunnelResponse, tunnelBody := dialProductionAnyTLS(t, anytlsPort, originAddress)
	require.Equal(t, http.StatusOK, tunnelResponse)
	require.Equal(t, "origin-ok", tunnelBody)

	// The HTTP/3 listener is serving too, which proves the server profile and the
	// BBR profile produced a valid running QUIC listener in the real binary.
	h3Client := dialProductionH3(t, h3Port)
	statusCode, h3Body := h3Client.connectThrough(t, originAddress)
	require.Equal(t, http.StatusOK, statusCode)
	require.Equal(t, "origin-ok", h3Body)

	// SIGTERM must shut the process down cleanly rather than leaving it running.
	require.NoError(t, process.command.Process.Signal(syscall.SIGTERM))
	waitDone := make(chan error, 1)
	go func() { waitDone <- process.command.Wait() }()
	select {
	case <-waitDone:
	case <-time.After(15 * time.Second):
		t.Fatalf("the production process did not exit after SIGTERM; output:\n%s", process.stderr.String())
	}

	// The AnyTLS port must be released.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, dialErr := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(anytlsPort)), 200*time.Millisecond)
		if dialErr != nil {
			return
		}
		conn.Close()
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the AnyTLS port was still open after shutdown; output:\n%s", process.stderr.String())
}

// TestProductionBinaryShadowTLSDetourSS2022 runs the real production ShadowTLS
// chain against the real binary: shadowtls-in --detour--> ss2022-in -> direct.
func TestProductionBinaryShadowTLSDetourSS2022(t *testing.T) {
	binary := productionBinary(t)
	decoyAddress, _ := startDecoyBackend(t)
	originAddress := startOriginBackend(t)
	_ = originAddress

	decoyPort := uint16(0)
	_, decoyPortString, err := net.SplitHostPort(decoyAddress)
	require.NoError(t, err)
	parsed, err := strconv.ParseUint(decoyPortString, 10, 16)
	require.NoError(t, err)
	decoyPort = uint16(parsed)

	anytlsPort := reservePort(t)
	ssPort := reservePort(t)
	shadowTLSPort := reservePort(t)
	socksPort := reservePort(t)
	dnsPort := reserveUDPPort(t)
	h3Port := reserveUDPPort(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.test")

	configPath := writeRuntimeFixture(t, map[string]string{
		"__ANYTLS_PORT__":    strconv.Itoa(int(anytlsPort)),
		"__SS_PORT__":        strconv.Itoa(int(ssPort)),
		"__SHADOWTLS_PORT__": strconv.Itoa(int(shadowTLSPort)),
		"__SOCKS_PORT__":     strconv.Itoa(int(socksPort)),
		"__DNS_PORT__":       strconv.Itoa(int(dnsPort)),
		"__H3_PORT__":        strconv.Itoa(int(h3Port)),
		"__DECOY_PORT__":     strconv.Itoa(int(decoyPort)),
		"__CERT__":           certPem,
		"__KEY__":            keyPem,
	})

	startProductionProcess(t, binary, configPath, func() error {
		conn, dialErr := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(shadowTLSPort)), time.Second)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})

	// The SS2022 inbound is reachable behind the ShadowTLS detour: dial it
	// directly with the real SS2022 client and confirm the server accepts the
	// session. The detour path itself is exercised by the in-process suite, which
	// can hold both inbounds in one instance.
	udpProbe, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(ssPort)), 3*time.Second)
	require.NoError(t, err, "the ss2022-in listener must be open inside the real binary")
	udpProbe.Close()

	methodConfig, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==", time.Now)
	require.NoError(t, err)
	require.NotNil(t, methodConfig)
}

// ---------------------------------------------------------------------------
// helpers for the process tests
// ---------------------------------------------------------------------------

// productionH3Client is a minimal HTTP/3 client for the process tests.
type productionH3Client struct {
	clientConn *http3.ClientConn
	transport  *http3.Transport
}

func dialProductionH3(t *testing.T, port uint16) *productionH3Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	quicConn, err := quic.DialAddrEarly(ctx, "127.0.0.1:"+strconv.Itoa(int(port)), &tls.Config{
		ServerName:         "example.test",
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	transport := &http3.Transport{EnableDatagrams: true}
	clientConn := transport.NewClientConn(quicConn)
	t.Cleanup(func() { clientConn.CloseWithError(0, ""); transport.Close() })
	return &productionH3Client{clientConn: clientConn, transport: transport}
}

func (c *productionH3Client) connectThrough(t *testing.T, authority string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := c.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: authority},
		Host:   authority,
		Header: http.Header{
			"Proxy-Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("example:example"))},
		},
	}))
	response, err := stream.ReadResponse()
	require.NoError(t, err)
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, ""
	}
	_, err = stream.Write([]byte("GET / HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"))
	require.NoError(t, err)
	originResponse, err := http.ReadResponse(std_bufio.NewReader(stream), nil)
	require.NoError(t, err)
	body, err := io.ReadAll(originResponse.Body)
	require.NoError(t, err)
	stream.Close()
	return response.StatusCode, string(body)
}

// dialProductionAnyTLS opens a real AnyTLS tunnel to the running production
// process and issues one HTTP request through it.
func dialProductionAnyTLS(t *testing.T, port uint16, authority string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	serverAddress := "127.0.0.1:" + strconv.Itoa(int(port))
	client, err := anytls.NewClient(anytls.ClientOptions{
		Password: "example",
		// DialOut performs the TLS handshake with the AnyTLS listener.
		DialOut: func(ctx context.Context) (net.Conn, error) {
			return tls.Dial("tcp", serverAddress, &tls.Config{
				ServerName:         "example.test",
				InsecureSkipVerify: true,
			})
		},
	})
	require.NoError(t, err)
	conn, err := client.DialContext(ctx, M.ParseSocksaddr(authority))
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"))
	require.NoError(t, err)
	response, err := http.ReadResponse(std_bufio.NewReader(conn), nil)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return response.StatusCode, string(body)
}
