package interop

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// The local destination and the local camouflage server.
//
// # Why the target is local and speaks HTTP
//
// The point of the stand is to assert that bytes written by the test come back
// out of the tunnel unchanged. A local HTTP server makes that a two-way claim
// instead of a one-way one: the request and its body travel the tunnel in one
// direction, the response and its body travel back in the other, and a
// transport that corrupts either direction fails the comparison. A raw echo
// socket would prove only half of it and would leave the HTTP framing of the
// XHTTP transport untested against a real endpoint.
//
// It also removes the last external dependency: no destination outside the
// machine is contacted, which is what makes the stand runnable in a sandbox with
// no network beyond loopback.

// The fixed endpoints every scenario's round trip is asserted against. They are
// constants so that the harness, the target and the failure messages cannot
// disagree about what "/echo" means.
const (
	// TargetHelloPath is a tiny, fast response used by the readiness probe. It
	// must not depend on a request body: the probe runs before anything is known
	// to work, and a probe that needs a working upload stream would report the
	// transport as unready for as long as the transport is broken.
	TargetHelloPath = "/hello"
	// TargetEchoPath echoes the request body back verbatim.
	TargetEchoPath = "/echo"
	// TargetSinkPath drains the request body and answers with its length, for
	// uploads too large to want echoed.
	TargetSinkPath = "/sink"
	// TargetSourcePath answers with `size` deterministic bytes.
	TargetSourcePath = "/source"
	// TargetSlowPath never answers until the caller goes away. It exists so that
	// a cancel and a deadline can be asserted as observed behaviour rather than
	// as configuration.
	TargetSlowPath = "/slow"
)

// slowHoldDuration is how long /slow waits for the caller. It is longer than any
// deadline a test sets, so the test's own cancellation is always what ends the
// request; a shorter hold would make a deadline test pass because the server
// answered, which is the opposite of what it claims.
const slowHoldDuration = 2 * time.Minute

// maxTargetBody bounds how much the echo endpoint will read, so a broken client
// that streams forever cannot turn a test failure into a memory exhaustion.
const maxTargetBody = 8 << 20

// Target is the local HTTP destination.
type Target struct {
	listener net.Listener
	server   *http.Server
	port     uint16
}

// StartTarget starts the local echo/HTTP destination on an ephemeral loopback
// port.
func StartTarget() (*Target, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, E.Cause(err, "listen for the interop target")
	}
	target := &Target{
		listener: listener,
		port:     uint16(listener.Addr().(*net.TCPAddr).Port),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(TargetHelloPath, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(writer, "interop\n")
	})
	mux.HandleFunc(TargetEchoPath, func(writer http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(io.LimitReader(request.Body, maxTargetBody))
		if readErr != nil {
			// Answering 502 rather than panicking keeps the failure on the client
			// side, where the assertion and the artifact capture live.
			http.Error(writer, "read request body: "+readErr.Error(), http.StatusBadGateway)
			return
		}
		writer.Header().Set("Content-Type", "application/octet-stream")
		writer.Header().Set("X-Interop-Echo-Length", strconv.Itoa(len(body)))
		_, _ = writer.Write(body)
	})
	mux.HandleFunc(TargetSinkPath, func(writer http.ResponseWriter, request *http.Request) {
		written, copyErr := io.Copy(io.Discard, io.LimitReader(request.Body, maxTargetBody))
		if copyErr != nil {
			http.Error(writer, "read request body: "+copyErr.Error(), http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(writer, strconv.FormatInt(written, 10))
	})
	mux.HandleFunc(TargetSourcePath, func(writer http.ResponseWriter, request *http.Request) {
		size, parseErr := strconv.Atoi(request.URL.Query().Get("size"))
		if parseErr != nil || size < 0 || size > maxTargetBody {
			http.Error(writer, "invalid size", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/octet-stream")
		_, _ = writer.Write(deterministicPayload(size))
	})
	mux.HandleFunc(TargetSlowPath, func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(slowHoldDuration):
		}
		// Deliberately no response: the caller has already gone away, and writing
		// to a closed connection would only add noise to the target's log.
	})
	target.server = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		_ = target.server.Serve(listener)
	}()
	return target, nil
}

// Port is the ephemeral port the target bound.
func (t *Target) Port() uint16 {
	return t.port
}

// Address is the host:port the reference's freedom outbound dials.
func (t *Target) Address() string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(t.port)))
}

// URL builds an absolute URL for one of the fixed endpoints, for the harness's
// HTTP client.
func (t *Target) URL(path string) string {
	return "http://" + t.Address() + path
}

// Close stops the target.
func (t *Target) Close() error {
	return t.server.Close()
}

// Camouflage is a local TLS server standing in for the site a REALITY handshake
// is disguised as.
//
// It advertises h2 as well as HTTP/1.1, because an XHTTP-over-REALITY client
// negotiates HTTP/2 and a camouflage endpoint that only spoke HTTP/1.1 would
// make the stand's REALITY+XHTTP scenarios fail in a way that looks like a
// transport bug.
type Camouflage struct {
	listener   net.Listener
	server     *http.Server
	port       uint16
	certFile   string
	keyFile    string
	serverName string
}

// StartCamouflage starts the camouflage TLS server with a freshly minted
// certificate for serverName.
func StartCamouflage(certificateDir string, serverName string) (*Camouflage, error) {
	certFile, keyFile, err := WriteSelfSignedCertificate(certificateDir, serverName)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, E.Cause(err, "listen for the REALITY camouflage server")
	}
	camouflage := &Camouflage{
		listener:   listener,
		port:       uint16(listener.Addr().(*net.TCPAddr).Port),
		certFile:   certFile,
		keyFile:    keyFile,
		serverName: serverName,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(writer, "camouflage\n")
	})
	camouflage.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			// The h2 entry is what lets Go's ServeTLS install the HTTP/2 handler;
			// listing it here rather than relying on the default is deliberate,
			// because the default only applies to a config that does not already
			// set NextProtos.
			NextProtos: []string{"h2", "http/1.1"},
			MinVersion: tls.VersionTLS12,
		},
	}
	go func() {
		// ServeTLS with empty file names uses TLSConfig.Certificates when it is
		// set, but the stand needs the files on disk anyway for the reference
		// config, so they are passed explicitly — one load path, not two.
		_ = camouflage.server.ServeTLS(listener, certFile, keyFile)
	}()
	return camouflage, nil
}

// Address is the host:port a REALITY server's `dest` points at.
func (c *Camouflage) Address() string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(c.port)))
}

// CertificateFile is the certificate the reference is configured with when the
// scenario uses ordinary TLS rather than REALITY.
func (c *Camouflage) CertificateFile() string {
	return c.certFile
}

// ServerName is the SNI the camouflage certificate was minted for.
func (c *Camouflage) ServerName() string {
	return c.serverName
}

// KeyFile is the matching private key file.
func (c *Camouflage) KeyFile() string {
	return c.keyFile
}

// Close stops the camouflage server.
func (c *Camouflage) Close() error {
	return c.server.Close()
}

// deterministicPayload builds an incompressible-looking but fully reproducible
// byte string of the requested size.
//
// Reproducible matters more than random here: a failure message can name the
// exact offset that differs only if the expected bytes can be regenerated from
// the test source alone.
func deterministicPayload(size int) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte((index*31 + 7) % 251)
	}
	return payload
}

// summarizeBody renders a body for a failure message without dumping megabytes
// of binary into the test log.
func summarizeBody(body []byte) string {
	const limit = 64
	if len(body) <= limit {
		return strconv.Quote(string(body))
	}
	return strconv.Quote(string(body[:limit])) + "... (" + strconv.Itoa(len(body)) + " bytes, truncated)"
}
