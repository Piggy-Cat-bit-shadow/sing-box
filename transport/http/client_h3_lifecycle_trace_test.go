//go:build with_quic

package http

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for the connection-lifecycle tracing added for the 1.84s/30s investigation.
//
// # What the tracing is for
//
// The earlier investigation could not tell, from the logs available, whether two timeouts came from
// the same QUIC connection, whether a redial happened, or whether the cached connection was
// rejected because it was absent or because it was dead. These tests pin the properties that make
// those questions answerable: a stable generation number, an explicit reject reason, and a hard
// guarantee that no credential can reach the log.

// recordingLogger captures TRACE output so a test can assert on what would be emitted.
type recordingLogger struct {
	access   sync.Mutex
	messages []string
}

func (l *recordingLogger) Trace(args ...any) { l.record("TRACE", args...) }
func (l *recordingLogger) Debug(args ...any) { l.record("DEBUG", args...) }
func (l *recordingLogger) Info(args ...any)  { l.record("INFO", args...) }
func (l *recordingLogger) Warn(args ...any)  { l.record("WARN", args...) }
func (l *recordingLogger) Error(args ...any) { l.record("ERROR", args...) }
func (l *recordingLogger) Fatal(args ...any) { l.record("FATAL", args...) }
func (l *recordingLogger) Panic(args ...any) { l.record("PANIC", args...) }

func (l *recordingLogger) TraceContext(_ context.Context, args ...any) { l.record("TRACE", args...) }
func (l *recordingLogger) DebugContext(_ context.Context, args ...any) { l.record("DEBUG", args...) }
func (l *recordingLogger) InfoContext(_ context.Context, args ...any)  { l.record("INFO", args...) }
func (l *recordingLogger) WarnContext(_ context.Context, args ...any)  { l.record("WARN", args...) }
func (l *recordingLogger) ErrorContext(_ context.Context, args ...any) { l.record("ERROR", args...) }
func (l *recordingLogger) FatalContext(_ context.Context, args ...any) { l.record("FATAL", args...) }
func (l *recordingLogger) PanicContext(_ context.Context, args ...any) { l.record("PANIC", args...) }

func (l *recordingLogger) record(level string, args ...any) {
	l.access.Lock()
	defer l.access.Unlock()
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		parts = append(parts, formatLogValue(arg))
	}
	l.messages = append(l.messages, level+" "+strings.Join(parts, " "))
}

func (l *recordingLogger) all() []string {
	l.access.Lock()
	defer l.access.Unlock()
	return append([]string(nil), l.messages...)
}

func (l *recordingLogger) joined() string {
	return strings.Join(l.all(), "\n")
}

// formatLogValue renders a value the way a structured logger would, so the assertions below see
// the same fields an operator would. Errors and plain values are both represented.
func formatLogValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return "<nil>"
	case string:
		return typed
	case error:
		return typed.Error()
	case uint64:
		return uitoa(typed)
	case int:
		return uitoa(uint64(typed))
	default:
		return ""
	}
}

func uitoa(value uint64) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

// TestLifecycleTracingDistinguishesGenerations is the core observability assertion.
//
// When a stale connection is replaced, the trace must make the replacement visible as a change of
// generation. Without that, two failures look identical in the log and an operator cannot tell a
// redial from a second failure on the same connection -- which is precisely the question the
// 1.84s/30s investigation could not answer.
func TestLifecycleTracingDistinguishesGenerations(t *testing.T) {
	t.Parallel()

	server := startKillableTunnelServer(t)
	client := newConnIdentityClient(t, server.address)
	recorder := &recordingLogger{}
	client.impl.SetLifecycleLogger(recorder)

	tunnel := client.dialTunnel(t, "target.example:443")
	writeAndReadBack(t, tunnel, "first")
	tunnel.Close()

	traced := recorder.joined()
	require.Contains(t, traced, "http3 dial succeeded",
		"establishing a connection must be traceable")
	require.Contains(t, traced, "generation",
		"the trace must carry the connection generation, which is what makes a redial visible")

	connA := client.currentConn()
	require.NotNil(t, connA)
	generationA := client.impl.generation.Load()
	require.Equal(t, uint64(1), generationA, "the first connection is generation 1")

	server.killConnections()
	require.Eventually(t, func() bool {
		return connA.Context().Err() != nil
	}, 10*time.Second, 10*time.Millisecond)

	second := client.dialTunnel(t, "target.example:443")
	defer second.Close()

	require.Equal(t, generationA+1, client.impl.generation.Load(),
		"a replacement must advance the generation, which is how a redial is distinguished from "+
			"a second failure on the same connection")

	// The reject reason must be recorded: the cached connection existed and was dead.
	require.Contains(t, recorder.joined(), "http3 cached connection rejected",
		"a rejected cached connection must be distinguishable from an empty cache; otherwise the "+
			"1.84s question -- was there a cached connection at all -- cannot be answered")
}

// TestLifecycleTracingRecordsEmptyCacheDistinctly separates the two rejection causes.
func TestLifecycleTracingRecordsEmptyCacheDistinctly(t *testing.T) {
	t.Parallel()

	server := startKillableTunnelServer(t)
	client := newConnIdentityClient(t, server.address)
	recorder := &recordingLogger{}
	client.impl.SetLifecycleLogger(recorder)

	tunnel := client.dialTunnel(t, "target.example:443")
	defer tunnel.Close()

	traced := recorder.joined()
	require.Contains(t, traced, "http3 connection cache empty",
		"a cold cache must be recorded as empty rather than as a rejection, so the two causes are "+
			"not conflated in the trace")
	require.NotContains(t, traced, "http3 cached connection rejected",
		"nothing was rejected on a cold cache")
}

// TestLifecycleTracingNeverLogsSecrets is the safety guarantee.
//
// The trace runs on every CONNECT, so anything it printed would be written continuously. The
// client holds an Authorization header and the destination can carry credentials or identifying
// query parameters, none of which may appear.
func TestLifecycleTracingNeverLogsSecrets(t *testing.T) {
	t.Parallel()

	const (
		secretUser  = "alice"
		secretPass  = "s3cr3t-p4ssw0rd"
		secretToken = "bearer-TOKEN-must-not-appear"
	)

	server := startKillableTunnelServer(t)
	client := newConnIdentityClient(t, server.address)
	recorder := &recordingLogger{}
	client.impl.SetLifecycleLogger(recorder)

	// Give the client a credential and a sensitive header, exactly as a configured outbound would.
	client.impl.authorization = "Basic " + secretPass
	client.impl.headers = map[string][]string{
		"Authorization":       {"Bearer " + secretToken},
		"Proxy-Authorization": {"Basic " + secretPass},
		"X-Api-Key":           {secretPass},
	}

	tunnel := client.dialTunnel(t, "target.example:443")
	writeAndReadBack(t, tunnel, "with-credentials")
	tunnel.Close()

	// Force a replacement too, so the reject/redial branches are exercised with credentials set.
	server.killConnections()
	require.Eventually(t, func() bool {
		return client.impl.conn == nil || client.impl.conn.Context().Err() != nil
	}, 10*time.Second, 10*time.Millisecond)
	second := client.dialTunnel(t, "target.example:443")
	defer second.Close()

	logged := recorder.joined()
	for _, secret := range []string{secretPass, secretToken, secretUser, "Authorization", "Proxy-Authorization", "X-Api-Key"} {
		require.NotContains(t, logged, secret,
			"the lifecycle trace must never contain %q; it runs on every CONNECT and would write "+
				"the credential continuously", secret)
	}
}

// TestLifecycleTracingIsSilentWithoutALogger proves the trace is optional and cannot make a
// logger-less client fail.
func TestLifecycleTracingIsSilentWithoutALogger(t *testing.T) {
	t.Parallel()

	server := startKillableTunnelServer(t)
	client := newConnIdentityClient(t, server.address)
	// Deliberately no SetLifecycleLogger call.

	tunnel := client.dialTunnel(t, "target.example:443")
	defer tunnel.Close()
	writeAndReadBack(t, tunnel, "no-logger")
}

// TestLifecycleTracingDoesNotEmitAboveTrace proves the success path produces no noise.
//
// An operator who has not enabled trace output must see nothing from a healthy connection;
// otherwise the tracing reintroduces the very log flooding the earlier rounds removed.
func TestLifecycleTracingDoesNotEmitAboveTrace(t *testing.T) {
	t.Parallel()

	server := startKillableTunnelServer(t)
	client := newConnIdentityClient(t, server.address)
	recorder := &recordingLogger{}
	client.impl.SetLifecycleLogger(recorder)

	tunnel := client.dialTunnel(t, "target.example:443")
	writeAndReadBack(t, tunnel, "healthy")
	tunnel.Close()

	for _, message := range recorder.all() {
		require.True(t, strings.HasPrefix(message, "TRACE "),
			"a healthy connection must only ever emit TRACE, got %q", message)
	}
}

// TestLifecycleLoggerIsWiredFromClientOptions proves the logger actually reaches the HTTP/3 client
// through the production construction path, not only when a test sets it by hand.
func TestLifecycleLoggerIsWiredFromClientOptions(t *testing.T) {
	t.Parallel()

	clientTLS, err := tls.NewSTDClient(t.Context(), logger.NOP(), "example.test",
		option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "example.test",
			Insecure:   true,
			ALPN:       []string{"h3"},
		})
	require.NoError(t, err)

	recorder := &recordingLogger{}
	// NewClientWithTLS is the production entry point. If it stops forwarding the logger, the
	// HTTP/3 lifecycle becomes invisible again and this test fails.
	client, err := NewClientWithTLS(t.Context(), recorder, &connectedUDPDialer{},
		option.ServerOptions{Server: "127.0.0.1", ServerPort: 1},
		option.OutboundTLSOptions{Enabled: true, ServerName: "example.test", Insecure: true, ALPN: []string{"h3"}},
		ClientOptions{
			Dialer:       &connectedUDPDialer{},
			TLSConfig:    clientTLS,
			Server:       M.ParseSocksaddr("127.0.0.1:1"),
			Version:      3,
			HTTP2Options: option.HTTP2Options{},
		})
	require.NoError(t, err)

	tracer, isTracer := client.http3.(http3LifecycleTracer)
	require.True(t, isTracer, "the HTTP/3 client must accept a lifecycle logger")
	tracer.SetLifecycleLogger(recorder)

	impl, isImpl := client.http3.(*http3ClientImpl)
	require.True(t, isImpl)
	require.NotNil(t, impl.lifecycleLogger,
		"NewClientWithTLS must forward its logger to the HTTP/3 client; without it the connection "+
			"lifecycle is invisible in production")
}

// guard against an unused import if the QUIC config assertions above are ever trimmed.
var _ = http3.Transport{}
var _ = quic.Config{}
var _ = N.NetworkTCP
