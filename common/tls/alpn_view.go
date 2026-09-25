package tls

import (
	stdTLS "crypto/tls"
	"net"
)

// Transport-scoped ALPN views.
//
// The problem. An inbound that serves BOTH TCP and QUIC shares one ServerConfig,
// because the certificate material, the ACME service and the file watcher must
// exist exactly once. The ALPN list, however, must NOT be shared: h3 is a
// QUIC-only protocol and h2/http1.1 are TCP-only. One combined list means a TCP
// client can negotiate h3, a protocol it cannot speak over TCP, and a QUIC client
// can negotiate h2.
//
// The two obvious alternatives both fail:
//
//   - Clone() cannot be used. STDServerConfig.Clone copies only the *tls.Config
//     and the handshake timeout, dropping the certificate provider, the ACME
//     service and the watcher, so the clone could neither serve certificates nor
//     reload them.
//
//   - Calling SetNextProtos before each handshake is a data race: TCP and QUIC
//     handshakes run concurrently against the same object.
//
// A VIEW works. It holds the real config and answers NextProtos from its own
// list, delegating every other call - including Start, Close and STDConfig - to
// the one underlying object. There is still exactly one certificate provider, one
// ACME service, one watcher and one Close, so no lifecycle is duplicated or lost,
// and each transport reads its own ALPN list.

// serverConfigView is a ServerConfig whose ALPN list is transport-scoped.
//
// Every method except the ALPN accessors and Server delegates to the wrapped
// config, so the view adds no lifecycle of its own.
type serverConfigView struct {
	ServerConfig
	nextProtos []string
}

// TransportALPNView returns a ServerConfig that reports nextProtos while
// delegating everything else to config.
//
// The result must be used INSTEAD OF cloning config, not alongside a clone: it
// shares the certificate provider, ACME service, watcher and Close path with
// config, which is what keeps those lifecycles single. It is a facade for
// handshake-time ALPN, not an independently startable or closable config.
//
// nextProtos is copied, so a caller mutating its slice afterwards cannot change
// what a live listener negotiates.
func TransportALPNView(config ServerConfig, nextProtos []string) ServerConfig {
	if config == nil {
		return nil
	}
	return &serverConfigView{
		ServerConfig: config,
		nextProtos:   append([]string(nil), nextProtos...),
	}
}

// NextProtos reports this view's ALPN list, not the shared config's.
func (v *serverConfigView) NextProtos() []string {
	return append([]string(nil), v.nextProtos...)
}

// SetNextProtos replaces this view's list only.
//
// It deliberately does NOT write through to the shared config: a per-transport
// mutation reaching the other transport is exactly the defect this type exists to
// prevent.
func (v *serverConfigView) SetNextProtos(nextProto []string) {
	v.nextProtos = append([]string(nil), nextProto...)
}

// STDConfig returns the shared *tls.Config with THIS view's ALPN applied.
//
// Overriding STDConfig is what makes the view work for QUIC. The sing-quic
// listener path resolves a config through STDConfig and hands the raw
// *tls.Config to quic-go, so a view that only overrode NextProtos would leave the
// QUIC transport negotiating from the shared list. Returning a per-call clone
// with the view's ALPN is what actually scopes the transport.
//
// The clone is per-call, so no two handshakes share the object being modified and
// TCP and QUIC cannot race. The shared config itself is never mutated.
//
// Certificates keep working because GetCertificate, GetConfigForClient and the
// other callbacks are function pointers copied into the clone; they continue to
// observe the live certificate state, which is what keeps ACME and file-watch
// reload applying to both transports.
func (v *serverConfigView) STDConfig() (*STDConfig, error) {
	shared, err := v.ServerConfig.STDConfig()
	if err != nil {
		return nil, err
	}
	scoped := shared.Clone()
	scoped.NextProtos = v.NextProtos()

	// GetConfigForClient must be wrapped too.
	//
	// STDServerConfig installs a GetConfigForClient callback that returns the
	// SHARED config, so Go replaces the handshake configuration with it partway
	// through the handshake and discards the NextProtos set above. That is what
	// made an earlier revision of this view ineffective even though its own
	// NextProtos and STDConfig were correct.
	//
	// The wrapper re-applies this view's ALPN to whatever the inner callback
	// returns, so certificate selection still comes from the live config while
	// the ALPN stays transport-scoped. The returned config is cloned rather than
	// mutated, because the inner callback hands back the shared object and
	// writing to it would leak into the other transport.
	if inner := scoped.GetConfigForClient; inner != nil {
		scoped.GetConfigForClient = func(hello *stdTLS.ClientHelloInfo) (*stdTLS.Config, error) {
			selected, err := inner(hello)
			if err != nil || selected == nil {
				return selected, err
			}
			scopedSelected := selected.Clone()
			scopedSelected.NextProtos = v.NextProtos()
			return scopedSelected, nil
		}
	}
	return scoped, nil
}

// Server negotiates using the shared config with this view's ALPN applied.
//
// It goes through STDConfig so there is exactly one place where the ALPN scoping
// happens, and the TCP and QUIC paths cannot drift apart.
func (v *serverConfigView) Server(conn net.Conn) (Conn, error) {
	scoped, err := v.STDConfig()
	if err != nil {
		return nil, err
	}
	return stdTLS.Server(conn, scoped), nil
}

// The embedded ServerConfig supplies Start, Close, ServerName, HandshakeTimeout,
// STDConfig, Client and Clone. Restating the ones that carry semantics here would
// risk silently diverging from the shared implementation, so only the two ALPN
// accessors and Server are overridden.

var _ ServerConfig = (*serverConfigView)(nil)
