//go:build with_quic

package http

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

func init() {
	ConfigureHTTP3ListenerFunc = func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.QUICOptions, maxHeaderBytes int) (io.Closer, error) {
		err := qtls.ConfigureHTTP3(tlsConfig)
		if err != nil {
			return nil, err
		}
		udpConn, err := listener.ListenUDP()
		if err != nil {
			return nil, err
		}
		quicConfig := httpclient.NewQUICConfig(options)
		// MaxIncomingStreams is deliberately NOT forced to 1 << 60 here.
		//
		// 1 << 60 is quic-go's INTERNAL "effectively unlimited" clamp
		// (config.go validateConfig caps the field at that value), so setting it
		// explicitly disabled the only server-side bound on concurrent streams
		// this listener had. Neither reference does that: quic-go/masque-go and
		// quic-go/connect-ip-go both construct their server without touching the
		// field, which leaves quic-go's default of 100
		// (protocol.DefaultMaxIncomingStreams).
		//
		// An operator who genuinely needs more sets max_concurrent_streams, which
		// NewQUICConfig already honours above; the production topology does
		// exactly that through server_profile. So the default is bounded and the
		// override is explicit, rather than the default being unbounded.
		// 0-RTT is disabled on the proxy inbound.
		//
		// Why: a CONNECT is not a safe, idempotent request. It creates a tunnel,
		// and 0-RTT data is REPLAYABLE BY DESIGN, so a captured CONNECT could be
		// replayed by a network attacker. The HTTP/3 layer does not filter this
		// for us -- quic-go's own comment in http3/server.go says "It's the
		// client's responsibility to decide which requests are eligible for
		// 0-RTT" -- so a third-party client is free to send CONNECT as early data
		// if the server permits 0-RTT at all.
		//
		// Our own client already refuses to do so: it gates every CONNECT on
		// HandshakeComplete (see client_h3.go awaitHandshake). This setting makes
		// the server enforce the same rule for clients that do not.
		//
		// The cost is nil for the data path: session resumption still works, and
		// only the ability to send application data in the first flight is lost,
		// which for a proxy tunnel means one extra round trip on a resumed
		// connection. That is a fair trade for removing a replay vector on a
		// production inbound.
		quicConfig.Allow0RTT = false
		// The path manager is left at quic-go's default (enabled), which is what
		// both references get: neither masque-go nor connect-ip-go sets
		// DisablePathManager. Disabling migration is a production choice, so it
		// is opted into through quic_disable_path_manager rather than compiled
		// into the protocol default.
		quicConfig.DisablePathManager = options.DisablePathManager
		quicConfig.EnableDatagrams = true
		quicListener, err := qtls.ListenEarly(udpConn, tlsConfig, quicConfig)
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		// bbr_profile is validated at configuration load. An UNSET value now means
		// "leave quic-go's own congestion control", not "BBR standard".
		//
		// The reason is reference parity: quic-go/masque-go and
		// quic-go/connect-ip-go both construct their server without setting a
		// congestion control, so they get the library default (CUBIC). Forcing
		// BBR here made the protocol default a production tuning choice, which is
		// the same class of silent divergence the HTTP/3 audit removed from the
		// Native Naive listener.
		//
		// A deployment that wants BBR names it, and the production topology does
		// that through server_profile.
		congestionProfile, profileErr := parseBBRProfile(options.BBRProfile.BBRProfileValue())
		if profileErr != nil {
			quicListener.Close()
			udpConn.Close()
			return nil, profileErr
		}
		http3Server := &http3.Server{
			Handler:         handler,
			EnableDatagrams: true,
			// max_header_bytes must apply to HTTP/3 as well as HTTP/2. Without
			// this, the HTTP/3 server silently used http.DefaultMaxHeaderBytes
			// and the configured limit only affected the loopback HTTP/2
			// listener, which is the opposite of what the profile is for.
			MaxHeaderBytes: maxHeaderBytes,
			// idle_timeout is the HTTP/3 APPLICATION-layer idle timeout, which
			// is a different knob from quic.Config.MaxIdleTimeout.
			//
			// quic.Config.MaxIdleTimeout (set inside httpclient.NewQUICConfig)
			// is the QUIC transport idle timeout. It is refreshed by ANY packet
			// on the connection, including a bare PING, so a peer that does
			// nothing but PING can hold a fully established QUIC connection --
			// and all of its state -- open indefinitely without ever creating an
			// HTTP/3 request stream.
			//
			// http3.Server.IdleTimeout closes that gap. Measured against
			// quic-go v0.61.0-sing-box-mod.7 (http3/server_conn.go):
			//
			//   - the timer is armed when the connection is created;
			//   - handleRequestStream STOPS it as soon as a request stream
			//     arrives, so an in-flight request can never be killed by it;
			//   - clearStream RESETS it only when the LAST active stream goes
			//     away, so a long-lived CONNECT tunnel is safe for as long as it
			//     is open and restarts the countdown only once the connection is
			//     genuinely idle;
			//   - PING frames do not touch it at all ("activity at the QUIC layer
			//     like PING frames are not considered", http3/server.go).
			//
			// That is exactly the intended behaviour: authenticated long-lived
			// CONNECT tunnels are unaffected, while a connection that completes
			// the QUIC handshake and then never opens a request stream is
			// reclaimed. This closes the established-connection resource gap
			// without patching quic-go and without inventing a connection-count
			// cap that has no measured basis.
			//
			// Zero (the upstream default, and what an unselected profile leaves
			// here) disables the timer entirely, so upstream behaviour is
			// preserved when no profile is configured.
			IdleTimeout: time.Duration(options.IdleTimeout),
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				// A nil profile means "keep quic-go's default sender". Calling
				// SetCongestionControl with a nil cannot be expressed, so the
				// call is skipped rather than guarded.
				if congestionProfile != nil {
					conn.SetCongestionControl(congestionProfile(conn))
				}
				return log.ContextWithNewID(ctx)
			},
		}
		go func() {
			serveErr := http3Server.ServeListener(quicListener)
			udpConn.Close()
			// A listener that stops because the server is shutting down is
			// expected. Anything else is a real fault and stays an error.
			if serveErr != nil && !E.IsClosedOrCanceled(serveErr) && !isExpectedH3Closure(serveErr) {
				logger.Error("http3 server closed: ", serveErr)
			}
		}()
		return quicListener, nil
	}
	HTTP3StreamFunc = func(ctx context.Context, writer http.ResponseWriter) (DatagramStream, bool) {
		streamer, isStreamer := writer.(http3.HTTPStreamer)
		if !isStreamer {
			return nil, false
		}
		settingser, isSettingser := writer.(http3.Settingser)
		if !isSettingser {
			return nil, false
		}
		select {
		case <-settingser.ReceivedSettings():
		case <-ctx.Done():
			return nil, false
		}
		return &datagramStream{
			Stream:           streamer.HTTPStream(),
			datagramsEnabled: settingser.Settings().EnableDatagrams,
		}, true
	}
}

type datagramStream struct {
	*http3.Stream
	datagramsEnabled bool
}

// DatagramsEnabled reports whether the peer negotiated HTTP Datagrams.
//
// This is the answer the session must use instead of a type assertion: the stream
// implements the interface either way, so the type says nothing about the
// capability. Reading it from the peer's SETTINGS is what makes the fallback
// decision correct.
func (s *datagramStream) DatagramsEnabled() bool {
	return s.datagramsEnabled
}

func (s *datagramStream) SendDatagram(payload []byte) error {
	if !s.datagramsEnabled {
		return ErrDatagramUnsupported
	}
	err := s.Stream.SendDatagram(payload)
	if err == nil {
		return nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return &DatagramTooLargeError{MaxPayloadSize: int(tooLarge.MaxDatagramPayloadSize) - VarintLen(uint64(s.Stream.StreamID()/4))}
	}
	return err
}

func (s *datagramStream) Close() error {
	s.Stream.SetWriteDeadline(time.Now())
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}

// parseBBRProfile maps an option name onto a profile that actually exists in
// congestion_meta2. Only these three are accepted; nothing is invented here.
func parseBBRProfile(name string) (func(conn *quic.Conn) congestion.CongestionControl, error) {
	// "" means "leave the library default", which is what an unconfigured
	// HTTP/3 server gets. It used to resolve to ProfileStandard, which made BBR
	// the protocol default rather than an explicit choice; the references set no
	// congestion control at all.
	if name == "" {
		return nil, nil
	}
	var profile congestion_meta2.Profile
	switch name {
	case option.BBRProfileStandard:
		profile = congestion_meta2.ProfileStandard
	case option.BBRProfileConservative:
		profile = congestion_meta2.ProfileConservative
	case option.BBRProfileAggressive:
		profile = congestion_meta2.ProfileAggressive
	default:
		return nil, E.New("unsupported bbr_profile: ", name)
	}
	return func(conn *quic.Conn) congestion.CongestionControl {
		return congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), profile)
	}, nil
}
