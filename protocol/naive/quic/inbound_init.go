package quic

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-quic"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/ntp"
)

// nativeNaiveQUICConfig builds the QUIC configuration for the Native Naive
// HTTP/3 listener.
//
// It is a function rather than an inline literal so the configuration can be
// asserted by a test without starting a listener.
//
// Allow0RTT is deliberately NOT set, which leaves quic-go's default of false:
//
//   - HTTP/3 works without 0-RTT. It is a latency optimisation, not a
//     prerequisite, so refusing early data costs a round trip on a resumed
//     connection and nothing else.
//   - A CONNECT tunnel is precisely the wrong place to accept early data. 0-RTT
//     data is replayable by anyone who captures it, so an early-data CONNECT can
//     be replayed against this server. A proxy that authenticates the tunnel
//     request should not carry that exposure for a latency win.
//   - The pinned reference (Caddy v2.10.0 + forwardproxy@d62c80d3) does not
//     enable 0-RTT either: its quic.Config sets only Versions and Tracer. This
//     fork prefers reference-like defaults.
//
// The protocol default is reference-like: nothing that changes wire behaviour is
// hardcoded. Properties Caddy leaves to quic-go - the path manager among them -
// are left to quic-go here too, and the fork's production tuning is opt-in
// through the inbound options.
//
// Rationale, matching how the rest of this fork treats retained differences: a
// protocol implementation should not silently disagree with the reference. Where
// this deployment WANTS different behaviour, that is stated in configuration,
// where it can be seen, tested and reverted, rather than compiled in.
//
// See docs/JIEJIE-NAIVE-H3-AUDIT.md. DisablePathManager is recorded there as a
// retained difference; making it configurable is what allows the default to go
// back to reference-like without discarding the production choice.
func nativeNaiveQUICConfig(options option.NaiveInboundOptions) *quic.Config {
	return &quic.Config{
		// QUIC versions are pinned EXPLICITLY, matching the reference.
		//
		// Caddy v2.10's startHTTP3 builds
		// &quic.Config{Versions: []quic.Version{quic.Version1, quic.Version2}},
		// so v1 and v2 are a stated decision there, not an inherited default.
		//
		// Measured: this listener accepts exactly [v1 v2] and so does the
		// reference. They agreed only because quic-go's default happens to be
		// both, which is a dependency property - a dependency bump that changed
		// it would silently drop v2 support here with nothing failing. Pinning
		// makes the set a decision this repository owns, and the differential
		// test compares the two sets so a divergence is visible.
		Versions: []quic.Version{quic.Version1, quic.Version2},
		// MaxIncomingStreams is deliberately NOT set, so it takes the quic-go
		// default of 100 (internal/protocol.DefaultMaxIncomingStreams).
		//
		// It used to be 1 << 60, which is literally the value quic-go uses
		// INTERNALLY as its "effectively unlimited" clamp (config.go validateConfig
		// caps MaxIncomingStreams at 1 << 60). So the old setting was the
		// library's own no-limit sentinel, not a considered limit, and it matched
		// neither the library default nor the reference.
		//
		// Measured before removing it, on Linux, with concurrent HTTP/3 request
		// streams from one connection:
		//
		//	streams  accepted  refused  RSS+KiB  goroutines  fds
		//	1        1         0        344      0           0
		//	8        8         0        520      0           0
		//	32       32        0        848      0           0
		//	64       64        0        1732     0           0
		//	128      128       0        1728     0           0
		//	256      256       0        2504     0           0
		//
		// So 256 concurrent streams cost only ~2.5 MiB with no extra goroutines or
		// descriptors, and the default of 100 covers that comfortably. There is no
		// compatibility evidence that a Naive client needs more, and the old value
		// removed the only server-side bound on concurrent HTTP/3 work on a
		// ~1 GiB host. This aligns with the reference, whose quic.Config does not
		// set the field either.
		//
		// DisablePathManager is NOT set by default, so quic-go's default (path
		// manager enabled) applies and the protocol default matches the
		// reference. Caddy sets only Versions and Tracer on its quic.Config, so
		// leaving the field unset is what "reference-like" means here. A
		// deployment that wants migration disabled opts in explicitly through
		// quic_disable_path_manager.
		DisablePathManager: options.QUICDisablePathManager,
	}
}

// newNaiveCongestionControl resolves quic_congestion_control to a sender factory.
//
// It is a separate function so the VALUE VALIDATION can be tested without a UDP
// socket: the listener constructor needs a real socket, so a test that wanted to
// check "bogus is refused" through the constructor would have to bind a port. The
// constructor and the test both call this, so there is one validation and no
// second copy in the test that could drift from it.
//
// A nil return with a nil error means "use the library default", which is what an
// unset value and the explicit "default" both select. The reference sets neither a
// congestion control nor a path manager, so an unset value staying with quic-go is
// the reference-like behaviour; BBR is a production choice and must be named.
//
// Matching is exact. No whitespace trimming and no case folding: an unrecognised
// value is a configuration error the operator should see, and silently accepting
// "BBR" or " bbr" would make a typo look like it worked.
func newNaiveCongestionControl(name string, timeFunc func() time.Time) (func(conn *quic.Conn) congestion.CongestionControl, error) {
	switch name {
	case "", "default":
		// nil leaves quic-go's own default sender in place.
		return nil, nil
	case "bbr":
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), congestion_meta2.ProfileStandard)
		}, nil
	case "cubic":
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_meta1.NewCubicSender(
				congestion_meta1.DefaultClock{TimeFunc: timeFunc},
				conn.InitialPacketSize(),
				false,
			)
		}, nil
	case "reno":
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_meta1.NewCubicSender(
				congestion_meta1.DefaultClock{TimeFunc: timeFunc},
				conn.InitialPacketSize(),
				true,
			)
		}, nil
	default:
		return nil, E.New("unknown quic congestion control: ", name)
	}
}

func init() {
	naive.ConfigureHTTP3ListenerFunc = func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.NaiveInboundOptions) (io.Closer, error) {
		err := qtls.ConfigureHTTP3(tlsConfig)
		if err != nil {
			return nil, err
		}
		// ALPN is deliberately NOT set here. The inbound resolves the complete
		// list once, before any listener starts, precisely so that the TLS config
		// this function SHARES with the TCP listener cannot be changed after TCP
		// has begun handshaking. Setting h3 here would leak a QUIC-only protocol
		// into the TCP ALPN list, and the object cannot be cloned safely
		// (STDServerConfig.Clone drops the certificate provider, ACME service and
		// watcher).
		if !common.Contains(tlsConfig.NextProtos(), http3.NextProtoH3) {
			return nil, E.New("HTTP/3 requires h3 in the TLS ALPN list, but it is ",
				"absent; the inbound must resolve ALPN before starting listeners")
		}

		udpConn, err := listener.ListenUDP()
		if err != nil {
			return nil, err
		}

		timeFunc := ntp.TimeFuncFromContext(ctx)
		if timeFunc == nil {
			timeFunc = time.Now
		}
		// Unset means "use the library default", which is CUBIC in quic-go and is
		// therefore what the reference gets. The fork's BBR preference is a
		// performance choice, opted into by name rather than being what an unset
		// field silently selects. The resolution and its validation live in
		// newNaiveCongestionControl so they can be tested without a socket.
		congestionControl, err := newNaiveCongestionControl(options.QUICCongestionControl, timeFunc)
		if err != nil {
			return nil, err
		}

		quicListener, err := qtls.ListenEarly(udpConn, tlsConfig, nativeNaiveQUICConfig(options))
		if err != nil {
			udpConn.Close()
			return nil, err
		}

		h3Server := &http3.Server{
			Handler: handler,
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				// A nil selector means "keep quic-go's default congestion
				// control". Calling SetCongestionControl with a nil would be a
				// nil dereference, so it is skipped rather than guarded.
				if congestionControl != nil {
					conn.SetCongestionControl(congestionControl(conn))
				}
				return log.ContextWithNewID(ctx)
			},
		}

		go func() {
			sErr := h3Server.ServeListener(quicListener)
			udpConn.Close()
			if sErr != nil && !E.IsClosedOrCanceled(sErr) {
				logger.Error("http3 server closed: ", sErr)
			}
		}()

		return quicListener, nil
	}
	naive.WrapError = qtls.WrapError
}
