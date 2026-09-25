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
// MaxIncomingStreams and DisablePathManager remain explicit. They are recorded
// in docs/JIEJIE-NAIVE-H3-AUDIT.md as differences from the reference that have
// NOT been aligned, because aligning them needs runtime evidence rather than a
// config diff.
func nativeNaiveQUICConfig() *quic.Config {
	return &quic.Config{
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
		DisablePathManager: true,
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

		var congestionControl func(conn *quic.Conn) congestion.CongestionControl
		timeFunc := ntp.TimeFuncFromContext(ctx)
		if timeFunc == nil {
			timeFunc = time.Now
		}
		switch options.QUICCongestionControl {
		case "", "bbr":
			congestionControl = func(conn *quic.Conn) congestion.CongestionControl {
				return congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), congestion_meta2.ProfileStandard)
			}
		case "cubic":
			congestionControl = func(conn *quic.Conn) congestion.CongestionControl {
				return congestion_meta1.NewCubicSender(
					congestion_meta1.DefaultClock{TimeFunc: timeFunc},
					conn.InitialPacketSize(),
					false,
				)
			}
		case "reno":
			congestionControl = func(conn *quic.Conn) congestion.CongestionControl {
				return congestion_meta1.NewCubicSender(
					congestion_meta1.DefaultClock{TimeFunc: timeFunc},
					conn.InitialPacketSize(),
					true,
				)
			}
		default:
			return nil, E.New("unknown quic congestion control: ", options.QUICCongestionControl)
		}

		quicListener, err := qtls.ListenEarly(udpConn, tlsConfig, nativeNaiveQUICConfig())
		if err != nil {
			udpConn.Close()
			return nil, err
		}

		h3Server := &http3.Server{
			Handler: handler,
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				conn.SetCongestionControl(congestionControl(conn))
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
