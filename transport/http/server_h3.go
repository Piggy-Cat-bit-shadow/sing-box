//go:build with_quic

package http

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/sagernet/quic-go"
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
		if quicConfig.MaxIncomingStreams == 0 {
			quicConfig.MaxIncomingStreams = 1 << 60
		}
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
		quicConfig.DisablePathManager = true
		quicConfig.EnableDatagrams = true
		quicListener, err := qtls.ListenEarly(udpConn, tlsConfig, quicConfig)
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		// bbr_profile is validated at configuration load; an unset value
		// resolves to standard, which is exactly the previous behaviour.
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
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				conn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), congestionProfile))
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
func parseBBRProfile(name string) (congestion_meta2.Profile, error) {
	switch name {
	case "", option.BBRProfileStandard:
		return congestion_meta2.ProfileStandard, nil
	case option.BBRProfileConservative:
		return congestion_meta2.ProfileConservative, nil
	case option.BBRProfileAggressive:
		return congestion_meta2.ProfileAggressive, nil
	default:
		return congestion_meta2.ProfileStandard, E.New("unsupported bbr_profile: ", name)
	}
}
