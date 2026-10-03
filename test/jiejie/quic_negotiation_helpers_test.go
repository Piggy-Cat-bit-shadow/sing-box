package jiejie_test

import (
	"context"
	"crypto/tls"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

// QUIC ALPN negotiation helpers.
//
// # Why these perform a real handshake
//
// The property under test is which application protocol a transport actually negotiates, and that is
// decided by the TLS stack during a real handshake. Asserting against a configuration object would
// only prove the configuration was written the way the test expects - it cannot catch a listener that
// ignores it, or two transports sharing one TLS object and leaking each other's ALPN list. Those are
// exactly the defects these helpers exist to detect, so the handshake is real.
//
// # Why there is one implementation and two names
//
// The callers differ only in the TLS server name they dial against: the Native Naive inbound presents
// `naive.test` and the mixed HTTP inbound presents `example.org`. Sharing the negotiation keeps a
// single place where the handshake is performed, so a change to how it is done - the timeout, the
// QUIC config, the early-data behaviour - cannot apply to one caller and not the other.

// negotiateQUICALPNWithServerName completes a QUIC handshake and reports the negotiated ALPN.
//
// It returns the error rather than failing the test, because the caller decides whether an
// unsuccessful handshake is a failure or an expected outcome for the build it is running in.
func negotiateQUICALPNWithServerName(t *testing.T, port uint16, serverName string, offered []string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddrEarly(ctx,
		"127.0.0.1:"+strconv.Itoa(int(port)),
		&tls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
			NextProtos:         offered,
		}, &quic.Config{})
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.CloseWithError(0, "") }()
	return conn.ConnectionState().TLS.NegotiatedProtocol, nil
}

// negotiateQUICALPN negotiates against a Native Naive inbound.
func negotiateQUICALPN(t *testing.T, port uint16, offered []string) (string, error) {
	t.Helper()
	return negotiateQUICALPNWithServerName(t, port, "naive.test", offered)
}
