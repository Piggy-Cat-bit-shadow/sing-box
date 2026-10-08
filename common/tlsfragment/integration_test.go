//go:build tlsfragment_integration

// The real-internet fragmentation check.
//
// # Why this file carries both a build tag and an environment variable
//
// Either gate alone gets run by accident. A build tag is invisible in a plain `go test ./...` and is
// easy to leave in a release script; an environment variable can be inherited by a test run that had
// no intention of touching the network - a CI job that exports everything, a shell that was used for
// an earlier experiment. The tag means the default suite does not even compile this file, and the
// variable means someone who built with the tag still has to say that the dial was intended.
//
// # What it proves that the deterministic suite cannot
//
// conn_test.go proves the STRUCTURE of the fragmentation against a loopback listener: the piece
// count, the cut position, the record headers, the byte-exact reconstruction. A loopback listener
// has no middlebox on the path, so it cannot prove anything about what a real network does with the
// pieces. These tests dial 1.1.1.1:443 through the wrapper for each mode and require the handshake to
// complete, which is exactly the assertion the default suite used to make and no weaker.
//
// Run:
//
//	SING_BOX_TLSFRAGMENT_INTEGRATION=1 go test -tags tlsfragment_integration \
//	    ./common/tlsfragment/ -run Integration -v
package tf_test

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"testing"
	"time"

	tf "github.com/sagernet/sing-box/common/tlsfragment"

	"github.com/stretchr/testify/require"
)

const (
	integrationEnv        = "SING_BOX_TLSFRAGMENT_INTEGRATION"
	integrationServer     = "1.1.1.1:443"
	integrationServerName = "www.cloudflare.com"
	integrationDialWait   = 10 * time.Second
)

func requireIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(integrationEnv) == "" {
		t.Skipf("set %s=1 to run the real-internet fragmentation check", integrationEnv)
	}
}

// integrationHandshake dials the public endpoint through the wrapper and completes a handshake.
//
// The dial carries a deadline where the original test had none. That is not a relaxation: the
// original relied on the operating system's own connect timeout, which on a host with no route
// produced the 75-second red this restructuring exists to remove. An explicitly gated test that is
// asked to run and cannot reach the network should say so promptly.
func integrationHandshake(t *testing.T, splitPacket, splitRecord bool) {
	t.Helper()
	requireIntegration(t)
	tcpConn, err := net.DialTimeout("tcp", integrationServer, integrationDialWait)
	require.NoError(t, err)
	defer tcpConn.Close()
	tlsConn := tls.Client(
		tf.NewConn(tcpConn, context.Background(), splitPacket, splitRecord, 0),
		&tls.Config{ServerName: integrationServerName},
	)
	require.NoError(t, tlsConn.Handshake())
}

func TestTLSFragmentIntegration(t *testing.T) {
	t.Parallel()
	integrationHandshake(t, true, false)
}

func TestTLSRecordFragmentIntegration(t *testing.T) {
	t.Parallel()
	integrationHandshake(t, false, true)
}

func TestTLS2FragmentIntegration(t *testing.T) {
	t.Parallel()
	integrationHandshake(t, true, true)
}
