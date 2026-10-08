//go:build with_tailscale

package tailssh

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	gliderssh "github.com/sagernet/gliderssh"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/tailscale/tailcfg"
	gossh "golang.org/x/crypto/ssh"

	"github.com/stretchr/testify/require"
)

// testSSHContext is the minimum gliderssh.Context needed to drive applyAction.
// gliderssh's own context is unexported, and the banner path below does not touch
// the tailnet backend, so no tsnet.Server is involved.
type testSSHContext struct {
	context.Context
	sync.Mutex
	values map[any]any
}

func newTestSSHContext() *testSSHContext {
	return &testSSHContext{
		Context: context.Background(),
		values:  make(map[any]any),
	}
}

func (c *testSSHContext) User() string                        { return "test" }
func (c *testSSHContext) SessionID() string                   { return "test" }
func (c *testSSHContext) ClientVersion() string               { return "test" }
func (c *testSSHContext) ServerVersion() string               { return "test" }
func (c *testSSHContext) RemoteAddr() net.Addr                { return nil }
func (c *testSSHContext) LocalAddr() net.Addr                 { return nil }
func (c *testSSHContext) Permissions() *gliderssh.Permissions { return nil }
func (c *testSSHContext) Value(key any) any                   { return c.values[key] }
func (c *testSSHContext) SetValue(key, value any)             { c.values[key] = value }

// recordingBannerSender stands in for gossh.ServerPreAuthConn, which cannot be
// implemented outside x/crypto/ssh.
type recordingBannerSender struct {
	banners []string
	err     error
}

func (s *recordingBannerSender) SendAuthBanner(message string) error {
	s.banners = append(s.banners, message)
	return s.err
}

func newTestServer() *Server {
	return &Server{logger: logger.NOP()}
}

func testConnInfo(action *tailcfg.SSHAction) *sshConnInfo {
	return &sshConnInfo{
		userProfile: tailcfg.UserProfile{LoginName: "operator@example.com"},
		localUser:   "root",
		action:      action,
	}
}

// The banner must be delivered on the Reject path. BannerCallback was called after
// key exchange but before authentication, while connInfo is only installed into the
// context once authentication succeeds, so the operator's message never reached a
// rejected client at all — leaving it with a bare "permission denied".
func TestApplyActionSendsBannerBeforeReject(t *testing.T) {
	server := newTestServer()
	sender := &recordingBannerSender{}
	connInfo := testConnInfo(&tailcfg.SSHAction{
		Reject:  true,
		Message: "maintenance window in progress",
	})

	permissions, err := server.applyAction(newTestSSHContext(), sender, connInfo, tailcfg.NodeView{}, "root", netip.Addr{})
	var partial *gossh.PartialSuccessError
	require.ErrorAs(t, err, &partial)
	require.Nil(t, permissions)
	require.Equal(t, []string{"maintenance window in progress"}, sender.banners,
		"the operator's message is the only explanation a rejected client ever gets")
}

func TestApplyActionSendsBannerOnAccept(t *testing.T) {
	server := newTestServer()
	sender := &recordingBannerSender{}
	ctx := newTestSSHContext()
	connInfo := testConnInfo(&tailcfg.SSHAction{
		Accept:  true,
		Message: "welcome",
	})

	permissions, err := server.applyAction(ctx, sender, connInfo, tailcfg.NodeView{}, "root", netip.MustParseAddr("100.64.0.1"))
	require.NoError(t, err)
	require.NotNil(t, permissions)
	require.Equal(t, []string{"welcome"}, sender.banners)
	require.Same(t, connInfo, server.connInfoFromContext(ctx),
		"an accepted connection must install its connInfo for later sessions")
	require.NotEmpty(t, connInfo.connID)
}

func TestApplyActionOmitsEmptyBanner(t *testing.T) {
	server := newTestServer()
	sender := &recordingBannerSender{}

	_, err := server.applyAction(newTestSSHContext(), sender, testConnInfo(&tailcfg.SSHAction{Accept: true}), tailcfg.NodeView{}, "root", netip.Addr{})
	require.NoError(t, err)
	require.Empty(t, sender.banners, "an action without a message must not send an empty banner")
}

// A banner that cannot be delivered must deny the connection. If the failure were
// ignored, an action carrying Message + Accept would connect the client while the
// operator's instructions were silently lost.
func TestApplyActionDeniesWhenBannerFails(t *testing.T) {
	server := newTestServer()
	sender := &recordingBannerSender{err: errors.New("connection closed")}

	permissions, err := server.applyAction(newTestSSHContext(), sender, testConnInfo(&tailcfg.SSHAction{
		Accept:  true,
		Message: "welcome",
	}), tailcfg.NodeView{}, "root", netip.Addr{})
	var partial *gossh.PartialSuccessError
	require.ErrorAs(t, err, &partial)
	require.Nil(t, permissions)
	require.Equal(t, []string{"welcome"}, sender.banners)
}

// authenticate needs the pre-auth connection to send a banner, and the dead
// BannerCallback must not be reinstated: at banner time the callback would look up
// connInfo in a context that does not have it yet, so it can only ever return "".
func TestServerConfigInstallsPreAuthConnCallback(t *testing.T) {
	server := newTestServer()
	config := server.serverConfig(newTestSSHContext())
	require.NotNil(t, config.PreAuthConnCallback,
		"authenticate cannot deliver a banner without the pre-auth connection")
	require.Nil(t, config.BannerCallback)
}
