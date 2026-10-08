package socks

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	N "github.com/sagernet/sing/common/network"
)

// ---------------------------------------------------------------------------
// TD-007: a SOCKS4 user id is an IDENT claim, not a credential.
//
// sing's SOCKS4 handshake puts the request's USERID into the context
// unconditionally (protocol/socks/handshake.go, `auth.ContextWithUser(ctx,
// request.Username)`), and only *verifies* it when an authenticator was
// configured. The inbound used to promote whatever it found in the context to
// metadata.User, so with no `users` configured any client could name itself
// whatever it liked and be routed, logged and reported under that identity:
//
//   - route rules that match on `user` would treat the claim as authenticated;
//   - connection logs and the Clash API would attribute the flow to it.
//
// The rule these tests pin: the claim becomes metadata.User only when a
// configured credential table actually verified it. With no users there is
// nothing to verify against, so the claim is protocol input and nothing more.
// ---------------------------------------------------------------------------

func TestSOCKS4UserIDIsNotAnIdentityWithoutUsers(t *testing.T) {
	userIDs := []string{"alice", "root", "", "very-long-ident-claim-that-is-not-a-credential"}
	for _, userID := range userIDs {
		userID := userID
		t.Run(userID, func(t *testing.T) {
			harness := newInboundHarness(t, nil)
			conn := newScriptedConn(socks4Connect([4]byte{203, 0, 113, 5}, 9050, userID))
			recorder := newCloseRecorder()
			harness.newConnection(context.Background(), conn, recorder.handler())
			// NewConnection is synchronous: it has returned, the session is live,
			// and nothing may have reported it closed yet.
			if recorder.count() != 0 {
				t.Fatalf("onClose ran %d times on a live session that was never closed", recorder.count())
			}

			routed := harness.router.waitConnection(t)
			if routed.metadata.User != "" {
				t.Fatalf("SOCKS4 user id %q was promoted to metadata.User with no users configured", routed.metadata.User)
			}
			if got := routed.metadata.Destination.AddrString(); got != "203.0.113.5" {
				t.Fatalf("destination = %q, want the requested address", got)
			}
			if routed.metadata.Destination.Port != 9050 {
				t.Fatalf("destination port = %d, want 9050", routed.metadata.Destination.Port)
			}
		})
	}
}

func TestSOCKS4VerifiedUserIDIsAnIdentity(t *testing.T) {
	harness := newInboundHarness(t, []auth.User{{Username: "alice"}})
	conn := newScriptedConn(socks4Connect([4]byte{203, 0, 113, 5}, 9050, "alice"))
	harness.newConnection(context.Background(), conn, nil)

	routed := harness.router.waitConnection(t)
	if routed.metadata.User != "alice" {
		t.Fatalf("authenticated SOCKS4 user = %q, want alice", routed.metadata.User)
	}
}

func TestSOCKS4UnverifiedUserIDIsRejected(t *testing.T) {
	harness := newInboundHarness(t, []auth.User{{Username: "alice"}})
	conn := newScriptedConn(socks4Connect([4]byte{203, 0, 113, 5}, 9050, "bob"))
	recorder := newCloseRecorder()
	harness.newConnection(context.Background(), conn, recorder.handler())

	harness.router.requireNoConnection(t, 200*time.Millisecond)
	if !recorder.wait(2 * time.Second) {
		t.Fatal("rejected session never reported through onClose")
	}
	if recorder.count() != 1 {
		t.Fatalf("onClose ran %d times, want exactly once", recorder.count())
	}
	// The SOCKS4 rejection reply is 0x00 0x5B, which is what tells the client it
	// was refused rather than silently dropped.
	written := conn.written()
	if len(written) < 2 || written[1] != 0x5B {
		t.Fatalf("rejection reply = % x, want a 0x5B SOCKS4 refusal", written)
	}
}

func TestSOCKS5VerifiedUserIDIsAnIdentity(t *testing.T) {
	harness := newInboundHarness(t, []auth.User{{Username: "u1", Password: "p1"}})
	conn := newScriptedConn(socks5WithPassword("example.com", 443, "u1", "p1"))
	harness.newConnection(context.Background(), conn, nil)

	routed := harness.router.waitConnection(t)
	if routed.metadata.User != "u1" {
		t.Fatalf("authenticated SOCKS5 user = %q, want u1", routed.metadata.User)
	}
	if got := routed.metadata.Destination.AddrString(); got != "example.com" {
		t.Fatalf("destination = %q, want example.com", got)
	}
}

func TestSOCKS5WrongPasswordIsRejected(t *testing.T) {
	harness := newInboundHarness(t, []auth.User{{Username: "u1", Password: "p1"}})
	conn := newScriptedConn(socks5WithPassword("example.com", 443, "u1", "wrong"))
	recorder := newCloseRecorder()
	harness.newConnection(context.Background(), conn, recorder.handler())

	harness.router.requireNoConnection(t, 200*time.Millisecond)
	if !recorder.wait(2 * time.Second) {
		t.Fatal("rejected session never reported through onClose")
	}
	if recorder.count() != 1 {
		t.Fatalf("onClose ran %d times, want exactly once", recorder.count())
	}
}

func TestSOCKS5WithoutUsersCarriesNoIdentity(t *testing.T) {
	harness := newInboundHarness(t, nil)
	conn := newScriptedConn(socks5NoAuth("example.com", 443))
	harness.newConnection(context.Background(), conn, nil)

	routed := harness.router.waitConnection(t)
	if routed.metadata.User != "" {
		t.Fatalf("unauthenticated SOCKS5 session reported user %q", routed.metadata.User)
	}
}

// closeRecorder records CloseHandlerFunc invocations so a test can assert
// exactly-once reporting without racing the rejection path.
type closeRecorder struct {
	calls  chan error
	closed chan struct{}
}

func newCloseRecorder() *closeRecorder {
	return &closeRecorder{
		calls:  make(chan error, 8),
		closed: make(chan struct{}),
	}
}

func (c *closeRecorder) handler() N.CloseHandlerFunc {
	return func(err error) {
		select {
		case c.calls <- err:
		default:
		}
		select {
		case <-c.closed:
		default:
			close(c.closed)
		}
	}
}

func (c *closeRecorder) count() int {
	return len(c.calls)
}

func (c *closeRecorder) wait(timeout time.Duration) bool {
	select {
	case <-c.closed:
		return true
	case <-time.After(timeout):
		return false
	}
}
