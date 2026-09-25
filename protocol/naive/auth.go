package naive

import (
	"crypto/sha256"
	"crypto/subtle"

	"github.com/sagernet/sing/common/auth"
)

// naiveAuthenticator verifies inbound credentials with a constant-time password
// comparison.
//
// Why this exists rather than sing/common/auth.Authenticator: the upstream
// implementation compares passwords with common.Contains, which is plain string
// equality and returns as soon as it finds a match. That is fine for its own
// callers, but this inbound is reachable by an unauthenticated network peer, so
// the comparison timing is attacker-observable and a byte-by-byte early exit
// leaks how much of a guessed password was correct.
//
// The fix is deliberately local. Changing sing/common/auth would alter the
// comparison used by every other protocol in the tree, which is out of scope for
// a Native Naive hardening change and would need its own review.
//
// Username lookup is a map access and is NOT constant-time. That is a deliberate
// limit, matching the reference: forwardproxy also distinguishes known from
// unknown users (it looks the credential up by username before comparing), so
// hiding the username-existence signal is not part of the compatibility target
// and doing so here would be security theatre without changing the observable
// behaviour.
type naiveAuthenticator struct {
	// users maps a username to the SHA-256 digests of its accepted passwords.
	//
	// Digests are stored rather than plaintext so the comparison is a fixed-size
	// operation that does not depend on the password length. subtle's
	// ConstantTimeCompare returns immediately on a length mismatch, so comparing
	// raw passwords would leak the length of the correct one.
	users map[string][][sha256.Size]byte
}

// newNaiveAuthenticator builds an authenticator from the configured users.
//
// It returns nil when no users are configured, mirroring the upstream
// constructor: callers must treat a nil authenticator as "nothing verifies".
func newNaiveAuthenticator(users []auth.User) *naiveAuthenticator {
	if len(users) == 0 {
		return nil
	}
	authenticator := &naiveAuthenticator{
		users: make(map[string][][sha256.Size]byte, len(users)),
	}
	for _, user := range users {
		// Append rather than overwrite: a username may legitimately appear more
		// than once with different passwords, which the upstream authenticator
		// also supports. Overwriting would silently drop every earlier password
		// for that user.
		authenticator.users[user.Username] = append(
			authenticator.users[user.Username],
			sha256.Sum256([]byte(user.Password)),
		)
	}
	return authenticator
}

// Verify reports whether the credential pair is accepted.
//
// Every configured password digest for the username is compared, without an
// early exit, and the results are accumulated with a constant-time OR so the
// total number of comparisons does not depend on which password matched.
func (a *naiveAuthenticator) Verify(username string, password string) bool {
	if a == nil {
		return false
	}
	passwords, loaded := a.users[username]
	if !loaded || len(passwords) == 0 {
		return false
	}
	presented := sha256.Sum256([]byte(password))
	var matched int
	for _, expected := range passwords {
		matched |= subtle.ConstantTimeCompare(presented[:], expected[:])
	}
	return matched == 1
}
