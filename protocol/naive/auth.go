package naive

import (
	"crypto/sha256"
	"crypto/subtle"

	"github.com/sagernet/sing/common/auth"
)

// naiveAuthenticator verifies inbound credentials without a username-existence
// timing signal.
//
// Why this exists rather than sing/common/auth.Authenticator: the upstream
// implementation compares passwords with common.Contains, which is plain string
// equality that returns as soon as it finds a match. This inbound is reachable by
// an unauthenticated network peer, so that timing is attacker-observable.
//
// The first version of this file kept a map from username to password digests,
// which still leaked: an unknown username returned immediately after the map
// lookup, while a known one hashed the password and walked its digest list. The
// two paths did measurably different work, so "does this user exist" was
// distinguishable from response timing alone.
//
// This version keeps a FLAT list and walks all of it for every request, so a
// known user, an unknown user, a wrong password and a correct password all do the
// same work. It is also structurally closer to the reference:
// klzgrad/forwardproxy's checkCredentials iterates h.AuthCredentials and compares
// each entry with subtle.ConstantTimeCompare, with no username lookup at all.
// (An earlier comment in this file described the reference as looking the
// credential up by username. That was wrong; the reference walks a flat list.)
//
// HARDENING, not reference parity. The reference itself documents its comparison
// as knowingly imperfect ("Please do not consider this to be timing-attack-safe
// code ... e.g. size of smallest credentials is guessable"). There is no intent to
// reproduce that weakness, so this is deliberately stronger while remaining
// observationally identical on the wire.
type naiveAuthenticator struct {
	// credentials holds SHA-256 digests of "username:password".
	//
	// A digest is used rather than the raw pair so every comparison is a
	// fixed-size operation: subtle.ConstantTimeCompare returns immediately on a
	// length mismatch, so comparing raw strings would leak the length of the
	// configured credential through timing.
	//
	// Every entry is compared for every request, with no early exit, so the
	// number of comparisons depends only on the configuration and never on the
	// presented credential.
	credentials [][sha256.Size]byte
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
		credentials: make([][sha256.Size]byte, 0, len(users)),
	}
	for _, user := range users {
		// Every configured pair becomes its own entry. A username may appear
		// more than once with different passwords, which the upstream
		// authenticator also supports; a flat list represents that directly and
		// needs no per-user accumulation.
		authenticator.credentials = append(authenticator.credentials,
			sha256.Sum256([]byte(user.Username+":"+user.Password)))
	}
	return authenticator
}

// Verify reports whether the credential pair is accepted.
//
// The presented pair is hashed once and compared against every configured entry.
// Results are accumulated with a constant-time OR, so the comparison count does
// not depend on which entry matched - or on whether any did.
func (a *naiveAuthenticator) Verify(username string, password string) bool {
	if a == nil || len(a.credentials) == 0 {
		return false
	}
	presented := sha256.Sum256([]byte(username + ":" + password))
	var matched int
	for index := range a.credentials {
		matched |= subtle.ConstantTimeCompare(presented[:], a.credentials[index][:])
	}
	return matched == 1
}
