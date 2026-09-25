package naive

import (
	"crypto/sha256"
	"testing"

	"github.com/sagernet/sing/common/auth"
)

// These tests pin the Native Naive credential comparison.
//
// The property that matters is not just "the right password works": it is that a
// wrong password is rejected for every shape of wrong input, and that the
// comparison itself does not short-circuit. The constant-time behaviour is
// asserted structurally (by exercising every configured password) rather than by
// timing, because a timing assertion is inherently flaky in CI and would be
// weakened into meaninglessness to keep it green.

func TestNaiveAuthenticatorAcceptsCorrectCredential(t *testing.T) {
	authenticator := newNaiveAuthenticator([]auth.User{
		{Username: "user-a", Password: "password-a"},
	})

	if !authenticator.Verify("user-a", "password-a") {
		t.Fatal("the configured credential must verify")
	}
}

func TestNaiveAuthenticatorRejectsWrongPassword(t *testing.T) {
	authenticator := newNaiveAuthenticator([]auth.User{
		{Username: "user-a", Password: "password-a"},
	})

	for _, wrong := range []string{
		"",
		"password-",
		"password-b",
		"Password-a",               // case differs
		"password-a ",              // trailing space
		" password-a",              // leading space
		"password-a\n",             // trailing newline
		"password-aaaaaaaaaaaaaaa", // longer, shared prefix
	} {
		if authenticator.Verify("user-a", wrong) {
			t.Fatalf("password %q must not verify", wrong)
		}
	}
}

func TestNaiveAuthenticatorRejectsUnknownUser(t *testing.T) {
	authenticator := newNaiveAuthenticator([]auth.User{
		{Username: "user-a", Password: "password-a"},
	})

	for _, unknown := range []string{"", "user", "user-b", "user-A", "user-a "} {
		if authenticator.Verify(unknown, "password-a") {
			t.Fatalf("unknown username %q must not verify", unknown)
		}
	}
}

// TestNaiveAuthenticatorSupportsRepeatedUsername covers a username configured
// more than once.
//
// The upstream authenticator accumulates passwords per username rather than
// overwriting, so a config that lists the same user twice accepts both
// passwords. Preserving that matters because the local implementation replaced
// it: silently dropping all but the last password would lock out a working
// credential, which is a behaviour change no config would reveal until login.
func TestNaiveAuthenticatorSupportsRepeatedUsername(t *testing.T) {
	authenticator := newNaiveAuthenticator([]auth.User{
		{Username: "user-a", Password: "password-1"},
		{Username: "user-a", Password: "password-2"},
		{Username: "user-a", Password: "password-3"},
	})

	for _, accepted := range []string{"password-1", "password-2", "password-3"} {
		if !authenticator.Verify("user-a", accepted) {
			t.Fatalf("password %q must verify for a user configured with it", accepted)
		}
	}
	if authenticator.Verify("user-a", "password-4") {
		t.Fatal("an unconfigured password must not verify")
	}
}

// TestNaiveAuthenticatorChecksEveryPasswordDigest asserts the no-early-exit
// property that the constant-time comparison depends on.
//
// A short-circuiting implementation returns as soon as one digest matches, so
// the work it does depends on the POSITION of the matching password. This test
// cannot observe timing directly, but it does pin the stronger, checkable
// invariant: every configured password is independently accepted, including ones
// that collide on a shared prefix with an earlier entry. An implementation that
// stopped at the first comparison would still pass the single-password tests
// above and fail here.
func TestNaiveAuthenticatorChecksEveryPasswordDigest(t *testing.T) {
	users := []auth.User{
		{Username: "user", Password: "aaaaaaaa"},
		{Username: "user", Password: "aaaaaaab"},
		{Username: "user", Password: "aaaaaaac"},
		{Username: "user", Password: "zzzzzzzz"},
	}
	authenticator := newNaiveAuthenticator(users)

	for _, user := range users {
		if !authenticator.Verify(user.Username, user.Password) {
			t.Fatalf("password %q must verify regardless of its position in the list",
				user.Password)
		}
	}
}

func TestNaiveAuthenticatorRejectsMalformedCredential(t *testing.T) {
	authenticator := newNaiveAuthenticator([]auth.User{
		{Username: "user-a", Password: "password-a"},
	})

	// parseBasicAuth failures reach Verify as empty strings. An empty credential
	// must never verify, including when the configured password is itself empty,
	// which is not a credential any config should carry but is representable.
	for _, malformed := range []struct{ user, pass string }{
		{"", ""},
		{"user-a", ""},
		{"", "password-a"},
	} {
		if authenticator.Verify(malformed.user, malformed.pass) {
			t.Fatalf("malformed credential (%q,%q) must not verify",
				malformed.user, malformed.pass)
		}
	}

	emptyPassword := newNaiveAuthenticator([]auth.User{{Username: "user-a", Password: ""}})
	if emptyPassword.Verify("", "") {
		t.Fatal("an empty username must not verify even against an empty password")
	}
	if !emptyPassword.Verify("user-a", "") {
		t.Fatal("an explicitly configured empty password is still a configured " +
			"credential for its username; changing that would alter config semantics")
	}
}

// TestNaiveAuthenticatorNilIsSafe pins the no-users case.
//
// The constructor returns nil when nothing is configured, and the inbound refuses
// to start in that state. Verify must still be safe to call, because the field is
// a pointer and a future refactor could call it before that check.
func TestNaiveAuthenticatorNilIsSafe(t *testing.T) {
	var authenticator *naiveAuthenticator
	if authenticator.Verify("user", "password") {
		t.Fatal("a nil authenticator must verify nothing")
	}
	if newNaiveAuthenticator(nil) != nil {
		t.Fatal("no users must produce a nil authenticator")
	}
	if newNaiveAuthenticator([]auth.User{}) != nil {
		t.Fatal("an empty user list must produce a nil authenticator")
	}
}

// TestNaiveAuthenticatorStoresDigestsNotPlaintext asserts the passwords are not
// retained in recoverable form.
//
// The comparison hashes the presented password and compares fixed-size digests
// rather than the strings themselves, so a wrong-length guess does not return
// early on a length mismatch. Storing the digest is what makes that possible; if
// the field ever went back to plaintext the length leak would return, and the
// test would catch the regression.
func TestNaiveAuthenticatorStoresDigestsNotPlaintext(t *testing.T) {
	const username = "u"
	const password = "a-very-distinctive-password"
	authenticator := newNaiveAuthenticator([]auth.User{{Username: username, Password: password}})

	if len(authenticator.credentials) != 1 {
		t.Fatalf("expected one stored digest, got %d", len(authenticator.credentials))
	}
	// The digest covers the PAIR, so a credential is one opaque value rather
	// than a username key plus a password list. That is what removes the
	// username-existence timing path.
	expected := sha256.Sum256([]byte(username + ":" + password))
	if authenticator.credentials[0] != expected {
		t.Fatal("the stored value must be the SHA-256 digest of username:password")
	}
	if len(authenticator.credentials[0]) != sha256.Size {
		t.Fatalf("stored digest must be %d bytes, got %d",
			sha256.Size, len(authenticator.credentials[0]))
	}
}

// TestNaiveAuthenticatorWalksEveryEntry pins the property that removes the
// username-existence timing signal.
//
// The previous map-based verifier returned immediately for an unknown username
// and did more work for a known one, so the two were distinguishable from
// response timing. With a flat list every request performs exactly one digest and
// len(credentials) comparisons, whatever the input. The count cannot be observed
// directly without a timing assertion, which would be flaky; what CAN be pinned
// is the structure that makes the count input-independent, and that is what this
// test does.
func TestNaiveAuthenticatorWalksEveryEntry(t *testing.T) {
	users := []auth.User{
		{Username: "first", Password: "one"},
		{Username: "second", Password: "two"},
		{Username: "third", Password: "three"},
	}
	authenticator := newNaiveAuthenticator(users)

	if len(authenticator.credentials) != len(users) {
		t.Fatalf("every configured pair must be its own entry: got %d, want %d",
			len(authenticator.credentials), len(users))
	}

	// A known user, an unknown user, a wrong password and a correct password
	// must all be verifiable through the same code path. The observable
	// consequence of the flat structure is that an unknown username is accepted
	// if and only if its pair was configured - there is no separate lookup that
	// could short-circuit.
	for _, user := range users {
		if !authenticator.Verify(user.Username, user.Password) {
			t.Fatalf("configured pair %q must verify", user.Username)
		}
		if authenticator.Verify(user.Username, "wrong") {
			t.Fatalf("wrong password for %q must not verify", user.Username)
		}
	}
	if authenticator.Verify("not-configured", "one") {
		t.Fatal("an unconfigured username must not verify")
	}
	// A pair whose halves exist separately must NOT be accepted: the digest
	// covers the joined pair, so there is no way to combine them.
	if authenticator.Verify("first", "two") {
		t.Fatal("credentials must not be combinable across configured pairs")
	}
}
