package jiejie_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests cover the differential harness's VERDICT LOGIC, not the proxies.
//
// That logic is the part that decides whether a real behavioural difference fails CI,
// so a bug in it silently converts "incompatible" into "fine". It is also the part that
// cannot be exercised by the integration test alone: reaching a specific divergence by
// talking to two live proxies is not reproducible on demand, so the enforcement has to
// be tested directly.
//
// # What this replaced
//
// The previous design carried a free-text `knownDivergence` string per probe, and the
// verdict was "INTENTIONAL-DIFF whenever that string is non-empty". Once ANY difference
// had been labelled, every future difference in that same probe - including a new
// regression, and including a difference in a completely different field - was accepted
// as intentional too. The prose was never compared against what was observed.
//
// The tests below are written so that the OLD design fails them: each one takes a probe
// carrying a valid declared divergence and then introduces a SECOND, undeclared
// difference, which must be reported as a DIFF.

// declaredDivergence returns the declaration shape used by these tests: a divergence
// that is complete enough to be accepted on its own.
func declaredDivergence() *expectedDivergence {
	return &expectedDivergence{
		referenceStatus: "407",
		singBoxStatus:   "none",
		referenceError:  "none",
		singBoxError:    "refused",
		referenceCommit: CaddyReferenceCommit,
		rationale:       "this deployment does not challenge unauthenticated CONNECT",
		evidence:        "pinned forwardproxy source plus runtime repro through this harness",
	}
}

// observation builds a parityObservation with the named fields set.
func observation(status string, err string, padding string, tunnel string) parityObservation {
	return parityObservation{
		status:        status,
		err:           err,
		paddingHeader: padding,
		tunnelOpened:  tunnel,
	}
}

// TestExpectedDivergenceAcceptsExactlyWhatItDeclares is the positive control: without
// it, the negative tests below could pass by rejecting everything.
func TestExpectedDivergenceAcceptsExactlyWhatItDeclares(t *testing.T) {
	reference := observation("407", "", "absent", "closed")
	singBox := observation("none", "refused", "absent", "closed")

	matched, violations := declaredDivergence().matches(reference, singBox)
	require.True(t, matched,
		"a difference that is exactly the declared one must be accepted; violations: %v",
		violations)
	require.Empty(t, violations)
}

// TestUndeclaredDifferenceInANewFieldFails is the core regression this change prevents.
//
// The status and error fields differ exactly as declared, so the old design would have
// accepted the probe. The padding header ALSO differs, and that was never declared. The
// verdict must therefore be DIFF.
func TestUndeclaredDifferenceInANewFieldFails(t *testing.T) {
	reference := observation("407", "", "present", "closed")
	singBox := observation("none", "refused", "absent", "closed")

	matched, violations := declaredDivergence().matches(reference, singBox)
	require.False(t, matched,
		"a difference in a field the declaration said nothing about must NOT be "+
			"accepted as intentional; that is precisely how a regression hides behind "+
			"an old label")
	require.Len(t, violations, 1)
	require.Contains(t, violations[0], "padding")
	require.Contains(t, strings.Join(violations, "; "), "undeclared difference")
}

// TestDeclaredButNotObservedDifferenceIsStale catches the opposite error: the sides now
// AGREE, but the probe still carries a declaration saying they differ. That means the
// label is out of date - exactly the situation the two H1 auth probes were in, where the
// implementation had been changed to match the reference while the label still claimed a
// reset.
func TestDeclaredButNotObservedDifferenceIsStale(t *testing.T) {
	// Both sides now behave identically.
	reference := observation("407", "", "absent", "closed")
	singBox := observation("407", "", "absent", "closed")

	// A declaration that expects a difference.
	declared := &expectedDivergence{
		referenceStatus: "407",
		singBoxStatus:   "none",
		referenceCommit: CaddyReferenceCommit,
		rationale:       "stale",
		evidence:        "stale",
	}

	matched, violations := declared.matches(reference, singBox)
	require.False(t, matched,
		"a stale declaration must be reported, not silently ignored, or a probe can "+
			"keep a divergence label it no longer needs")
	require.NotEmpty(t, violations)
	require.Contains(t, strings.Join(violations, "; "), "stale")
}

// TestWrongStatusValuesFail proves the declaration is compared by VALUE, not merely
// consulted for non-emptiness. The old design only asked "is the label non-empty?".
func TestWrongStatusValuesFail(t *testing.T) {
	// The declaration expects singbox status "none"; it actually produced "500".
	reference := observation("407", "", "absent", "closed")
	singBox := observation("500", "read-response", "absent", "closed")

	matched, violations := declaredDivergence().matches(reference, singBox)
	require.False(t, matched,
		"a declaration must not excuse a status it did not predict")
	require.NotEmpty(t, violations)
	require.Contains(t, strings.Join(violations, "; "), "singbox observed")
}

// TestIncompleteDeclarationIsRejected proves the evidence bar is enforced in code.
// A declaration with no rationale, no evidence or no pinned commit is not a documented
// product decision, so it must not excuse anything.
func TestIncompleteDeclarationIsRejected(t *testing.T) {
	reference := observation("407", "", "absent", "closed")
	singBox := observation("none", "refused", "absent", "closed")

	for name, mutate := range map[string]func(*expectedDivergence){
		"no rationale": func(d *expectedDivergence) { d.rationale = "" },
		"no evidence":  func(d *expectedDivergence) { d.evidence = "" },
		"no pinned commit": func(d *expectedDivergence) {
			d.referenceCommit = ""
		},
	} {
		declared := declaredDivergence()
		mutate(declared)

		matched, violations := declared.matches(reference, singBox)
		require.False(t, matched,
			"%s: an undocumented divergence must not be accepted", name)
		require.NotEmpty(t, violations, "%s: the rejection must say why", name)
	}
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

// TestErrorClassSeparatesRealFailures is the P1-7 half: before this change equal()
// ignored err entirely, so two implementations that failed in DIFFERENT ways scored
// PASS whenever the other fields happened to line up - which is the common case for a
// connection that never produced a response.
func TestErrorClassSeparatesRealFailures(t *testing.T) {
	tlsFailure := observation("none", "tls", "", "")
	readFailure := observation("none", "read-response", "", "")
	dialFailure := observation("none", "dial", "", "")

	require.False(t, tlsFailure.equal(readFailure),
		"a TLS failure and a read failure are different behaviours and must not compare "+
			"equal; before this change both had empty status/padding/tunnel fields and "+
			"were scored identical")
	require.False(t, tlsFailure.equal(dialFailure))

	// The positive control: the same failure on both sides still matches.
	require.True(t, tlsFailure.equal(observation("none", "tls", "", "")),
		"identical failures must compare equal, or every error path would report DIFF")
	require.True(t, observation("200", "", "present", "opened").equal(
		observation("200", "", "present", "opened")))
}

// TestErrorClassIgnoresUnstableDetail proves the comparison is on the CLASS. One probe
// sets err to "tls: " + err.Error(); the Go and TLS stack wording inside that suffix is
// not stable across versions, so comparing it as text would create a permanently
// flapping verdict.
func TestErrorClassIgnoresUnstableDetail(t *testing.T) {
	shortForm := observation("none", "tls", "", "")
	longForm := observation("none",
		"tls: remote error: tls: handshake failure (alert 40) from Go 1.25.5", "", "")

	require.True(t, shortForm.equal(longForm),
		"the same error CLASS with different detail must compare equal")

	require.Equal(t, "tls", errorClass(shortForm))
	require.Equal(t, "tls", errorClass(longForm))

	// A genuinely different class must still differ.
	require.False(t, shortForm.equal(observation("none", "tls-verify", "", "")),
		"a different class must not be collapsed into the same one")
}

// TestErrorClassOfNoError covers the empty case explicitly, because "none" has to be a
// real class rather than a missing value that accidentally matches anything.
func TestErrorClassOfNoError(t *testing.T) {
	require.Equal(t, "none", errorClass(parityObservation{}))
	require.Equal(t, "none", errorClass(observation("200", "", "present", "opened")))

	// An err that is only a colon must normalize to "none" rather than to "".
	require.Equal(t, "none", errorClass(observation("none", ":", "", "")))
	require.Equal(t, "none", errorClass(observation("none", "  ", "", "")))
}

// TestDifferenceNamesTheErrorClass proves a DIFF report actually explains the error
// difference. A report that says "differs" without saying how is not actionable.
func TestDifferenceNamesTheErrorClass(t *testing.T) {
	reference := observation("none", "tls", "", "")
	singBox := observation("none", "read-response", "", "")

	difference := reference.difference(singBox)
	require.Contains(t, difference, "error class",
		"the difference report must name the error class; got %q", difference)
	require.Contains(t, difference, "tls")
	require.Contains(t, difference, "read-response")
}

// TestEqualAndDifferenceAgree is a consistency check between the two functions. If they
// disagree, a probe can be scored PASS while its own report prints a difference, which
// makes the report untrustworthy exactly when it matters.
func TestEqualAndDifferenceAgree(t *testing.T) {
	cases := []struct {
		name      string
		reference parityObservation
		singBox   parityObservation
	}{
		{"identical", observation("200", "", "present", "opened"),
			observation("200", "", "present", "opened")},
		{"status", observation("200", "", "present", "opened"),
			observation("407", "", "present", "opened")},
		{"error class", observation("none", "tls", "", ""),
			observation("none", "dial", "", "")},
		{"padding", observation("200", "", "present", "opened"),
			observation("200", "", "absent", "opened")},
		{"tunnel", observation("200", "", "present", "opened"),
			observation("200", "", "present", "closed")},
		{"error detail only", observation("none", "tls", "", ""),
			observation("none", "tls: specific wording", "", "")},
	}

	for _, testCase := range cases {
		equal := testCase.reference.equal(testCase.singBox)
		difference := testCase.reference.difference(testCase.singBox)

		if equal {
			require.Empty(t, difference,
				"%s: equal() reported a match but difference() reported %q",
				testCase.name, difference)
		} else {
			require.NotEmpty(t, difference,
				"%s: equal() reported a difference but difference() explained nothing",
				testCase.name)
		}
	}
}
