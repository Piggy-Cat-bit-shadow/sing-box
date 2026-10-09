//go:build with_utls

// Gated on with_utls because it builds a RealityClientConfig, which only exists in that
// configuration (common/tls/reality_client.go is with_utls). It was the only reality test file
// in this package without the constraint - reality_handshake_test.go, reality_key_share_test.go,
// reality_short_id_test.go and utls_client_test.go all have it - so the untagged test build
// failed with `undefined: RealityClientConfig`.
package tls

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// buildSessionID must derive every field from the time it is given.
//
// # The defect this pins
//
// The version/time field was built from the caller's `now` while the timestamp four bytes later came
// from a second, fresh `time.Now()` call. A caller injecting a clock through uTLS's `Config.Time` -
// which is how a test makes the greeting reproducible, and how a caller with a corrected clock keeps
// it consistent - therefore controlled one field and not the other, and the greeting on the wire was
// not the one the caller had asked for. Nothing could pin it, because the second field moved on its
// own.
//
// The failure is invisible rather than loud: the server checks the timestamp against its own clock
// within a window, so an injected-clock test still usually authenticated, and the bug only showed up
// as a test that could not be made deterministic.

func testRealityConfig(shortID [8]byte) *RealityClientConfig {
	return &RealityClientConfig{shortID: shortID}
}

// Same input, same output. If any field is read from a clock instead of the argument, two calls with
// one fixed time disagree.
func TestRealitySessionIDIsAFunctionOfItsArgument(t *testing.T) {
	t.Parallel()
	config := testRealityConfig([8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	when := time.Unix(1_700_000_000, 0)

	first := config.buildSessionID(when)
	// A real clock advance between the calls is what caught this: without the fix the second call
	// necessarily differed, and the test is meaningful because it fails deterministically on the
	// broken version rather than racing.
	time.Sleep(time.Millisecond)
	second := config.buildSessionID(when)

	require.Equal(t, first, second,
		"the session id must be a pure function of the time it is given; a clock read inside makes "+
			"the greeting uncontrollable by the caller")
}

// The timestamp the server reads is the caller's, not the wall clock's.
func TestRealitySessionIDEncodesTheGivenTimestamp(t *testing.T) {
	t.Parallel()
	config := testRealityConfig([8]byte{})
	when := time.Unix(1_700_000_000, 0)
	sessionID := config.buildSessionID(when)

	require.EqualValues(t, 1_700_000_000, binary.BigEndian.Uint32(sessionID[4:8]),
		"bytes 4..8 are the timestamp the REALITY server validates against its own clock")

	// And the declared minimum client version still occupies the first three bytes, so the fix did
	// not disturb the layout the server parses.
	require.Equal(t, byte(realityMinClientVersionMajor), sessionID[0])
	require.Equal(t, byte(realityMinClientVersionMinor), sessionID[1])
	require.Equal(t, byte(realityMinClientVersionPatch), sessionID[2])
}

// Two different times must differ, and only where they should: the timestamp field. This is the
// negative control for the test above - if buildSessionID ignored `now` entirely, the purity
// assertion would pass vacuously.
func TestRealitySessionIDTracksTheTimestampField(t *testing.T) {
	t.Parallel()
	config := testRealityConfig([8]byte{0xaa, 0xbb})
	early := config.buildSessionID(time.Unix(1_700_000_000, 0))
	late := config.buildSessionID(time.Unix(1_700_000_060, 0))

	require.NotEqual(t, early, late, "a sixty-second difference must be encoded")
	require.Equal(t, early[:4], late[:4], "the version and its trailing byte do not depend on the time")
	require.Equal(t, early[8:], late[8:], "the short id does not depend on the time")
	require.NotEqual(t, early[4:8], late[4:8], "the timestamp field is where the difference belongs")
}

// The short id lands where the reference reads it, and a short id shorter than the field leaves the
// remainder zero rather than repeating or shifting.
func TestRealitySessionIDCarriesTheShortIDAtTheReferenceOffset(t *testing.T) {
	t.Parallel()
	shortID := [8]byte{0xde, 0xad, 0xbe, 0xef}
	sessionID := testRealityConfig(shortID).buildSessionID(time.Unix(1_700_000_000, 0))

	require.Equal(t, shortID[:4], sessionID[8:12])
	require.Equal(t, make([]byte, 20), sessionID[12:],
		"the rest of the session-id field stays zero past the eight-byte short id")
}
