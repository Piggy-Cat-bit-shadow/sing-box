//go:build with_naive_outbound

package naive

import (
	"testing"

	"github.com/sagernet/sing/common/byteformats"
	"github.com/stretchr/testify/require"
)

// Tests that the Naive outbound's window options cannot silently become something
// other than what was configured.
//
// stream_receive_window and quic_session_receive_window are *byteformats.MemoryBytes.
// That parser used to multiply the literal by its unit without an overflow check, so
// a large value wrapped with no error - and because the outbound passes 0 through as
// "unset", a wrapped-to-zero value silently reverted to the upstream default. The
// configuration was accepted and then ignored.
//
// These tests pin the parser behaviour at the boundary the Naive options actually
// depend on, so a future dependency bump that regresses it fails here rather than in
// production as an unexplained performance difference.

// memoryBytesFrom parses a literal the way the JSON decoder would.
func memoryBytesFrom(t *testing.T, literal string) (byteformats.MemoryBytes, error) {
	t.Helper()
	var value byteformats.MemoryBytes
	err := value.UnmarshalJSON([]byte(literal))
	return value, err
}

// TestReceiveWindowOverflowIsRejectedBeforeItBecomesZero is the regression guard.
//
// The failure mode is specific and quiet: the value becomes 0, the outbound treats 0
// as "not configured", and the default is used instead. Nothing is logged and nothing
// fails, so the operator sees a window that is not the one in the configuration file.
func TestReceiveWindowOverflowIsRejectedBeforeItBecomesZero(t *testing.T) {
	t.Parallel()

	for _, literal := range []string{`"16e"`, `"16384p"`, `"17e"`, `"18446744073709551615e"`} {
		value, err := memoryBytesFrom(t, literal)
		require.Error(t, err,
			"%s must be a configuration error, not a silent wrap to %d (which the "+
				"outbound would read as 'unset' and replace with the default)",
			literal, value.Value())
	}
}

// TestOrdinaryReceiveWindowsStillParse is the control: a guard that rejected real
// values would pass the test above while breaking every working configuration.
func TestOrdinaryReceiveWindowsStillParse(t *testing.T) {
	t.Parallel()

	// The forms that actually appear in configuration, including the ones in
	// release/jiejie-production-topology.json, which are JSON numbers.
	cases := []struct {
		literal string
		want    uint64
	}{
		{`8388608`, 8 << 20},   // the production stream_receive_window
		{`33554432`, 32 << 20}, // the production connection_receive_window
		{`"8m"`, 8 << 20},
		{`"32m"`, 32 << 20},
		{`"1g"`, 1 << 30},
		{`0`, 0},
		{`"0"`, 0},
	}
	for _, testCase := range cases {
		value, err := memoryBytesFrom(t, testCase.literal)
		require.NoError(t, err, "%s must parse", testCase.literal)
		require.Equal(t, testCase.want, value.Value(),
			"%s must keep its exact value", testCase.literal)
	}
}

// TestZeroIsStillTheUnsetSentinel documents the contract the overflow fix depends on.
//
// The fix works because a rejected value can no longer BECOME zero. Zero itself must
// remain a legitimate, accepted value meaning "use the default", so the guard is about
// rejecting the overflow, not about rejecting zero.
func TestZeroIsStillTheUnsetSentinel(t *testing.T) {
	t.Parallel()

	zero, err := memoryBytesFrom(t, `0`)
	require.NoError(t, err, "an explicit 0 must remain valid; it means 'use the default'")
	require.Zero(t, zero.Value())

	// And the marshaller's own output must be readable, since these values round-trip
	// through configuration dumps.
	var value byteformats.MemoryBytes
	require.NoError(t, value.UnmarshalJSON([]byte(`"0"`)),
		`"0" is what MarshalJSON emits for the zero value and must be parseable`)
	require.Zero(t, value.Value())
}
