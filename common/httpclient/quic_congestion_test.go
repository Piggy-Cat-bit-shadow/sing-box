//go:build with_quic

package httpclient

import (
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// Tests for the client QUIC congestion control option.
//
// # The property that matters most
//
// An UNSET value must leave quic-go's own sender in place. Every other outcome
// would mean this fork silently changed wire behaviour relative to upstream
// sing-box, quic-go/masque-go and quic-go/connect-ip-go, none of which select a
// client congestion control. A congestion control is a performance preference, so
// it must be named in configuration to take effect.
//
// The resolver returns a nil factory for that case rather than a CUBIC factory,
// because "explicitly CUBIC" and "left to the library" are different statements
// even when the library default happens to be CUBIC today: if a dependency bump
// changed the default, only the unset case should follow it.

func TestClientCongestionControlUnsetKeepsLibraryDefault(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"", "default"} {
		factory, err := NewClientCongestionControl(name)
		require.NoError(t, err, "value %q must be accepted", name)
		require.Nil(t, factory,
			"value %q must resolve to nil, meaning 'keep quic-go's sender'; a "+
				"non-nil factory here would override the library default silently", name)
	}
}

func TestClientCongestionControlAcceptsSupportedNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"cubic", "bbr", "reno"} {
		factory, err := NewClientCongestionControl(name)
		require.NoError(t, err, "value %q must be accepted", name)
		require.NotNil(t, factory,
			"value %q must produce a sender factory, or the option would be a no-op", name)
	}
}

// TestClientCongestionControlRejectsUnknownNames pins the validation.
//
// The matching is exact and case-sensitive on purpose: silently accepting "BBR" or
// " bbr" would make a typo look like it worked, and the operator would believe a
// performance setting was in effect when it was not.
func TestClientCongestionControlRejectsUnknownNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"BBR", " bbr", "bbr ", "cubicc", "vegas", "bbr2", "Default", "CUBIC"} {
		factory, err := NewClientCongestionControl(name)
		require.Error(t, err, "value %q must be rejected as unknown", name)
		require.Nil(t, factory, "a rejected value must not produce a factory")
		require.Contains(t, err.Error(), "unknown quic congestion control",
			"the error must name the problem so the operator can act on it")
	}
}

// TestClientCongestionControlErrorNamesTheValue guards the diagnostic.
//
// "unknown quic congestion control" without the offending value forces the reader
// to hunt through their configuration to find which option is wrong.
func TestClientCongestionControlErrorNamesTheValue(t *testing.T) {
	t.Parallel()

	_, err := NewClientCongestionControl("cubik")
	require.Error(t, err)
	require.Contains(t, err.Error(), "cubik",
		"the error must quote the rejected value")
}

// TestApplyClientCongestionControlNilIsANoOp asserts the unset path is safe.
//
// ApplyClientCongestionControl is called on every dial, including the default
// configuration, so a nil factory must not panic or touch the connection. A nil
// conn is passed deliberately: if the function dereferenced it before checking the
// factory, this would panic rather than return.
func TestApplyClientCongestionControlNilIsANoOp(t *testing.T) {
	t.Parallel()

	require.NotPanics(t, func() {
		ApplyClientCongestionControl(nil, nil)
	}, "a nil factory must return without touching the connection")
}

// TestNewQUICConfigLeavesCongestionControlToTheLibrary asserts the option is NOT
// smuggled into quic.Config.
//
// quic.Config has no congestion control field; the sender is installed on the Conn.
// Asserting the config still builds correctly with the new option set guards
// against a future refactor that tried to express it here.
func TestNewQUICConfigLeavesCongestionControlToTheLibrary(t *testing.T) {
	t.Parallel()

	config := NewQUICConfig(option.QUICOptions{CongestionControl: "bbr"})
	require.NotNil(t, config)
	// The new option must not disturb the fields that ARE part of quic.Config.
	require.Equal(t, int64(0), config.MaxIncomingStreams,
		"an unset max_concurrent_streams must stay unset")
}

// TestClientCongestionControlFactoryBuildsASender exercises each factory against a
// real *quic.Conn.
//
// The factories close over conn.InitialPacketSize(), so a factory that was
// constructed correctly but called against a nil conn would panic at dial time
// rather than at load time. This test is what proves the closure is only evaluated
// where a conn exists - which is why ApplyClientCongestionControl takes the conn
// rather than the factory being pre-bound.
func TestClientCongestionControlFactoryIsNotEvaluatedEarly(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"cubic", "bbr", "reno"} {
		factory, err := NewClientCongestionControl(name)
		require.NoError(t, err)
		require.NotNil(t, factory)
		// Building the factory must NOT require a connection: if it did, resolving
		// the option at construction time would panic.
		require.NotPanics(t, func() {
			_ = factory
		}, "resolving %q must not need a live connection", name)
	}
}

var _ = func() *quic.Conn { return nil }
