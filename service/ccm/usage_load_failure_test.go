package ccm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// Tests that a failed usage-statistics load does not destroy the file it failed to read.
//
// # The defect these pin
//
// Load clears the in-memory combinations BEFORE reading the file, so a failed read leaves the
// tracker holding empty state. The service then registered a save on close, which wrote that empty
// state over the file it had just failed to read - turning a transient read failure (a permission
// problem, a partially written file, a decode error) into permanent data loss.
//
// The fix is not to repair the file: it is to refuse to overwrite it. If the existing contents
// could not be understood, the service must not claim to be their new authoritative source.

// newLoadFixture creates a tracker writing to a temp file seeded with the given contents.
func newLoadFixture(t *testing.T, contents string) (*AggregatedUsage, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "usage.json")
	if contents != "" {
		require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
	}
	return &AggregatedUsage{
		ctx:      context.Background(),
		filePath: path,
		logger:   log.NewNOPFactory().NewLogger("ccm"),
	}, path
}

// TestFailedLoadLeavesUsableStateEmpty documents the precondition the fix relies on.
func TestFailedLoadLeavesUsableStateEmpty(t *testing.T) {
	tracker, path := newLoadFixture(t, `{"last_updated":"2026-01-01T00:00:00Z","combinations":[{"model":"m","cost":1}]}`)

	// A successful load populates the tracker.
	require.NoError(t, tracker.Load())
	require.NotEmpty(t, tracker.Combinations, "the seeded file must load")

	// Now make the file unreadable in a way that is not "missing".
	require.NoError(t, os.WriteFile(path, []byte("{ this is not json"), 0o644))
	require.Error(t, tracker.Load(), "a malformed file must fail to load")

	require.Empty(t, tracker.Combinations,
		"a failed load leaves the tracker empty, which is exactly why saving afterwards would "+
			"destroy the file")
}

// TestLoadFailureDisablesTheTracker is the fix, driven through the production helper.
func TestLoadFailureDisablesTheTracker(t *testing.T) {
	corrupt := "not json at all"
	tracker, path := newLoadFixture(t, corrupt)

	service := &Service{
		logger:       log.NewNOPFactory().NewLogger("ccm"),
		usageTracker: tracker,
	}

	service.loadUsageTracker(adapter.NewScope(context.Background(), log.NewNOPFactory().Logger()))

	require.Nil(t, service.usageTracker,
		"a tracker whose load failed must be dropped; keeping it means Close saves the empty "+
			"in-memory state over the file that could not be read")
	require.Equal(t, corrupt, string(mustRead(t, path)),
		"and the file must be untouched")
}

// TestHealthyLoadKeepsTheTracker is the control.
//
// Without it, a helper that always dropped the tracker would pass the test above.
func TestHealthyLoadKeepsTheTracker(t *testing.T) {
	healthy := `{"last_updated":"2026-01-01T00:00:00Z","combinations":[{"model":"m","cost":1}]}`
	tracker, _ := newLoadFixture(t, healthy)

	service := &Service{
		logger:       log.NewNOPFactory().NewLogger("ccm"),
		usageTracker: tracker,
	}

	service.loadUsageTracker(adapter.NewScope(context.Background(), log.NewNOPFactory().Logger()))

	require.NotNil(t, service.usageTracker,
		"a successful load must keep the tracker, or usage statistics would never persist")
	require.NotEmpty(t, service.usageTracker.Combinations)
}

// TestMissingFileStillEnablesTracking is the other boundary.
//
// A file that does not exist yet is a normal first run, not a failure: tracking must stay enabled
// so the file gets created.
func TestMissingFileStillEnablesTracking(t *testing.T) {
	tracker, _ := newLoadFixture(t, "")

	service := &Service{
		logger:       log.NewNOPFactory().NewLogger("ccm"),
		usageTracker: tracker,
	}

	service.loadUsageTracker(adapter.NewScope(context.Background(), log.NewNOPFactory().Logger()))

	require.NotNil(t, service.usageTracker,
		"a first run has nothing to load and must still track usage")
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}
