//go:build darwin || linux || windows

package libbox

// Retention tests for the diagnostic archive.
//
// Every assertion here is driven by an explicit `now` and explicit directory mtimes
// (os.Chtimes), never by a sleep: a retention policy whose behaviour depends on wall-clock
// racing would be flaky on a loaded CI machine and would not be reproducible at all. The policy
// struct is injectable for the same reason - the size bound is exercised with 100-byte
// directories rather than the real 64 MiB ones, so the test proves the deletion ORDER without
// writing hundreds of megabytes.

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// reportName makes a stable, sortable archive directory name for index i. nextAvailableReportPath
// uses the same timestamp shape, so the tests exercise realistic names.
func reportName(index int) string {
	return fmt.Sprintf("2026-01-02T03-04-%02d", index)
}

// testRetentionPolicy is the shipped policy, except where a test overrides a bound to keep its
// fixture directory tiny.
func testRetentionPolicy() reportRetentionPolicy {
	return reportRetentionPolicy{
		maxCount:      reportRetentionMaxCount,
		maxAge:        reportRetentionMaxAge,
		maxTotalBytes: reportRetentionMaxTotalBytes,
		minAge:        0,
	}
}

// writeReportDir creates one archive directory with a fixed mtime and, optionally, one file of
// `size` bytes. The mtime is set explicitly so an "old" report is old with no waiting.
func writeReportDir(t *testing.T, dir string, name string, modTime time.Time, size int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(path, 0o777); err != nil {
		t.Fatalf("create report dir %s: %v", name, err)
	}
	if size > 0 {
		if err := os.WriteFile(filepath.Join(path, "go.log"), make([]byte, size), 0o666); err != nil {
			t.Fatalf("write report file %s: %v", name, err)
		}
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatalf("set mtime on %s: %v", name, err)
	}
	return path
}

func reportDirNames(t *testing.T, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	names := make(map[string]bool, len(entries))
	for _, entry := range entries {
		names[entry.Name()] = true
	}
	return names
}

func reportDirTotalSize(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		total += reportPathSize(filepath.Join(dir, entry.Name()))
	}
	return total
}

// The count bound is what stops a crash loop: one directory per process start.
func TestPruneReportsKeepsOnlyTheNewestCount(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	const count = 6
	for i := 0; i < count; i++ {
		writeReportDir(t, dir, reportName(i), now.Add(-time.Duration(count-i)*time.Hour), 8)
	}
	policy := testRetentionPolicy()
	policy.maxCount = 3
	pruneReportsWithPolicy(dir, "", now, policy)

	names := reportDirNames(t, dir)
	if len(names) != 3 {
		t.Fatalf("retention kept %d reports, want 3: %v", len(names), names)
	}
	// Kept: the three newest, i.e. the three with the largest index.
	for i := count - 3; i < count; i++ {
		if !names[reportName(i)] {
			t.Errorf("newest report %s was pruned; want the three newest kept", reportName(i))
		}
	}
	for i := 0; i < count-3; i++ {
		if names[reportName(i)] {
			t.Errorf("oldest report %s survived the count bound", reportName(i))
		}
	}
}

// The archive currently being written must survive even when it is the oldest, which is the
// case a crash loop actually produces (the current report is created last, but the policy must
// not depend on that).
func TestPruneReportsNeverRemovesActiveReport(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	const count = 5
	keepPath := ""
	for i := 0; i < count; i++ {
		path := writeReportDir(t, dir, reportName(i), now.Add(-time.Duration(count-i)*time.Hour), 8)
		if i == 0 {
			keepPath = path
		}
	}
	policy := testRetentionPolicy()
	policy.maxCount = 2
	pruneReportsWithPolicy(dir, keepPath, now, policy)

	if _, err := os.Stat(keepPath); err != nil {
		t.Fatalf("the active report was removed by retention: %v", err)
	}
	names := reportDirNames(t, dir)
	// keepPath plus maxCount survivors: the bound is exceeded by exactly the protected report,
	// which is the documented trade-off.
	if len(names) != 3 {
		t.Fatalf("retention kept %d reports, want keepPath + 2: %v", len(names), names)
	}
	if !names[filepath.Base(keepPath)] {
		t.Fatalf("the active report is not among the survivors: %v", names)
	}
}

// Age is the slowest bound and the one that deletes the oldest data, so it is tested on both
// sides of the threshold.
func TestPruneReportsRemovesExpiredReports(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	writeReportDir(t, dir, "expired", now.Add(-40*24*time.Hour), 8)
	writeReportDir(t, dir, "recent", now.Add(-24*time.Hour), 8)
	policy := testRetentionPolicy()
	policy.maxAge = 7 * 24 * time.Hour
	pruneReportsWithPolicy(dir, "", now, policy)

	names := reportDirNames(t, dir)
	if names["expired"] {
		t.Error("a report older than maxReportAge survived")
	}
	if !names["recent"] {
		t.Error("a report inside maxReportAge was removed")
	}
}

// Size is the bound that matters for OOM/power reports, which embed a heap dump and six pprof
// profiles. The oldest directories go first, and the total ends at or under the cap.
func TestPruneReportsEnforcesTotalSize(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	const count = 4
	const perReport = 100
	for i := 0; i < count; i++ {
		writeReportDir(t, dir, reportName(i), now.Add(-time.Duration(count-i)*time.Hour), perReport)
	}
	policy := testRetentionPolicy()
	policy.maxTotalBytes = 300
	pruneReportsWithPolicy(dir, "", now, policy)

	if size := reportDirTotalSize(t, dir); size > 300 {
		t.Errorf("retention left %d bytes, over the 300-byte cap", size)
	}
	names := reportDirNames(t, dir)
	if names[reportName(0)] {
		t.Error("the oldest report survived the size bound")
	}
	if !names[reportName(count-1)] {
		t.Error("the newest report was removed by the size bound")
	}
}

// A report another process may still be filling in is inside the grace window and must not be
// touched, even when the count bound would delete it immediately.
func TestPruneReportsProtectsFreshReportsFromConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	writeReportDir(t, dir, "old", now.Add(-time.Hour), 8)
	writeReportDir(t, dir, "fresh", now.Add(-time.Second), 8)
	policy := testRetentionPolicy()
	policy.maxCount = 0
	policy.minAge = time.Minute
	pruneReportsWithPolicy(dir, "", now, policy)

	names := reportDirNames(t, dir)
	if names["old"] {
		t.Error("an old report survived a zero count bound")
	}
	if !names["fresh"] {
		t.Error("a report inside the grace window was removed")
	}
}

// A crash between the rename and the RemoveAll leaves <name>.pruning. The next prune must
// finish that deletion rather than counting the leftover as a live report.
func TestPruneReportsFinishesInterruptedPrune(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	writeReportDir(t, dir, "live", now, 8)
	writeReportDir(t, dir, "half-deleted"+reportPruneSuffix, now, 8)
	policy := testRetentionPolicy()
	pruneReportsWithPolicy(dir, "", now, policy)

	names := reportDirNames(t, dir)
	if names["half-deleted"+reportPruneSuffix] {
		t.Error("a .pruning leftover was not cleaned up by the next prune")
	}
	if !names["live"] {
		t.Error("recovering the interrupted prune removed a live report")
	}
}

// Retention reads the archive directory. A file that is not an archive directory is not ours to
// delete, and a prune must not fail because of one.
func TestPruneReportsLeavesStrayFilesAlone(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	strayPath := filepath.Join(dir, ".lock")
	if err := os.WriteFile(strayPath, []byte("held"), 0o666); err != nil {
		t.Fatal(err)
	}
	writeReportDir(t, dir, "old", now.Add(-time.Hour), 8)
	policy := testRetentionPolicy()
	policy.maxCount = 0
	pruneReportsWithPolicy(dir, "", now, policy)

	if _, err := os.Stat(strayPath); err != nil {
		t.Errorf("retention deleted a non-report file: %v", err)
	}
	names := reportDirNames(t, dir)
	if names["old"] {
		t.Error("the old report survived a zero count bound")
	}
}

// pruneReports is called from the crash path, so the mutex has to make concurrent calls sane
// (this is also what -race checks). keepPath must survive a burst of concurrent prunes.
func TestPruneReportsConcurrentCallsKeepActiveReport(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	keepPath := writeReportDir(t, dir, reportName(0), now.Add(-10*time.Hour), 8)
	for i := 1; i < 5; i++ {
		writeReportDir(t, dir, reportName(i), now.Add(-time.Duration(5-i)*time.Hour), 8)
	}
	policy := testRetentionPolicy()
	policy.maxCount = 1

	var waitGroup sync.WaitGroup
	for i := 0; i < 8; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			pruneReportsWithPolicy(dir, keepPath, now, policy)
		}()
	}
	waitGroup.Wait()

	if _, err := os.Stat(keepPath); err != nil {
		t.Fatalf("concurrent prunes removed the active report: %v", err)
	}
}
