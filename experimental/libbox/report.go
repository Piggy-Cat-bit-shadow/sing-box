//go:build darwin || linux || windows

package libbox

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
)

type reportMetadata struct {
	Source              string          `json:"source,omitempty"`
	BundleIdentifier    string          `json:"bundleIdentifier,omitempty"`
	ProcessName         string          `json:"processName,omitempty"`
	ProcessPath         string          `json:"processPath,omitempty"`
	StartedAt           string          `json:"startedAt,omitempty"`
	AppVersion          string          `json:"appVersion,omitempty"`
	AppMarketingVersion string          `json:"appMarketingVersion,omitempty"`
	CoreVersion         string          `json:"coreVersion,omitempty"`
	GoVersion           string          `json:"goVersion,omitempty"`
	Platform            json.RawMessage `json:"platform,omitempty"`
}

func baseReportMetadata() reportMetadata {
	processPath, _ := os.Executable()
	processName := filepath.Base(processPath)
	if processName == "." {
		processName = ""
	}
	return reportMetadata{
		Source:              sCrashReportSource,
		ProcessName:         processName,
		ProcessPath:         processPath,
		AppVersion:          sAppVersion,
		AppMarketingVersion: sAppMarketingVersion,
		CoreVersion:         C.Version,
		GoVersion:           GoVersion(),
		Platform:            sPlatformMetadata,
	}
}

func writeReportFile(destPath string, name string, content []byte) {
	filePath := filepath.Join(destPath, name)
	os.WriteFile(filePath, content, 0o666)
	chownReport(filePath)
}

func writeReportMetadata(destPath string, metadata any) {
	data, err := json.Marshal(metadata)
	if err != nil {
		return
	}
	writeReportFile(destPath, "metadata.json", data)
}

func copyConfigSnapshot(destPath string) {
	snapshotPath := configSnapshotPath()
	content, err := os.ReadFile(snapshotPath)
	if err != nil {
		return
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return
	}
	writeReportFile(destPath, "configuration.json", content)
}

func platformSnapshotPath() string {
	return filepath.Join(sWorkingPath, "PlatformMetadata-"+sCrashReportSource+".json")
}

func savePlatformSnapshot() {
	snapshotPath := platformSnapshotPath()
	if sPlatformMetadata == nil {
		os.Remove(snapshotPath)
		return
	}
	os.WriteFile(snapshotPath, sPlatformMetadata, 0o666)
	chownReport(snapshotPath)
}

func readPlatformSnapshot() json.RawMessage {
	content, err := os.ReadFile(platformSnapshotPath())
	if err != nil || !json.Valid(content) {
		return nil
	}
	return content
}

func initReportDir(path string) {
	os.MkdirAll(path, 0o777)
	chownReport(path)
}

func chownReport(path string) {
	if runtime.GOOS != "android" && runtime.GOOS != "windows" {
		os.Chown(path, sUserID, sGroupID)
	}
}

func nextAvailableReportPath(reportsDir string, timestamp time.Time) (string, error) {
	destName := timestamp.Format("2006-01-02T15-04-05")
	destPath := filepath.Join(reportsDir, destName)
	_, err := os.Stat(destPath)
	if os.IsNotExist(err) {
		return destPath, nil
	}
	for i := 1; i <= 1000; i++ {
		suffixedPath := filepath.Join(reportsDir, destName+"-"+strconv.Itoa(i))
		_, err = os.Stat(suffixedPath)
		if os.IsNotExist(err) {
			return suffixedPath, nil
		}
	}
	return "", E.New("no available report path for ", destName)
}

// # Diagnostic archive retention
//
// Every archived incident is a NEW directory under sWorkingPath: archiveCrashReport creates
// crash_reports/<timestamp>, oomkiller promotes oom_draft to oom_reports/<timestamp>, and
// powerreport promotes power_draft to power_reports/<timestamp>. nextAvailableReportPath only
// ever proposes a name that does not exist yet, and nothing used to remove anything, so the
// archive was append-only. A process in a crash or OOM loop therefore grew the working path
// without bound: one directory (and for OOM/power, a heap dump plus six pprof profiles) per
// restart, forever, until the platform killed the app or the disk filled. That is the debt
// these bounds pay off.
//
// # Why these numbers
//
// maxReportCount = 20. One directory is one incident. Twenty recent incidents is already more
// than a support engineer will read, and a crash loop produces one per process start, so the
// count bound is the one that matters for the pathological case. Small enough to stay cheap on
// a phone, large enough that a burst of distinct crashes is not lost.
//
// maxReportAge = 30 days. A crash that old has almost no diagnostic value, and the platform's
// own crash reporter keeps its own copy on both Apple and Android. Kept deliberately long
// because age is the slowest-moving of the three bounds and deleting old reports is the
// hardest to undo.
//
// maxReportTotalBytes = 64 MiB PER DIRECTORY. Count and age say nothing about size: an OOM
// report embeds a heap dump and six runtime profiles (allocs/block/goroutine/heap/mutex/
// threadcreate), so a handful of reports can be hundreds of megabytes. 64 MiB bounds the worst
// case while comfortably holding the small crash_reports directories (a crash log, metadata and
// a config snapshot) many times over. It is per directory rather than a single global budget
// because the three archives have different natural sizes and a shared budget would let OOM
// dumps evict crash logs.
//
// minAge is a grace window for concurrency ACROSS processes. On Apple the crash archive is
// written by the extension process while the containing app may be reading or archiving at the
// same time, and the two do not share this package's mutex. A directory whose mtime is inside
// the window is counted but never removed, so a prune can never delete a report another process
// is still filling in. The window is short because it also delays the count bound during a crash
// loop; ten seconds is far longer than the few milliseconds these writes take.
//
// # What this deliberately does not bound
//
// In-process concurrency is serialized by reportRetentionMu. Cross-process deletions are
// best-effort: a prune that loses a race to another process's prune removes nothing and reports
// nothing, which is correct because the other prune enforces the same policy.
const (
	reportRetentionMaxCount      = 20
	reportRetentionMaxAge        = 30 * 24 * time.Hour
	reportRetentionMaxTotalBytes = 64 << 20
	reportRetentionMinAge        = 10 * time.Second
	reportPruneSuffix            = ".pruning"
)

// reportRetentionPolicy is split out so tests can drive count/size/age with tiny directories
// and explicit timestamps instead of allocating tens of megabytes or sleeping.
type reportRetentionPolicy struct {
	maxCount      int
	maxAge        time.Duration
	maxTotalBytes int64
	minAge        time.Duration
}

var defaultReportRetention = reportRetentionPolicy{
	maxCount:      reportRetentionMaxCount,
	maxAge:        reportRetentionMaxAge,
	maxTotalBytes: reportRetentionMaxTotalBytes,
	minAge:        reportRetentionMinAge,
}

// reportRetentionMu serializes pruning inside this process. It is package-level rather than
// per-directory because a process prunes at most a handful of directories per start and the
// contention is nil; correctness beats granularity here.
var reportRetentionMu sync.Mutex

// pruneReports enforces the default retention policy on one archive directory. keepPath, when
// non-empty, is the archive currently being written: it is counted towards the size budget but
// can never be removed, whatever the bounds say. Pruning is best-effort in the strong sense -
// it returns nothing and ignores every error - because it runs on the crash path, where failing
// to write the report is worse than keeping one directory too many.
func pruneReports(reportsDir string, keepPath string, now time.Time) {
	pruneReportsWithPolicy(reportsDir, keepPath, now, defaultReportRetention)
}

func pruneReportsWithPolicy(reportsDir string, keepPath string, now time.Time, policy reportRetentionPolicy) {
	if reportsDir == "" {
		return
	}
	reportRetentionMu.Lock()
	defer reportRetentionMu.Unlock()

	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		return
	}

	type candidate struct {
		path    string
		name    string
		modTime time.Time
		size    int64
	}
	var candidates []candidate
	var totalSize int64
	cleanKeep := filepath.Clean(keepPath)
	for _, entry := range entries {
		entryPath := filepath.Join(reportsDir, entry.Name())
		if cleanKeep != "." && filepath.Clean(entryPath) == cleanKeep {
			totalSize += reportPathSize(entryPath)
			continue
		}
		if strings.HasSuffix(entry.Name(), reportPruneSuffix) {
			// A previous prune renamed this directory out of the live namespace and then
			// died before RemoveAll finished. It is already invisible to the count and
			// age bounds; finish the deletion so the leftovers cannot accumulate.
			os.RemoveAll(entryPath)
			continue
		}
		if !entry.IsDir() {
			// Archives are directories. A stray file is not ours to interpret, and
			// deleting it could destroy something another component wrote here.
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		size := reportPathSize(entryPath)
		totalSize += size
		if now.Sub(info.ModTime()) < policy.minAge {
			// Recent enough that another process might still be writing it. Counted for
			// size, never eligible for removal.
			continue
		}
		candidates = append(candidates, candidate{entryPath, entry.Name(), info.ModTime(), size})
	}

	// Oldest first. The name tie-break keeps the order total and deterministic even if two
	// directories share an mtime (nextAvailableReportPath suffixes collisions, but a
	// filesystem with coarse timestamps can still produce equal mtimes).
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].modTime.Equal(candidates[j].modTime) {
			return candidates[i].modTime.Before(candidates[j].modTime)
		}
		return candidates[i].name < candidates[j].name
	})

	remove := func(c candidate) bool {
		if !removeReport(c.path) {
			return false
		}
		totalSize -= c.size
		return true
	}

	// Age first: it is the bound that does not depend on how many incidents happened, and it
	// is the one an old archive is most likely to trip.
	live := candidates[:0]
	for _, c := range candidates {
		if now.Sub(c.modTime) > policy.maxAge {
			remove(c)
			continue
		}
		live = append(live, c)
	}

	// Count second: keep the newest maxCount.
	if policy.maxCount >= 0 && len(live) > policy.maxCount {
		for _, c := range live[:len(live)-policy.maxCount] {
			remove(c)
		}
		live = live[len(live)-policy.maxCount:]
	}

	// Size last, oldest-first. The active report and anything inside the grace window are
	// not candidates, so a single oversized active report can leave the directory above the
	// cap. That is deliberate: exceeding a soft cap is better than deleting the report
	// currently being written.
	for totalSize > policy.maxTotalBytes && len(live) > 0 {
		c := live[0]
		live = live[1:]
		if !remove(c) {
			break
		}
	}
}

// removeReport renames a directory out of the live namespace and only then deletes it. The
// rename is atomic, so a crash between the two steps cannot leave a half-deleted directory
// under a name that a report reader would treat as a valid archive: it leaves <name>.pruning,
// which the next prune finishes. A direct RemoveAll would leave the partial directory at its
// real name, which is exactly the state this avoids.
func removeReport(path string) bool {
	pruningPath := path + reportPruneSuffix
	// Clear a leftover from an earlier interrupted prune before trying to rename onto it.
	os.RemoveAll(pruningPath)
	if err := os.Rename(path, pruningPath); err != nil {
		return false
	}
	return os.RemoveAll(pruningPath) == nil
}

// reportPathSize is the on-disk size of one archive directory. It is best-effort: an entry that
// cannot be stat'ed contributes zero rather than failing the prune, because over-counting could
// delete a report that still fits and under-counting only makes the size bound softer.
func reportPathSize(path string) int64 {
	var size int64
	_ = filepath.WalkDir(path, func(_ string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || !entry.Type().IsRegular() {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return nil
		}
		size += info.Size()
		return nil
	})
	return size
}
