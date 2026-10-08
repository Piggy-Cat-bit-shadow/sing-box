//go:build darwin || linux || windows

package libbox

import (
	"path/filepath"
	"time"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/service/powerreport"
)

type powerReportMetadata struct {
	reportMetadata
	StartedAt string `json:"startedAt"`
}

func PowerReportOptions(startedService *daemon.StartedService) powerreport.Options {
	// powerreport promotes its draft to power_reports/<timestamp> when the recorder closes, so
	// the archive grows by one directory per recorded session and there is no promote hook in
	// this package to hang retention on. Pruning here, once per recorder start, bounds it across
	// restarts instead; like the OOM archive it is the total-size bound that matters, because a
	// report embeds six pprof profiles. The draft directory is never touched.
	pruneReports(filepath.Join(sWorkingPath, powerreport.ReportsDirectoryName), "", time.Now().UTC())
	metadata := powerReportMetadata{
		reportMetadata: baseReportMetadata(),
		StartedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	return powerreport.Options{
		BasePath:      sWorkingPath,
		Logger:        log.StdLogger(),
		Metadata:      metadata,
		OwnerCallback: chownReport,
		LogCallback: func() []byte {
			return formatLogEntries(startedService.SavedLog())
		},
		ProfileCallback: func(path string) {
			for _, name := range oomReportProfiles {
				writeOOMProfile(filepath.Join(path, name+".pb"), name)
			}
		},
	}
}

func DiscardPowerReportDraft() {
	powerreport.DiscardDraft(sWorkingPath)
}
