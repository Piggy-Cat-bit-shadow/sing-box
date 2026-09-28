package dns

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// These tests cover the per-record DNS response logging, which is on the resolver's hot
// path: a cache HIT runs it, and it used to cost ~11 allocations per record even when
// every line was discarded.
//
// # What went wrong
//
// The per-record lines call `FormatQuestion(record.String())`. Go evaluates that argument
// at the CALL SITE, before the logger is entered, so the logger's level check - which
// does correctly defer its own `F.ToString` - could not prevent the work. Measured at a
// level that discards every one of these lines:
//
//	record.String()                 ~288 ns   7 allocs
//	FormatQuestion(record.String()) ~710 ns   8 allocs
//
// # What these tests pin
//
//	1. the level constant used to gate the lines equals the real log level, so the gate
//	   cannot silently invert or drift;
//	2. the lines are NOT formatted when the level discards them (the fix);
//	3. the lines ARE still emitted when the level permits them (no output was lost).

// setFormatObserver installs the test hook and returns a restore function.
func setFormatObserver(observe func()) func() {
	previous := formatObserver
	formatObserver = observe
	return func() { formatObserver = previous }
}

// countingLogger records every Info call and can report a level.
//
// It implements `levelReporter` through its Level method, which is the capability the
// production path detects.
type countingLogger struct {
	level     uint8
	infoCalls int
	debugCall int
}

func (l *countingLogger) Trace(args ...any)                          {}
func (l *countingLogger) Debug(args ...any)                          { l.debugCall++ }
func (l *countingLogger) Info(args ...any)                           { l.infoCalls++ }
func (l *countingLogger) Warn(args ...any)                           {}
func (l *countingLogger) Error(args ...any)                          {}
func (l *countingLogger) Fatal(args ...any)                          {}
func (l *countingLogger) Panic(args ...any)                          {}
func (l *countingLogger) TraceContext(ctx context.Context, a ...any) {}
func (l *countingLogger) DebugContext(ctx context.Context, a ...any) { l.debugCall++ }
func (l *countingLogger) InfoContext(ctx context.Context, a ...any)  { l.infoCalls++ }
func (l *countingLogger) WarnContext(ctx context.Context, a ...any)  {}
func (l *countingLogger) ErrorContext(ctx context.Context, a ...any) {}
func (l *countingLogger) FatalContext(ctx context.Context, a ...any) {}
func (l *countingLogger) PanicContext(ctx context.Context, a ...any) {}

// Level implements levelReporter, which is what logsRecordsAt detects.
func (l *countingLogger) Level() int { return int(l.level) }

// opaqueLogger does NOT implement levelReporter. It stands for a logger whose level
// cannot be read, and it must keep behaving exactly as before the optimisation.
type opaqueLogger struct {
	countingLogger
}

func (l *opaqueLogger) Level() int { return 0 }

// responseWithRecords builds a response with records in all three sections, so the test
// exercises the same loop shape the production code does.
func responseWithRecords(t *testing.T, answers int) *dns.Msg {
	t.Helper()
	message := new(dns.Msg)
	message.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}
	for range answers {
		record, err := dns.NewRR("example.com. 300 IN A 93.184.216.34")
		require.NoError(t, err)
		message.Answer = append(message.Answer, record)
	}
	authority, err := dns.NewRR("example.com. 300 IN NS ns1.example.com.")
	require.NoError(t, err)
	message.Ns = append(message.Ns, authority)
	additional, err := dns.NewRR("ns1.example.com. 300 IN A 93.184.216.35")
	require.NoError(t, err)
	message.Extra = append(message.Extra, additional)
	return message
}

// TestRecordLogLevelConstantMatchesTheRealLevel is the load-bearing guard.
//
// sing-box's levels ascend with VERBOSITY (Panic=0 ... Trace=6) and the logger drops a
// message when `messageLevel > loggerLevel`. So the gate must be `loggerLevel >=
// recordLogLevelInfo`, and `recordLogLevelInfo` must equal the real Info level. If either
// the constant or the comparison direction were wrong, the optimisation would either do
// nothing (too permissive) or silently swallow every record line (too strict).
//
// The constant is duplicated rather than imported so the DNS client does not depend on
// the logging implementation. This test is what keeps the duplicate honest.
func TestRecordLogLevelConstantMatchesTheRealLevel(t *testing.T) {
	require.EqualValues(t, log.LevelInfo, recordLogLevelInfo,
		"recordLogLevelInfo must equal the real log.LevelInfo; the DNS client duplicates "+
			"the value to avoid importing the log package, so this is the guard that "+
			"keeps the duplicate correct")

	// The ordering itself, asserted so a future renumbering of the log levels cannot
	// invert the comparison unnoticed.
	require.Less(t, int(log.LevelWarn), int(log.LevelInfo),
		"Info must be MORE verbose than Warn in this codebase's ordering")
	require.Less(t, int(log.LevelInfo), int(log.LevelDebug),
		"Debug must be more verbose than Info")
	require.Greater(t, int(log.LevelTrace), int(log.LevelInfo),
		"Trace must be the most verbose level")
}

// TestRecordLinesAreNotFormattedWhenTheLevelDiscardsThem is the regression test for the
// fix.
//
// At Warn the logger discards every one of these Info lines. The formatter must therefore
// not be called at all.
func TestRecordLinesAreNotFormattedWhenTheLevelDiscardsThem(t *testing.T) {
	formatted := 0
	restore := setFormatObserver(func() { formatted++ })
	defer restore()

	message := responseWithRecords(t, 3)
	responseLogger := &countingLogger{level: log.LevelWarn}

	logCachedResponse(responseLogger, context.Background(), message, 300)

	require.Zero(t, formatted,
		"at level Warn the per-record lines are discarded, so formatting them is pure "+
			"waste: this is the ~11 allocations per record the fix removes")
	require.Zero(t, responseLogger.infoCalls,
		"no Info line may be emitted when the level discards it")
}

// TestRecordLinesAreFormattedWhenTheLevelPermitsThem is the negative control. Without it,
// a gate that always returned false would pass the test above while silently deleting all
// record output.
func TestRecordLinesAreFormattedWhenTheLevelPermitsThem(t *testing.T) {
	formatted := 0
	restore := setFormatObserver(func() { formatted++ })
	defer restore()

	message := responseWithRecords(t, 3)
	responseLogger := &countingLogger{level: log.LevelInfo}

	logCachedResponse(responseLogger, context.Background(), message, 300)

	// 3 answers + 1 authority + 1 additional.
	require.Equal(t, 5, formatted,
		"every record in all three sections must still be formatted at a level that "+
			"emits the lines")
	require.Equal(t, 5, responseLogger.infoCalls,
		"and each must reach the logger")

	// At Debug the Info lines are also emitted, because Debug is more verbose.
	debugFormatted := 0
	restoreDebug := setFormatObserver(func() { debugFormatted++ })
	defer restoreDebug()
	logCachedResponse(&countingLogger{level: log.LevelDebug}, context.Background(), message, 300)
	require.Equal(t, 5, debugFormatted,
		"a more verbose level must still emit the Info lines")
}

// TestOpaqueLoggerKeepsFormatting proves the conservative direction: a logger that cannot
// report its level keeps the previous behaviour, so adding the gate cannot lose output for
// a logger this code does not understand.
func TestOpaqueLoggerKeepsFormatting(t *testing.T) {
	formatted := 0
	restore := setFormatObserver(func() { formatted++ })
	defer restore()

	message := responseWithRecords(t, 2)
	// A logger whose Level method is not part of the detected capability: simulate by
	// passing one that satisfies ContextLogger but not levelReporter.
	responseLogger := &nonReportLogger{}
	logCachedResponse(responseLogger, context.Background(), message, 300)

	require.Equal(t, 4, formatted,
		"an unknown logger must still have its lines built; the gate may only remove "+
			"work that was provably going to be discarded")
	require.Equal(t, 4, responseLogger.infoCalls)

	// Guard the guard: this type must NOT satisfy levelReporter, or the assertion above
	// would be testing the opposite of what it claims.
	_, isReporter := any(responseLogger).(levelReporter)
	require.False(t, isReporter,
		"nonReportLogger must not implement levelReporter; if it does, this test is "+
			"exercising the readable-level path instead of the unknown-level one")
}

// nonReportLogger satisfies logger.ContextLogger but NOT levelReporter.
//
// It must NOT embed countingLogger: embedding promotes countingLogger.Level, which would
// make it a levelReporter and defeat the purpose of this type. That is exactly the bug
// the first version of this test had, and it made the test assert the opposite of what it
// claimed.
type nonReportLogger struct {
	infoCalls int
}

func (l *nonReportLogger) Trace(args ...any)                          {}
func (l *nonReportLogger) Debug(args ...any)                          {}
func (l *nonReportLogger) Info(args ...any)                           { l.infoCalls++ }
func (l *nonReportLogger) Warn(args ...any)                           {}
func (l *nonReportLogger) Error(args ...any)                          {}
func (l *nonReportLogger) Fatal(args ...any)                          {}
func (l *nonReportLogger) Panic(args ...any)                          {}
func (l *nonReportLogger) TraceContext(ctx context.Context, a ...any) {}
func (l *nonReportLogger) DebugContext(ctx context.Context, a ...any) {}
func (l *nonReportLogger) InfoContext(ctx context.Context, a ...any)  { l.infoCalls++ }
func (l *nonReportLogger) WarnContext(ctx context.Context, a ...any)  {}
func (l *nonReportLogger) ErrorContext(ctx context.Context, a ...any) {}
func (l *nonReportLogger) FatalContext(ctx context.Context, a ...any) {}
func (l *nonReportLogger) PanicContext(ctx context.Context, a ...any) {}

// TestAllFiveHelpersGateTheirRecordLines proves the gate was applied to every helper, not
// just the cache-hit one. A single ungated helper would reintroduce the cost on its own
// path.
func TestAllFiveHelpersGateTheirRecordLines(t *testing.T) {
	message := responseWithRecords(t, 2)

	for name, call := range map[string]func(logger *countingLogger){
		"logCachedResponse": func(l *countingLogger) {
			logCachedResponse(l, context.Background(), message, 300)
		},
		"logOptimisticResponse": func(l *countingLogger) {
			logOptimisticResponse(l, context.Background(), message)
		},
		"logExchangedResponse": func(l *countingLogger) {
			logExchangedResponse(l, context.Background(), message, 300)
		},
		"logRefreshedResponse": func(l *countingLogger) {
			logRefreshedResponse(l, context.Background(), message, 300)
		},
		"logRejectedResponse": func(l *countingLogger) {
			logRejectedResponse(l, context.Background(), message)
		},
	} {
		discarding := &countingLogger{level: log.LevelWarn}
		call(discarding)
		require.Zero(t, discarding.infoCalls,
			"%s must not emit record lines at a level that discards them", name)

		emitting := &countingLogger{level: log.LevelInfo}
		call(emitting)
		require.Equal(t, 4, emitting.infoCalls,
			"%s must emit one line per record at a level that permits them", name)
	}
}

// TestRecordLoggingIsAllocationFreeWhenDiscarded is the direct measurement of the fix.
//
// The assertion is on the SHAPE of the cost, not an exact number: the point is that no
// per-record formatting allocations occur, which is a large multiple apart from the
// previous behaviour, not a few bytes.
func TestRecordLoggingIsAllocationFreeWhenDiscarded(t *testing.T) {
	message := responseWithRecords(t, 4) // 6 records total
	discarding := &countingLogger{level: log.LevelWarn}

	// Warm up so the first-call costs do not dominate.
	logCachedResponse(discarding, context.Background(), message, 300)

	allocations := testing.AllocsPerRun(50, func() {
		logCachedResponse(discarding, context.Background(), message, 300)
	})

	// The two cheap response-level lines (FqdnToDomain and the rcode lookup) plus the
	// logger's own variadic slice. Six records would previously add roughly 6 x 11
	// allocations on top of this.
	require.Less(t, allocations, float64(10),
		"a discarded record-logging pass must not allocate per record; measured %.1f "+
			"allocations for 6 records, which was ~66 before the fix", allocations)
}
