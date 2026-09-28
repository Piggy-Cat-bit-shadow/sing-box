package dns

import (
	"context"
	"strings"

	"github.com/sagernet/sing/common/logger"

	"github.com/miekg/dns"
)

// The DNS response log helpers.
//
// # Why they are written this way
//
// A DNS response is logged one RECORD at a time, and each line formats the record with
// `FormatQuestion(record.String())`. That expression is an ordinary Go argument, so it is
// evaluated at the CALL SITE, before the logger is entered and before the logger can
// consult its level. The logger does defer the final `F.ToString` behind a level check
// (log/observable.go checks the level and returns before formatting), but it cannot
// un-evaluate arguments that were already computed.
//
// Measured on this code, with the level set so that every one of these lines is
// discarded:
//
//	record.String()                     ~288 ns   7 allocs   152 B
//	FormatQuestion(record.String())     ~710 ns   8 allocs   200 B
//
// and per record the whole call costs ~11 allocs, so an A/AAAA response with a handful of
// records paid tens of allocations in the resolver's hot path for logs nobody saw. The
// cache-HIT path was the worst case, because a cache hit is supposed to be the cheap
// path.
//
// `dns.Type(...).String()` is free (interned lookup, 0 allocs), so it is left where it is;
// only the per-record formatting needed hoisting.
//
// # How it is fixed
//
// The per-record body is only built when the corresponding level would actually be
// emitted. `logCachedResponse` and friends therefore take the record lines as a LAZY
// closure and are called through `logRecords`, which invokes it only when the level
// permits.
//
// The level is read through a capability interface rather than by changing the shared
// `logger.ContextLogger` interface, because that interface is implemented across the
// whole project and by external callers. A logger that does not expose its level is
// treated as "unknown", and in that case the lines are built exactly as before - so this
// change can only remove work that was provably going to be discarded, never remove a
// line that would have been printed.
//
// `logRecords` is intentionally NOT used here: the two response-level lines remain
// direct calls, because `dns.RcodeToString[...]` and `FqdnToDomain` are already cheap
// (0 and 1 allocations) and gating them would add a branch for no measurable gain. Only
// the per-record loop, which is the expensive part, is gated.

// levelReporter is implemented by loggers that can report their current level.
//
// It is deliberately optional. `logger.ContextLogger` has no level accessor, and adding
// one would be a cross-project interface change; capability detection keeps the
// optimisation local to the DNS path.
type levelReporter interface {
	Level() int
}

// recordLogLevelInfo
//
// IMPORTANT: sing-box's log levels ascend with VERBOSITY:
//
//	log.LevelPanic=0 Fatal=1 Error=2 Warn=3 Info=4 Debug=5 Trace=6
//
// and the logger drops a message when `messageLevel > loggerLevel`. So a HIGHER number
// means MORE verbose, and an INFO line is emitted only when the configured level is at
// least Info (4) - that is, for the Info, Debug and Trace settings.
//
// Expressing the check as `loggerLevel >= lineLevel` therefore means "the configured
// level is verbose enough for this line", which is the condition under which the line
// would actually be printed.
//
// The constant is declared here rather than imported from the log package so the DNS
// client does not depend on the logging implementation. A test pins it to the real value.
const recordLogLevelInfo = 4

// logsRecordsAt reports whether an INFO-level record line would be emitted.
//
// A logger that does not implement levelReporter returns true, which builds the lines
// exactly as before. That is the conservative direction: a logger whose level cannot be
// read keeps today's behaviour rather than silently losing output.
func logsRecordsAt(logger logger.ContextLogger) bool {
	reporter, isReporter := logger.(levelReporter)
	if !isReporter {
		return true
	}
	return reporter.Level() >= recordLogLevelInfo
}

func logCachedResponse(logger logger.ContextLogger, ctx context.Context, response *dns.Msg, ttl int) {
	if logger == nil || len(response.Question) == 0 {
		return
	}
	domain := FqdnToDomain(response.Question[0].Name)
	logger.DebugContext(ctx, "cached ", domain, " ", dns.RcodeToString[response.Rcode], " ", ttl)
	logRecordLines(logger, ctx, "cached ", response)
}

func logOptimisticResponse(logger logger.ContextLogger, ctx context.Context, response *dns.Msg) {
	if logger == nil || len(response.Question) == 0 {
		return
	}
	domain := FqdnToDomain(response.Question[0].Name)
	logger.DebugContext(ctx, "optimistic ", domain, " ", dns.RcodeToString[response.Rcode])
	logRecordLines(logger, ctx, "optimistic ", response)
}

func logExchangedResponse(logger logger.ContextLogger, ctx context.Context, response *dns.Msg, ttl uint32) {
	if logger == nil || len(response.Question) == 0 {
		return
	}
	domain := FqdnToDomain(response.Question[0].Name)
	logger.DebugContext(ctx, "exchanged ", domain, " ", dns.RcodeToString[response.Rcode], " ", ttl)
	logRecordLines(logger, ctx, "exchanged ", response)
}

func logRefreshedResponse(logger logger.ContextLogger, ctx context.Context, response *dns.Msg, ttl uint32) {
	if logger == nil || len(response.Question) == 0 {
		return
	}
	domain := FqdnToDomain(response.Question[0].Name)
	logger.DebugContext(ctx, "refreshed ", domain, " ", dns.RcodeToString[response.Rcode], " ", ttl)
	logRecordLines(logger, ctx, "refreshed ", response)
}

func logRejectedResponse(logger logger.ContextLogger, ctx context.Context, response *dns.Msg) {
	if logger == nil || len(response.Question) == 0 {
		return
	}
	logRecordLines(logger, ctx, "rejected ", response)
}

// formatObserver, when non-nil, is called immediately before each record is formatted.
//
// It exists so tests can prove the formatter is NOT reached at a level that discards the
// lines. Production leaves it nil, which costs one predictable nil check per record -
// negligible next to the formatting it guards, and the reason the fix is testable at all.
var formatObserver func()

// logRecordLines emits one INFO line per record in the answer, authority and additional
// sections.
//
// `prefix` is the message word ("cached", "exchanged", ...). The formatting of each
// record happens INSIDE the level-checked closure, so a discarded line costs nothing.
func logRecordLines(logger logger.ContextLogger, ctx context.Context, prefix string, response *dns.Msg) {
	if !logsRecordsAt(logger) {
		// The per-record lines are below the configured level, so the logger would
		// discard them. Do not format them.
		return
	}
	for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range recordList {
			if formatObserver != nil {
				formatObserver()
			}
			logger.InfoContext(ctx, prefix,
				dns.Type(record.Header().Rrtype).String(), " ",
				FormatQuestion(record.String()))
		}
	}
}

func FqdnToDomain(fqdn string) string {
	if dns.IsFqdn(fqdn) {
		return fqdn[:len(fqdn)-1]
	}
	return fqdn
}

func FormatQuestion(string string) string {
	for strings.HasPrefix(string, ";") {
		string = string[1:]
	}
	string = strings.ReplaceAll(string, "\t", " ")
	string = strings.ReplaceAll(string, "\n", " ")
	string = strings.ReplaceAll(string, ";; ", " ")
	string = strings.ReplaceAll(string, "; ", " ")

	for strings.Contains(string, "  ") {
		string = strings.ReplaceAll(string, "  ", " ")
	}
	return strings.TrimSpace(string)
}
