//go:build !darwin || !badlinkname || !tfogo_checklinkname0

// The negation of signal_handler_darwin.go's constraint. !tfogo_checklinkname0 covers the
// `go test` build, which links with the default -checklinkname policy: cmd/go has no
// per-package way to set -ldflags=-checklinkname=0, so a test binary cannot carry the real
// implementation's runtime-internal linknames. Keeping badlinkname here (rather than
// dropping it from the test tag set) is deliberate: every other linknamed path in the
// package passes checklinkname on its own, and the tests should keep compiling it.
package libbox

func PrepareCrashSignalHandlers() {}

func ReinstallCrashSignalHandlers() {}
