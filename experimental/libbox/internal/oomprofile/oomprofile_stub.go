//go:build (darwin || linux || windows) && !tfogo_checklinkname0

package oomprofile

// The link-safe half of this package, compiled wherever the real implementation is not.
//
// # Why the package splits at all
//
// The profile builder reads the runtime's own profile buffers. The only way to do that without
// copying `runtime/pprof` is the private interface it uses internally: five pulls of `runtime`
// symbols, which the runtime PUSHES, and six pulls of `runtime/pprof` symbols, which it does NOT
// (measured against the pinned toolchain: `runtime` declares 169 push directives, `runtime/pprof`
// declares 0). A pull with no matching push is rejected by the Go linker under its default
// `-checklinkname=1` policy:
//
//	link: .../internal/oomprofile: invalid reference to runtime/pprof.parseProcSelfMaps
//
// The flag that relaxes that policy, `-checklinkname=0`, is a property of the BUILDER: cmd/go cannot
// inject it per package. So the real implementation can be compiled only where the builder passes
// the flag, and it records that with `tfogo_checklinkname0` - the tag this repository uses for
// exactly this, the way `experimental/libbox/internal/runtimeinfo/goroutine_badlinkname.go` and
// `experimental/libbox/signal_handler_darwin.go` already do.
//
// # What each configuration gets
//
//   - A product build carries the tag, because its builder passes the flag:
//     `cmd/internal/mobilebuildtags.sharedTags` holds it for every mobile and Apple target, and
//     `cmd/internal/build_boxdd` appends it for the desktop daemon - in both cases because
//     `cmd/internal/build_shared.LinkerFlags` puts `-checklinkname=0` on the linker command line. It
//     compiles the real implementation, unchanged, and the OOM profile it writes is byte-for-byte
//     what it was before this split.
//
//   - A bare `go build ./...` carries no tag and passes no flag. It compiles this file instead, so
//     the tree still builds and links, and the capability is ABSENT RATHER THAN WRONG: WriteFile
//     returns an error naming the missing tag and flag. Nothing is silently degraded and no caller
//     can mistake a stub profile for a real one.
//
// The two halves cannot both be compiled, and which one is present is observable rather than
// assumed: profileSupport() answers it, and the package's tests assert both directions.

import "errors"

// WriteFile writes the runtime profile named `name` to `filePath`.
//
// In a build without the capability tag this reports the missing capability instead of writing a
// partial or empty profile.
func WriteFile(filePath string, name string) error {
	return errors.New("oomprofile: this build does not carry the OOM profile writer: it needs the " +
		"tfogo_checklinkname0 build tag AND the linker flag -checklinkname=0, because reading the " +
		"runtime's profile buffers requires //go:linkname pulls of runtime/pprof, which pushes no " +
		"symbols. Every shipping build (the mobile and Apple tag sets in " +
		"cmd/internal/mobilebuildtags, and cmd/internal/build_boxdd for the desktop daemon) carries " +
		"both; a bare `go build ./...` carries neither, by design, because -checklinkname=0 cannot be " +
		"injected per package by cmd/go. Rebuild with the product tag set to get OOM profiling")
}

// profileSupport reports whether this build carries the real writer.
func profileSupport() bool { return false }
