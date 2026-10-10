//go:build (darwin || linux || windows) && tfogo_checklinkname0

package oomprofile

// The two //go:linkname pulls this package makes that need the linker flag -checklinkname=0. They
// live in their own file, gated on the tag that records the flag, so that the file holding them
// cannot be compiled into a build that would fail to link.
//
// The distinction is per-DEFINITION, not per-name, and it is why only these two are here.
// `runtime/pprof.parseProcSelfMaps` and `runtime/pprof.elfBuildID` are defined by package
// runtime/pprof itself, which carries no push linkname at all, so a reference to either is rejected
// under the linker's default policy:
//
//	link: .../internal/oomprofile: invalid reference to runtime/pprof.parseProcSelfMaps
//
// Their neighbours in linkname.go - runtime_FrameStartLine, runtime_FrameSymbolName,
// runtime_expandFinalInlineFrame, runtime_cyclesPerSecond, mach_vm_region and the rest - are named
// as if they belonged to runtime/pprof, but their definitions live in package runtime and DO carry
// push linknames, so they link under the default policy and stay in the ungated file.
//
// The only reference to parseProcSelfMaps is mapping_linux.go, which is gated on the same tag, so
// the two are compiled together or not at all. Mapping on a build without the flag is handled by
// mapping_linux_public.go, which reads the same file with a public parser.

import (
	// Required for //go:linkname. Without an import of unsafe in the file, the directive is inert
	// and these two become declarations with no body, which does not compile.
	_ "unsafe"
)

//go:linkname stdParseProcSelfMaps runtime/pprof.parseProcSelfMaps
func stdParseProcSelfMaps(data []byte, addMapping func(lo uint64, hi uint64, offset uint64, file string, buildID string))

// stdELFBuildID has no caller today: the build IDs that reach a profile are read inside the private
// parseProcSelfMaps, not through this declaration. It is kept because it names the dependency, and
// because it is the second of the two pulls that would need the flag if anything ever called it.
//
//go:linkname stdELFBuildID runtime/pprof.elfBuildID
func stdELFBuildID(file string) (string, error)
