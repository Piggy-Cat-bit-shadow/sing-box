//go:build linux && tfogo_checklinkname0

package oomprofile

// The private half of the Linux mapping reader. `runtime/pprof.parseProcSelfMaps` is one of only TWO
// symbols this package pulls that genuinely need the linker flag `-checklinkname=0`: it is DEFINED by
// package runtime/pprof (runtime/pprof/proto.go) and carries no push linkname, so the linker rejects
// the reference under its default policy.
//
// The distinction is per-DEFINITION, not per-name, and it is why this file is the only one that has
// to be gated. `runtime/pprof.runtime_FrameStartLine`, `runtime/pprof.mach_vm_region` and their
// neighbours LOOK like they belong to runtime/pprof, but they are defined by package runtime with
// push linknames, so they link under the default policy and their files need no tag.
//
// `-checklinkname=0` is a property of the BUILDER - cmd/go cannot inject it per package - so this
// file is compiled only where the builder really passes it, which `tfogo_checklinkname0` records.
// Every product tag set carries that tag because its builder passes the flag: the mobile and Apple
// sets through cmd/internal/mobilebuildtags.sharedTags, and the desktop daemon because
// cmd/internal/build_boxdd appends it, in both cases via cmd/internal/build_shared.LinkerFlags.
// Android needs it, because the android platform satisfies the linux build tag. The bare
// configuration compiles mapping_linux_public.go instead.

import "os"

func (b *profileBuilder) readMapping() {
	data, _ := os.ReadFile(pidMapsPath)
	stdParseProcSelfMaps(data, func(lo, hi, offset uint64, file, buildID string) {
		b.addMappingEntry(lo, hi, offset, file, buildID, false)
	})
	if len(b.mem) == 0 {
		b.addMappingEntry(0, 0, 0, "", "", true)
	}
}

// linuxMappingReaderIsPrivate reports that this build carries the private reader, so which half was
// compiled is observable rather than assumed.
func linuxMappingReaderIsPrivate() bool { return true }
