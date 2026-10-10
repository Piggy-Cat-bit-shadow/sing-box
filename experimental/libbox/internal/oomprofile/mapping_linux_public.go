//go:build linux && !tfogo_checklinkname0

package oomprofile

// The public-API half of the Linux mapping reader, compiled wherever the private one is not.
//
// This is a REPLACEMENT, not a degradation, and it reproduces the private parser's behaviour field
// for field and quirk for quirk. `runtime/pprof.parseProcSelfMaps` reports lo, hi, offset and file
// per line of /proc/self/maps; so does this. What it does NOT reproduce is the mapping build ID,
// which the private parser reads out of the mapped file's ELF header rather than out of
// /proc/self/maps (the maps line has no such column). See the note on that below.
//
// Reference for the format: `man 5 proc_pid_maps`.
//
// # The quirks that are behaviour, not detail
//
// A parser that only splits the obvious columns produces a DIFFERENT mapping table, which is
// observable in the profile even though Go symbolisation does not read mappings at all. All four of
// the private parser's filters are reproduced here:
//
//  1. ONLY EXECUTABLE mappings are reported (permissions field, third character 'x'). Without this
//     the table gains every anonymous and data mapping in the process.
//  2. A line whose inode is "0" AND whose pathname is empty is dropped - the huge-page text-mapping
//     artefact - while `[vdso]` and `[vsyscall]`, which are also inode 0, are kept because their
//     pathname is not empty.
//  3. A trailing " (deleted)" marker is trimmed off the pathname.
//  4. The pathname is the REMAINDER of the line after the inode column, not a whitespace field, so
//     a path containing spaces survives intact. A line that ends at the inode column is dropped.
//  5. When the table comes out empty the caller still records one fake mapping; that fallback lives
//     in the caller, so it applies to both halves.

import (
	"bytes"
	"os"
	"strconv"
)

func (b *profileBuilder) readMapping() {
	data, _ := os.ReadFile(pidMapsPath)
	parseProcSelfMaps(data, func(lo, hi, offset uint64, file, buildID string) {
		b.addMappingEntry(lo, hi, offset, file, buildID, false)
	})
	if len(b.mem) == 0 {
		b.addMappingEntry(0, 0, 0, "", "", true)
	}
}

// linuxMappingReaderIsPrivate reports that this build does NOT carry the private reader, so the two
// configurations can be told apart by a test instead of by reading build constraints.
func linuxMappingReaderIsPrivate() bool { return false }

// parseProcSelfMaps walks /proc/self/maps line by line and reports each mapping.
//
// The build ID argument is always empty here, and that is the one bounded difference from the
// private parser: the private one fills it with the GNU build ID of the file the mapping points at,
// read from that file's ELF notes. An absent build ID means pprof cannot match a mapping against a
// separate binary by build ID - which is EXACTLY the status quo elsewhere in the standard library:
// its own Darwin writer passes "" for every mapping ("currently no attempt is made to obtain the
// buildID information") and its Windows writer substitutes a path-plus-modtime string that is not a
// build ID at all. Go symbolisation, sample values, locations, functions and lines do not consult
// it. Restoring it would mean re-implementing the ELF note walk, which is a real implementation
// rather than a fallback and does not belong in the link-safe path.
//
// A malformed line is SKIPPED rather than fatal. This runs on the OOM path, where a partial mapping
// table is worth more than none and an allocation failure is the thing being diagnosed.
func parseProcSelfMaps(data []byte, addMapping func(lo uint64, hi uint64, offset uint64, file string, buildID string)) {
	for len(data) > 0 {
		var line []byte
		line, data, _ = bytes.Cut(data, []byte{'\n'})

		// next removes and returns the next field, and the spaces that follow it.
		next := func() []byte {
			var field []byte
			field, line, _ = bytes.Cut(line, []byte{' '})
			line = bytes.TrimLeft(line, " ")
			return field
		}

		loStr, hiStr, ok := bytes.Cut(next(), []byte{'-'})
		if !ok {
			continue
		}
		lo, err := strconv.ParseUint(string(loStr), 16, 64)
		if err != nil {
			continue
		}
		hi, err := strconv.ParseUint(string(hiStr), 16, 64)
		if err != nil {
			continue
		}
		perm := next()
		if len(perm) < 4 || perm[2] != 'x' {
			// Quirk 1: only executable mappings.
			continue
		}
		offset, err := strconv.ParseUint(string(next()), 16, 64)
		if err != nil {
			continue
		}
		next()          // dev
		inode := next() // inode
		if line == nil {
			// Quirk 4: the line ended at the inode column.
			continue
		}
		file := string(line)

		// Quirk 3: trim the deleted-file marker.
		const deletedSuffix = " (deleted)"
		if len(file) >= len(deletedSuffix) && file[len(file)-len(deletedSuffix):] == deletedSuffix {
			file = file[:len(file)-len(deletedSuffix)]
		}

		if len(inode) == 1 && inode[0] == '0' && file == "" {
			// Quirk 2: the unpopulated fragment of a huge-page text mapping.
			continue
		}

		addMapping(lo, hi, offset, file, "")
	}
}
