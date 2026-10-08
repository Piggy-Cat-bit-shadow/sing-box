package libbox

import (
	"github.com/sagernet/sing-box/experimental/deprecated"
)

var _ = deprecated.Note(DeprecatedNote{})

type DeprecatedNote struct {
	Name              string
	Description       string
	DeprecatedVersion string
	ScheduledVersion  string
	EnvName           string
	MigrationLink     string
}

func (n DeprecatedNote) Impending() bool {
	return deprecated.Note(n).Impending()
}

// Message and MessageWithLink return *StringBox rather than string. Both are Go-implemented
// accessors read FROM the bound language and so put a pointer into cmd/cgo's packed result frame
// (the `bulkBarrierPreWrite: unaligned arguments` shape tracked by gomobile_surface_test.go).
// StringBox keeps the pointer in a heap object; the client reads it through Value, the same way
// it already reads TunOptions.GetDNSMode.
//
// Shipped call sites that move with this signature:
//
//	clients/apple/ApplicationLibrary/Views/Abstract/GlobalChecksModifier.swift
//	    report.message()!.value        (three call sites)
//	clients/android/.../compose/screen/dashboard/DashboardViewModel.kt
//	    note.message().value
//
// MessageWithLink has no call site in either client (the migration link is read from the
// MigrationLink FIELD, not from this method), so for it the change is a pure removal of a
// pointer-bearing frame.
func (n DeprecatedNote) Message() *StringBox {
	return wrapString(deprecated.Note(n).Message())
}

func (n DeprecatedNote) MessageWithLink() *StringBox {
	return wrapString(deprecated.Note(n).MessageWithLink())
}

type DeprecatedNoteIterator interface {
	HasNext() bool
	Next() *DeprecatedNote
}
