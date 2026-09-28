//go:build !jiejie_client_macos

package main

// Every other build keeps the complete upstream CLI.
//
// The upstream-compatible and Linux-server builds are generic: they may be driven
// by scripts, packaging pipelines or documentation that this fork does not own, so
// withholding commands there would be a silent compatibility break. Only the
// macOS product, whose entire call surface is known, narrows its CLI.
func productExcludesCommand(name string) bool {
	return false
}
