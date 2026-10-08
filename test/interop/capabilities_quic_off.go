//go:build !with_quic

package interop

// buildHasQUIC is false in a build without the `with_quic` tag. See the
// positive form for why the distinction matters.
const buildHasQUIC = false
