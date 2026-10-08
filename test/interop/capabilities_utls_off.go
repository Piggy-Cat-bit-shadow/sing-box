//go:build !with_utls

package interop

// buildHasUTLS is false in a build without the `with_utls` tag. See the
// positive form for why the distinction matters.
const buildHasUTLS = false
