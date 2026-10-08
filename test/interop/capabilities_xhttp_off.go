//go:build !with_xhttp

package interop

// buildHasXHTTP is false in a build without the `with_xhttp` tag. See the
// positive form for why the distinction matters.
const buildHasXHTTP = false
