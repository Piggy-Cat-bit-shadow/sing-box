//go:build with_xhttp

package interop

// buildHasXHTTP records the `with_xhttp` build tag at compile time.
//
// Without it nothing registers the "xhttp" client transport constructor, and a
// scenario that names it fails at box.New with the ordinary "unknown transport
// type: xhttp". That is the correct production behaviour and the wrong test
// failure: the stand has to say "rebuild with the tag" instead.
const buildHasXHTTP = true
