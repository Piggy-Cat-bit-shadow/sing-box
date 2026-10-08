//go:build with_utls

package interop

// buildHasUTLS records the `with_utls` build tag at compile time.
//
// The harness needs to distinguish "the scenario failed" from "this binary
// cannot even construct the scenario", because the second is a build
// configuration mistake and must skip with a message rather than fail as if the
// protocol were broken. common/tls replaces the REALITY client with a stub that
// returns `uTLS, which is required by reality is not included in this build`
// when the tag is absent, so a REALITY scenario in a tag-less build would fail
// at box.New with an error that says nothing about the reference.
const buildHasUTLS = true
