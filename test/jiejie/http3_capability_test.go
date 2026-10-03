package jiejie_test

// HTTP/3 capability as this build actually has it.
//
// # Why a compile-time constant rather than a runtime probe
//
// Asking whether a QUIC handshake succeeds cannot distinguish "HTTP/3 is not in this build" from
// "HTTP/3 is in this build and broken". Those two must be reported differently - the first is a SKIP,
// the second is a failure - so the capability has to be a fact about the build rather than an
// observation of its behaviour.
//
// # What decides the answer
//
// The gate is `with_quic`, and nothing else:
//
//	include/quic.go        //go:build with_quic    imports protocol/naive/quic
//	include/quic_stub.go   //go:build !with_quic   installs an inert listener func
//
// The two constants live in files carrying exactly those constraints, so the tag that selects the
// real package is the same tag that selects the constant. A build cannot report HTTP/3 as linked
// while linking the stub, or the reverse.
//
// # What this replaced
//
// These constants previously also carried `!jiejie_server_minimal` and `!jiejie_client_macos`. Both
// tags belonged to a capability-pruning architecture that has been retired: both products now build
// from upstream's complete registry, so no fork-side tag can remove a capability and the extra
// clauses had become permanently true. Keeping them would have preserved a claim about the build
// that is no longer how the build works.
//
// http3SupportLinked is the test layer's only capability API. It is a function so that call sites
// read as a question, and it is deliberately a thin wrapper so there is exactly one place to change
// if the gate ever moves.

// http3SupportLinked reports whether this build links HTTP/3.
//
// Callers use it to SKIP tests that need a real QUIC listener, which is why the answer must come
// from the build rather than from an attempted handshake.
func http3SupportLinked() bool {
	return http3SupportIncluded
}
