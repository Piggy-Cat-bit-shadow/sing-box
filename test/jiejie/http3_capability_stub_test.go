//go:build !with_quic

package jiejie_test

// http3SupportIncluded is false when this build does not link HTTP/3.
//
// See http3_capability_test.go for why this is a compile-time constant rather than a runtime probe.
// This variant is selected by the build tag that actually decides the answer.
const http3SupportIncluded = false
