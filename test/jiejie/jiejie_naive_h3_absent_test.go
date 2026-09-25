//go:build !with_quic || jiejie_server_minimal

package jiejie_test

// naiveHTTP3Included is false when the build does not link protocol/naive/quic.
// See the with_quic variant for why this is a compile-time constant.
const naiveHTTP3Included = false
