// Package jiejie_test holds the Jiejie Server Edition production integration
// tests in their own package so they depend only on local Go loopback fixtures.
//
// The upstream `test` package imports the whole upstream integration suite, which
// pulls Docker images for shadowsocks-rust, v2ray, trojan, naive, hysteria, tuic,
// xray and others. Running a Jiejie test there still contacted the Docker daemon
// and downloaded unrelated protocol images, which the server tests do not need.
//
// Everything here is loopback: no Docker, no network beyond localhost, no
// registry access.
package jiejie_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

// globalCtx carries the registry the box needs to resolve protocol types. It is
// built from the compiled-in registries, so this package links exactly the build
// it is compiled with (minimal or default).
var globalCtx = include.Context(context.Background())

var _ = adapter.Router(nil)

// startInstance starts a box in-process and returns it.
//
// Unlike the upstream helper this one does NOT overwrite options.Log when the
// caller already supplied an output, so tests can capture real log output.
func startInstance(t *testing.T, options option.Options) *box.Box {
	t.Helper()
	ctx, cancel := context.WithCancel(globalCtx)
	var (
		instance *box.Box
		err      error
	)
	for retry := 0; retry < 3; retry++ {
		instance, err = box.New(box.Options{
			Context: ctx,
			Options: options,
		})
		require.NoError(t, err)
		err = instance.Start()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		break
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		instance.Close()
		cancel()
	})
	return instance
}

// reserveTCPPort asks the kernel for a free loopback TCP port.
func reserveTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

// reserveUDPPort asks the kernel for a free loopback UDP port.
func reserveUDPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return uint16(listener.LocalAddr().(*net.UDPAddr).Port)
}

// mkBase64 returns a base64 random key of the given length, used for SS2022.
func mkBase64(t *testing.T, length int) string {
	t.Helper()
	psk := make([]byte, length)
	_, err := rand.Read(psk)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(psk)
}
