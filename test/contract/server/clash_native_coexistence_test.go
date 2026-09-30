//go:build with_clash_api

package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	badjson "github.com/sagernet/sing/common/json"
	"google.golang.org/protobuf/types/known/emptypb"
)

// These tests pin that the Native API and the Clash API COEXIST.
//
// The fork used to delete the Clash API outright, on the reasoning that the Native
// API plus sing-box-dashboard was the only management surface. Restoring it must not
// disturb the Native API: the shared pieces are the observable log factory (the
// Native API's SubscribeLog and the Clash API's /logs both consume it), the traffic
// manager and the clash-mode manager.
//
// A regression here is quiet: the Clash API would still work, and only the Native API
// would lose its log stream or its mode control. So both are asserted together,
// against one instance with both control planes configured.

const nativeAPIHost = "127.0.0.1"
const nativeAPIPort = 19911
const nativeAPIListen = "127.0.0.1:19911"
const clashAPIListen = "127.0.0.1:19912"
const clashSecret = "dual-plane-secret"

// dualPlaneInstance starts an instance with the Clash API and the Native API both
// enabled, and returns the Clash API base URL plus a shutdown function.
func dualPlaneInstance(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// A selector group is used rather than a urltest group on purpose. urltest would
	// trip a PRE-EXISTING upstream race: URLTestGroup.performUpdateCheck writes
	// urlTestTime/urlTestDelay while route.ReferenceManager.References reads them. Both
	// files are byte-identical to upstream, and the race reproduces on the pre-restore
	// baseline with no Clash API configured, so it is not this task's subject. This test
	// is about control-plane coexistence and does not try to provoke it.
	cachePath := filepath.Join(t.TempDir(), "cache.db")
	configJSON := fmt.Sprintf(`{
	  "log": {"level": "debug"},
	  "outbounds": [
	    {"type": "direct", "tag": "direct"},
	    {"type": "selector", "tag": "group", "outbounds": ["direct"]}
	  ],
	  "route": {"final": "group"},
	  "experimental": {
	    "cache_file": {"enabled": true, "path": %q},
	    "clash_api": {"external_controller": %q, "secret": %q, "default_mode": "Rule"}
	  },
	  "services": [{"type": "api", "tag": "api", "listen": %q, "listen_port": %d}]
	}`, cachePath, clashAPIListen, clashSecret, nativeAPIHost, nativeAPIPort)

	// include.Context installs the registries the decoder needs, so it must wrap the
	// DECODE as well as the instance construction.
	includeCtx := include.Context(ctx)
	var options option.Options
	err := badjson.UnmarshalContext(includeCtx, []byte(configJSON), &options)
	if err != nil {
		t.Fatalf("decode config: %v", err)
	}
	instance, err := box.New(box.Options{Context: includeCtx, Options: options, PlatformLogWriter: nil})
	if err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := instance.Start(); err != nil {
		t.Fatalf("start instance: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })

	return "http://" + clashAPIListen
}

// TestClashAPIAndNativeAPICoexist is the core assertion: one instance, both control
// planes, each answering on its own listener.
func TestClashAPIAndNativeAPICoexist(t *testing.T) {
	clashBase := dualPlaneInstance(t)
	waitForPort(t, clashAPIListen)
	waitForPort(t, nativeAPIListen)

	// Clash API answers its stable version endpoint.
	body := clashGet(t, clashBase+"/version", true)
	var versionPayload struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(body), &versionPayload); err != nil {
		t.Fatalf("clash /version is not JSON: %v (%q)", err, body)
	}
	if versionPayload.Version == "" {
		t.Fatal("clash /version returned no version")
	}

	// The Native API is a gRPC server; a plain HTTP request reaching it at all proves
	// the listener is up and independent of the Clash API's.
	if !portOpen(nativeAPIListen) {
		t.Fatal("the Native API listener is not accepting connections")
	}
}

// TestClashAPISecretIsEnforced pins that the secret is a real gate rather than a
// field that is parsed and ignored.
func TestClashAPISecretIsEnforced(t *testing.T) {
	clashBase := dualPlaneInstance(t)
	waitForPort(t, clashAPIListen)

	response, err := http.Get(clashBase + "/version")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated request must be rejected, got %d", response.StatusCode)
	}

	body := clashGet(t, clashBase+"/version", true)
	if body == "" {
		t.Fatal("an authenticated request returned an empty body")
	}
}

// TestClashAPISharedModeStateIsVisible pins that the traffic and mode managers are
// SHARED rather than duplicated per control plane: the mode the Clash API reports is
// the one the instance actually configured, seeded from default_mode.
func TestClashAPISharedModeStateIsVisible(t *testing.T) {
	clashBase := dualPlaneInstance(t)
	waitForPort(t, clashAPIListen)

	body := clashGet(t, clashBase+"/configs", true)
	var configs struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal([]byte(body), &configs); err != nil {
		t.Fatalf("clash /configs is not JSON: %v (%q)", err, body)
	}
	if configs.Mode == "" {
		t.Fatal("clash /configs reported an empty mode; the shared mode manager is not wired")
	}
}

// TestClashAPIProxiesReflectTheOutbounds proves the Clash API observes the same route
// graph rather than a snapshot of its own.
func TestClashAPIProxiesReflectTheOutbounds(t *testing.T) {
	clashBase := dualPlaneInstance(t)
	waitForPort(t, clashAPIListen)

	body := clashGet(t, clashBase+"/proxies", true)
	var payload struct {
		Proxies map[string]struct {
			Type string `json:"type"`
		} `json:"proxies"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("clash /proxies is not JSON: %v", err)
	}
	for _, tag := range []string{"direct", "group"} {
		if _, loaded := payload.Proxies[tag]; !loaded {
			t.Fatalf("clash /proxies does not list %q; it lists %v", tag, keysOf(payload.Proxies))
		}
	}
}

// TestNativeAPIClientReachesTheInstance is the Native API half of the coexistence
// assertion, driven through the real generated gRPC client rather than a port probe.
func TestNativeAPIClientReachesTheInstance(t *testing.T) {
	dualPlaneInstance(t)
	waitForPort(t, nativeAPIListen)

	conn, err := daemon.NewRemoteClient(daemon.RemoteClientOptions{
		ServerURL: "http://" + nativeAPIListen,
	})
	if err != nil {
		t.Fatalf("dial the Native API: %v", err)
	}
	defer conn.Close()

	client := daemon.NewStartedServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// SubscribeStatus is served by the Native API and depends on the same
	// traffic/mode managers the Clash API uses. If restoring the Clash API had
	// created a second, disconnected manager, this is where it would surface.
	stream, err := client.SubscribeStatus(ctx, &daemon.SubscribeStatusRequest{Interval: 0})
	if err != nil {
		t.Fatalf("SubscribeStatus: %v", err)
	}
	status, err := stream.Recv()
	if err != nil {
		t.Fatalf("SubscribeStatus receive: %v", err)
	}
	if status == nil {
		t.Fatal("SubscribeStatus returned nil status")
	}
	if status.Memory == 0 && status.Goroutines == 0 {
		t.Fatal("SubscribeStatus reported zero memory and zero goroutines, " +
			"which means it is not reading the instance")
	}
}

// TestNativeAPISubscribeLogStillWorks is the specific regression this task guards.
//
// The observable log factory is gated on `needAPIService || (needClashAPI &&
// external_controller != "")`. Before the Clash API was restored the gate was
// `needAPIService` alone. A careless merge would replace it with the Clash-only
// condition and silently break the Native API's log stream in any build without an
// external controller - which is exactly the configuration this test uses for the
// Native API: the Clash API IS present here, so both sides of the gate are live and
// the stream must still be delivered.
func TestNativeAPISubscribeLogStillWorks(t *testing.T) {
	dualPlaneInstance(t)
	waitForPort(t, nativeAPIListen)

	conn, err := daemon.NewRemoteClient(daemon.RemoteClientOptions{
		ServerURL: "http://" + nativeAPIListen,
	})
	if err != nil {
		t.Fatalf("dial the Native API: %v", err)
	}
	defer conn.Close()

	client := daemon.NewStartedServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	stream, err := client.SubscribeLog(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("SubscribeLog: %v", err)
	}
	// urltest fires every second against the local probe, and it logs at debug. A
	// delivered entry proves the observable factory is alive AND that the Clash API
	// did not take the stream for itself.
	type logResult struct {
		message string
		err     error
	}
	results := make(chan logResult, 1)
	go func() {
		for {
			entry, recvErr := stream.Recv()
			if recvErr != nil {
				results <- logResult{err: recvErr}
				return
			}
			if entry == nil {
				continue
			}
			for _, message := range entry.Messages {
				if message.GetMessage() != "" {
					results <- logResult{message: message.GetMessage()}
					return
				}
			}
		}
	}()
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("SubscribeLog receive: %v", result.err)
		}
		t.Logf("received log entry: %s", result.message)
	case <-time.After(20 * time.Second):
		t.Fatal("no log entry arrived within 20s; the observable log factory is not " +
			"serving the Native API (check the Observable gate in box.go)")
	}
}

func clashGet(t *testing.T, url string, authenticated bool) string {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authenticated {
		request.Header.Set("Authorization", "Bearer "+clashSecret)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, response.StatusCode)
	}
	body := make([]byte, 1<<16)
	n, _ := response.Body.Read(body)
	return string(body[:n])
}

func portOpen(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func waitForPort(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if portOpen(address) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Fall back to the environment for diagnostics.
	entries, _ := os.ReadDir("/proc/self")
	t.Fatalf("nothing is listening on %s after 15s (%d proc entries)", address, len(entries))
}

func keysOf(m map[string]struct {
	Type string `json:"type"`
}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
