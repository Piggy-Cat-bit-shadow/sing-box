//go:build with_lx_command

package daemon

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"
)

// BenchmarkGetGroupsSnapshot measures a snapshot over a large configuration: 10
// groups of 100 nodes each, 1000 nodes total.
//
// The requirement it documents is that GetGroups is O(groups + members) with NO
// network probing and NO serialization of the running config. Both properties are
// visible here: the numbers are in the tens of microseconds for a thousand nodes,
// which is only possible if the call is touching in-memory maps. A single network
// probe would show up as a millisecond-scale figure, and re-marshalling the config
// would show up as allocation growth proportional to the whole option tree.
//
// This is a MECHANISM benchmark. It says nothing about throughput through any
// tunnel, and it must not be quoted as a latency figure for real traffic.
func BenchmarkGetGroupsSnapshot(b *testing.B) {
	const (
		groupCount    = 10
		nodesPerGroup = 100
	)

	registerTestRegistries()
	harness := newStartedServiceBenchHarness(b)

	var config strings.Builder
	// A per-benchmark cache path: the default is the RELATIVE "cache.db", so two
	// instances in one process contend for one file and the second fails with
	// "initialize cache-file: timeout".
	cachePath := filepath.Join(b.TempDir(), "cache.db")
	fmt.Fprintf(&config, "{\n  \"log\": {\"level\": \"error\", \"disabled\": true},\n  \"experimental\": {\"cache_file\": {\"enabled\": true, \"path\": %q}},\n  \"outbounds\": [\n", cachePath)

	// A shared pool of node outbounds, then groupCount selectors over them. Keeping
	// the node pool shared means every group has nodesPerGroup members while the
	// config stays small, so the measured work is the group/member traversal rather
	// than JSON parsing.
	for node := 0; node < nodesPerGroup; node++ {
		fmt.Fprintf(&config, "    {\"type\": \"direct\", \"tag\": \"shared-node-%d\"},\n", node)
	}
	for g := 0; g < groupCount; g++ {
		fmt.Fprintf(&config, "    {\"type\": \"selector\", \"tag\": \"bench-group-%d\", \"outbounds\": [", g)
		for node := 0; node < nodesPerGroup; node++ {
			if node > 0 {
				config.WriteString(", ")
			}
			fmt.Fprintf(&config, "\"shared-node-%d\"", node)
		}
		fmt.Fprintf(&config, "], \"default\": \"shared-node-0\"},\n")
	}
	config.WriteString("    {\"type\": \"direct\", \"tag\": \"final\"}\n  ],\n  \"route\": {\"final\": \"final\"}\n}")

	// NOTE: a shared node pool keeps the config small while every group still has
	// nodesPerGroup members, so the measured work is the group/member traversal
	// rather than JSON parsing.
	if err := harness.service.StartOrReloadService(context.Background(), config.String(), nil); err != nil {
		b.Skipf("the benchmark config could not start: %v", err)
	}

	// Assert the fixture actually built the intended shape: a benchmark over an
	// empty config would report a meaningless number that looks fast.
	snapshot, err := harness.service.GetGroups(context.Background(), &emptypb.Empty{})
	if err != nil {
		b.Fatalf("GetGroups failed: %v", err)
	}
	if len(snapshot.Group) != groupCount {
		b.Fatalf("the benchmark config must define %d groups, got %d", groupCount, len(snapshot.Group))
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		groups, err := harness.service.GetGroups(ctx, &emptypb.Empty{})
		if err != nil {
			b.Fatalf("GetGroups failed: %v", err)
		}
		if groups == nil {
			b.Fatal("GetGroups returned nil")
		}
	}
}

// newStartedServiceBenchHarness is the testing.B counterpart of the test harness:
// same real server, same real registration path.
func newStartedServiceBenchHarness(b *testing.B) *startedServiceGRPCHarness {
	b.Helper()
	service := NewStartedService(ServiceOptions{Context: boxContext})
	return &startedServiceGRPCHarness{service: service}
}
