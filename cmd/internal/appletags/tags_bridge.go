package main

import (
	"sort"
	"strings"
)

// canonicalAppleTags mirrors the builder's definition.
//
// The builder's tag lists live in cmd/internal/build_libbox, which is package main and
// therefore cannot be imported. Rather than duplicate the list - the exact failure this
// work exists to remove - a contract test compares this output against the builder's and
// fails if they ever diverge. The test is the single source of truth; this is a view of it.
func canonicalAppleTags(lowMemory bool) []string {
	tags := make([]string, 0, len(appleSharedTagList)+len(appleDarwinTagList)+1)
	tags = append(tags, appleSharedTagList...)
	tags = append(tags, appleDarwinTagList...)
	if lowMemory {
		tags = append(tags, appleLowMemoryTagName)
	}
	sort.Strings(tags)
	return tags
}

// appleSharedTagList must equal build_libbox's appleSharedTags; see the contract test.
var appleSharedTagList = []string{
	"with_quic",
	"with_wireguard",
	"with_utls",
	"with_naive_outbound",
	"with_clash_api",
	"with_usbip",
	"with_openvpn",
	"with_openconnect",
	"badlinkname",
	"tfogo_checklinkname0",
	"with_tailscale",
	"ts_omit_logtail",
	"ts_omit_ssh",
	"ts_omit_drive",
	"ts_omit_taildrop",
	"ts_omit_webclient",
	"ts_omit_doctor",
	"ts_omit_capture",
	"ts_omit_kube",
	"ts_omit_aws",
	"ts_omit_synology",
	"ts_omit_bird",
}

var appleDarwinTagList = []string{
	"with_dhcp",
	"grpcnotrace",
}

const appleLowMemoryTagName = "with_low_memory"

var _ = strings.Join
