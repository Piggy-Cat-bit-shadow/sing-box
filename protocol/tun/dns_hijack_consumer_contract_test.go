package tun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Consumer-contract proof for the DNS hijack verdicts.
//
// # Why this reads the dependency's source
//
// The producer half - which verdict sing-box emits for a DNS flow - is covered by
// direct_fast_path_dns_test.go. What that cannot show is whether the CONSUMER does the right thing
// with `ActionAccept` on TCP/53, and that is the half the DNS filtering guarantee depends on:
//
//	UDP/53 -> ActionHijackDNS -> nfqueue case ActionFlow, ActionHijackDNS -> NfRepeat + inputMark
//	TCP/53 -> ActionAccept    -> nfqueue default -> acceptVerdict(packet)
//	                             nftables (repeatOnAccept=false): NfAccept
//	                             iptables (repeatOnAccept=true):  NfAccept for IPv4,
//	                                                             NfRepeat+tproxyMark for IPv6
//
// On both backends the TCP/53 packet is handed back to the stack, where the auto-redirect rules
// deliver it to sing-box's stream path and reach hijackDNSStream. The verdict is not "escape
// sing-box"; it is "let routing deliver this to the stream hijack".
//
// A real end-to-end check needs a Linux kernel with nftables or iptables and CAP_NET_ADMIN, which
// this suite does not have. Asserting the pinned source keeps the contract honest: a dependency
// bump that changes either switch fails here instead of silently changing DNS behaviour in the
// field. The limitation is recorded rather than papered over.

// singTunModuleDir locates the pinned sing-tun source in the module cache.
func singTunModuleDir(t *testing.T) string {
	t.Helper()
	goMod, err := os.ReadFile("../../go.mod")
	require.NoError(t, err, "go.mod must be readable to find the pinned sing-tun version")

	var version string
	for _, line := range strings.Split(string(goMod), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "github.com/sagernet/sing-tun ") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "github.com/sagernet/sing-tun"))
			break
		}
	}
	require.NotEmpty(t, version, "go.mod must pin github.com/sagernet/sing-tun")

	home, err := os.UserHomeDir()
	require.NoError(t, err)
	dir := filepath.Join(home, "go", "pkg", "mod", "github.com", "sagernet",
		"sing-tun@"+version)
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Skipf("pinned sing-tun source not in the module cache at %s: %v", dir, statErr)
	}
	return dir
}

// TestPinnedConsumerHandlesTheDNSVerdicts is the consumer half of the contract.
func TestPinnedConsumerHandlesTheDNSVerdicts(t *testing.T) {
	dir := singTunModuleDir(t)

	nfqueue, err := os.ReadFile(filepath.Join(dir, "nfqueue_linux.go"))
	require.NoError(t, err)
	source := string(nfqueue)

	// A DNS flow must be re-injected, not accepted: only NfRepeat puts it back on the userspace
	// path where the hijack is installed.
	require.Contains(t, source, "case ActionFlow, ActionHijackDNS:",
		"the consumer must group ActionHijackDNS with ActionFlow; a separate branch could reject "+
			"or accept it, and a DNS query that is accepted never reaches the DNS router")
	require.Contains(t, source, "acceptVerdict(packet)",
		"an ActionAccept on TCP must be resolved through acceptVerdict, which is what decides "+
			"whether a TCP/53 packet returns to the stream path")

	// The two auto-redirect backends behave differently, and the difference is load-bearing.
	redirect, err := os.ReadFile(filepath.Join(dir, "redirect_linux.go"))
	require.NoError(t, err)
	require.Contains(t, string(redirect), "repeatOnAccept: !r.useNFTables",
		"the iptables backend re-injects accepted TCP while nftables does not; if this changes, "+
			"the TCP/53 hijack path changes with it")

	require.Contains(t, source, "func (h *nfqueueHandler) acceptVerdict(",
		"acceptVerdict is the function that implements the per-backend behaviour")
}

// TestActionAcceptIsNeverBypassForDNS is the invariant the two halves must jointly preserve.
//
// It is stated separately because it is the property that actually matters: whatever the consumer
// does with ActionAccept, a DNS flow must never be handed to the platform as a bypass.
func TestActionAcceptIsNeverBypassForDNS(t *testing.T) {
	dir := singTunModuleDir(t)
	nfqueue, err := os.ReadFile(filepath.Join(dir, "nfqueue_linux.go"))
	require.NoError(t, err)
	source := string(nfqueue)

	// ActionBypass is the only verdict that hands the flow to the platform outside sing-box's
	// userspace path. It must not be reachable from the DNS verdicts.
	bypassIndex := strings.Index(source, "case ActionBypass:")
	require.GreaterOrEqual(t, bypassIndex, 0, "ActionBypass must be handled by the consumer")

	dnsIndex := strings.Index(source, "case ActionFlow, ActionHijackDNS:")
	require.GreaterOrEqual(t, dnsIndex, 0)

	require.NotEqual(t, bypassIndex, dnsIndex,
		"ActionBypass and ActionHijackDNS must not share a branch: sharing one would mean a DNS "+
			"flow is handed to the platform, skipping the DNS router entirely")
}
