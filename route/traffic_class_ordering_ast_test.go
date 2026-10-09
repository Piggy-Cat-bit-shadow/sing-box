package route

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTrafficClassResolvedBeforeChainIsPublished guards the ORDERING contract at the publish sites.
//
// # Why this is a structural check and not a source-text one
//
// The property is about statement order inside a function that needs a full Router, a connection
// manager and trackers to execute, so it is checked against the parsed tree rather than by running it.
//
// The first version of this test read route.go as raw text and counted literal occurrences of
//
//	metadata.TrafficClass = resolveTrafficClass(chain, r.trafficClassPolicies)
//	metadata.OutboundChain = chain
//
// as one byte sequence. That made it a check on how the file was CHECKED OUT rather than on what the
// code does: with CRLF line endings in the working tree - the platform default on Windows, and what
// one Git configuration on this host produced - the byte pattern simply does not occur, the count came
// back 0 instead of 3, and the test reported "a publish site forgot to resolve the class" for code
// that resolves it at every site. MEASURED: that false red fired on this host while
// `git diff HEAD --numstat -- route/route.go` was empty, i.e. the file was byte-identical to the
// committed blob.
//
// The check below parses the file and looks at the ORDER OF STATEMENTS in the syntax tree, so
// whitespace, tabs, line endings and formatting are irrelevant to it. It proves exactly the same
// invariant, and it is mutation-checked below against deliberately reordered trees.
func TestTrafficClassResolvedBeforeChainIsPublished(t *testing.T) {
	source, err := os.ReadFile("route.go")
	require.NoError(t, err)

	sites, err := findPublishSiteOrdering(source)
	require.NoError(t, err, "route.go must parse as Go source")

	require.Len(t, sites, 3,
		"all three publish sites (TCP, UDP, PreMatch flow) must publish metadata.OutboundChain; found "+
			"%d, so either a site stopped publishing the chain or a fourth one appeared", len(sites))

	for index, site := range sites {
		require.True(t, site.chainAssigned,
			"publish site %d does not assign metadata.OutboundChain", index)
		require.True(t, site.classAssigned,
			"publish site %d (metadata.OutboundChain at line %d) never assigns "+
				"metadata.TrafficClass in the same block: that flow stays unclassified and the policy "+
				"silently does nothing there", index, site.chainLine)
		require.True(t, site.classBeforeChain,
			"publish site %d assigns metadata.TrafficClass at line %d but publishes "+
				"metadata.OutboundChain at line %d, so the chain becomes visible before the class is "+
				"final and every consumer of OutboundChain can observe an unclassified flow",
			index, site.classLine, site.chainLine)
		require.True(t, site.resolutionBeforeChain,
			"publish site %d publishes metadata.OutboundChain at line %d without calling "+
				"resolveTrafficClass before it", index, site.chainLine)
		require.True(t, site.resolutionBeforeTrackers,
			"publish site %d resolves the traffic class at line %d but the first tracker loop is at "+
				"line %d: the trackers record the metadata for the API and byte accounting, so they "+
				"must observe the final class", index, site.resolutionLine, site.firstTrackerLine)
	}
}

// publishSiteOrdering is what a publish site looks like in the tree: the positions that matter and the
// orderings the invariant is made of.
type publishSiteOrdering struct {
	chainLine                int
	classLine                int
	resolutionLine           int
	firstTrackerLine         int
	chainAssigned            bool
	classAssigned            bool
	classBeforeChain         bool
	resolutionBeforeChain    bool
	resolutionBeforeTrackers bool
}

// findPublishSiteOrdering parses source and reports the ordering facts for every block that assigns
// metadata.OutboundChain.
//
// It takes source bytes rather than reading the file so the mutation cases below can feed it
// deliberately reordered trees; nothing in the product calls it.
func findPublishSiteOrdering(source []byte) ([]publishSiteOrdering, error) {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "route.go", source, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var sites []publishSiteOrdering
	for _, declaration := range parsed.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Body == nil {
			continue
		}
		// Every block in the function, including nested ones: a publish site inside an `if` is still a
		// publish site.
		ast.Inspect(function.Body, func(node ast.Node) bool {
			block, isBlock := node.(*ast.BlockStmt)
			if !isBlock {
				return true
			}
			site, publishesChain := orderingInBlock(fileSet, block)
			if publishesChain {
				sites = append(sites, site)
			}
			return true
		})
	}
	return sites, nil
}

// orderingInBlock reports the ordering facts for one block, and whether that block publishes the
// chain at all.
func orderingInBlock(fileSet *token.FileSet, block *ast.BlockStmt) (publishSiteOrdering, bool) {
	var site publishSiteOrdering
	lineOf := func(node ast.Node) int {
		return fileSet.Position(node.Pos()).Line
	}
	// The tracker loop's position is recorded before the publish site is looked for, because in
	// production it follows the publish and the ordering claim spans both.
	for _, statement := range block.List {
		ast.Inspect(statement, func(node ast.Node) bool {
			rangeStatement, isRange := node.(*ast.RangeStmt)
			if !isRange || site.firstTrackerLine != 0 {
				return true
			}
			selector, isSelector := rangeStatement.X.(*ast.SelectorExpr)
			if isSelector && selector.Sel.Name == "trackers" {
				site.firstTrackerLine = lineOf(rangeStatement)
			}
			return true
		})
	}

	for index, statement := range block.List {
		assignment, isAssignment := statement.(*ast.AssignStmt)
		if !isAssignment || !assignsSelector(assignment, "OutboundChain") {
			continue
		}
		site.chainAssigned = true
		site.chainLine = lineOf(statement)

		// The class assignment and the resolution call may appear anywhere in this block BEFORE the
		// publish, so the preceding statements are searched rather than a fixed offset.
		for earlier := 0; earlier < index; earlier++ {
			previous := block.List[earlier]
			if previousAssignment, isPreviousAssignment := previous.(*ast.AssignStmt); isPreviousAssignment {
				if assignsSelector(previousAssignment, "TrafficClass") {
					site.classAssigned = true
					site.classLine = lineOf(previous)
				}
			}
			ast.Inspect(previous, func(node ast.Node) bool {
				call, isCall := node.(*ast.CallExpr)
				if !isCall {
					return true
				}
				if function, isIdent := call.Fun.(*ast.Ident); isIdent && function.Name == "resolveTrafficClass" {
					site.resolutionLine = lineOf(call)
				}
				return true
			})
		}

		site.classBeforeChain = site.classAssigned && site.classLine < site.chainLine
		site.resolutionBeforeChain = site.resolutionLine != 0 && site.resolutionLine < site.chainLine
		site.resolutionBeforeTrackers = site.resolutionLine != 0 &&
			(site.firstTrackerLine == 0 || site.resolutionLine < site.firstTrackerLine)
		return site, true
	}
	return site, false
}

// assignsSelector reports whether an assignment writes to a selector with the given field name, e.g.
// `metadata.OutboundChain = ...` or `metadata.TrafficClass = ...`.
func assignsSelector(assignment *ast.AssignStmt, field string) bool {
	for _, target := range assignment.Lhs {
		selector, isSelector := target.(*ast.SelectorExpr)
		if isSelector && selector.Sel.Name == field {
			return true
		}
	}
	return false
}

// The mutation cases below are the reason the structural check is worth having: they prove it still
// catches the regression it exists for. Each tree is a minimal function that publishes the chain, and
// the assertions run the SAME code path the production tree goes through.
func TestTrafficClassOrderingCheckCatchesReordering(t *testing.T) {
	const correct = `package route

func (r *Router) publish(metadata *adapter.InboundContext, chain []adapter.Outbound) {
	metadata.TrafficClass = resolveTrafficClass(chain, r.trafficClassPolicies)
	metadata.OutboundChain = chain
	for _, tracker := range r.trackers {
		tracker.Track(metadata)
	}
}
`
	const reordered = `package route

func (r *Router) publish(metadata *adapter.InboundContext, chain []adapter.Outbound) {
	metadata.OutboundChain = chain
	metadata.TrafficClass = resolveTrafficClass(chain, r.trafficClassPolicies)
	for _, tracker := range r.trackers {
		tracker.Track(metadata)
	}
}
`
	const missing = `package route

func (r *Router) publish(metadata *adapter.InboundContext, chain []adapter.Outbound) {
	metadata.OutboundChain = chain
	for _, tracker := range r.trackers {
		tracker.Track(metadata)
	}
}
`
	const noResolution = `package route

func (r *Router) publish(metadata *adapter.InboundContext, chain []adapter.Outbound) {
	metadata.TrafficClass = 0
	metadata.OutboundChain = chain
	for _, tracker := range r.trackers {
		tracker.Track(metadata)
	}
}
`
	const trackersFirst = `package route

func (r *Router) publish(metadata *adapter.InboundContext, chain []adapter.Outbound) {
	for _, tracker := range r.trackers {
		tracker.Track(metadata)
	}
	metadata.TrafficClass = resolveTrafficClass(chain, r.trafficClassPolicies)
	metadata.OutboundChain = chain
}
`

	for _, testCase := range []struct {
		name                 string
		source               string
		wantSites            int
		wantOrderingPass     bool
		wantResolutionBefore bool
	}{
		{name: "correct order passes", source: correct, wantSites: 1, wantOrderingPass: true, wantResolutionBefore: true},
		{name: "chain published first is caught", source: reordered, wantSites: 1, wantOrderingPass: false, wantResolutionBefore: false},
		{name: "class never assigned is caught", source: missing, wantSites: 1, wantOrderingPass: false, wantResolutionBefore: false},
		{name: "class assigned but not resolved is caught", source: noResolution, wantSites: 1, wantOrderingPass: true, wantResolutionBefore: false},
		{name: "trackers before the resolution are caught", source: trackersFirst, wantSites: 1, wantOrderingPass: true, wantResolutionBefore: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			sites, err := findPublishSiteOrdering([]byte(testCase.source))
			require.NoError(t, err)
			require.Len(t, sites, testCase.wantSites)
			site := sites[0]
			require.Equal(t, testCase.wantOrderingPass, site.classBeforeChain,
				"classBeforeChain for %q", testCase.name)
			require.Equal(t, testCase.wantResolutionBefore, site.resolutionBeforeChain,
				"resolutionBeforeChain for %q", testCase.name)
			// The tracker bound is asserted separately: it is the part of the invariant the
			// "trackers first" case exists for.
			if testCase.name == "trackers before the resolution are caught" {
				require.False(t, site.resolutionBeforeTrackers,
					"the check must notice a tree whose trackers run before the class is resolved")
			}
		})
	}
}

// TestTrafficClassOrderingCheckIgnoresLineEndings is the regression guard for the false red itself:
// the SAME source, checked out with LF and with CRLF, must produce the same verdict. The old
// source-text version did not, which is the whole reason this file was rewritten.
func TestTrafficClassOrderingCheckIgnoresLineEndings(t *testing.T) {
	source, err := os.ReadFile("route.go")
	require.NoError(t, err)
	withLF := []byte(string(source))
	withCRLF := []byte(strings.ReplaceAll(string(source), "\n", "\r\n"))

	lfSites, err := findPublishSiteOrdering(withLF)
	require.NoError(t, err)
	crlfSites, err := findPublishSiteOrdering(withCRLF)
	require.NoError(t, err)

	require.Len(t, lfSites, len(crlfSites),
		"the same source must produce the same number of publish sites regardless of line endings")
	for index := range lfSites {
		require.Equal(t, lfSites[index].classBeforeChain, crlfSites[index].classBeforeChain,
			"publish site %d must be judged identically with LF and with CRLF line endings", index)
		require.Equal(t, lfSites[index].resolutionBeforeChain, crlfSites[index].resolutionBeforeChain,
			"publish site %d must be judged identically with LF and with CRLF line endings", index)
		require.True(t, crlfSites[index].classBeforeChain,
			"publish site %d must still satisfy the invariant when the file has CRLF line endings: "+
				"a Windows checkout is not a code change", index)
	}
}
