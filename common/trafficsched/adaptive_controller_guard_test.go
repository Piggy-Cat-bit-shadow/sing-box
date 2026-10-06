package trafficsched

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAdaptiveControllerIsNotInProduction is a guard on the PRODUCT, not on the research.
//
// It lives here, in an untagged file, rather than beside the controller it guards. The
// controller and its characterisation carry the `trafficresearch` build tag and are
// therefore absent from a release test run - but this assertion is about what the shipped
// binary may contain, so it has to keep running in exactly the runs the research does not.
//
// It needs none of the prototype's machinery: it reads files and asserts an identifier is
// absent from production sources and present in the research one.
func TestAdaptiveControllerIsNotInProduction(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	productionFiles := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		productionFiles++
		content, readErr := os.ReadFile(name)
		require.NoError(t, readErr)
		require.NotContains(t, string(content), "adaptiveRate",
			"%s is a production file and must not contain the adaptive controller: it is research, "+
				"and a wrong controller that is reachable from configuration is worse than none", name)
	}
	require.Positive(t, productionFiles, "the guard must be reading the package, not an empty directory")

	// Positive control: the identifier the guard looks for must exist somewhere, or a rename would
	// turn the loop above into a check that passes by finding nothing.
	research, readErr := os.ReadFile("adaptive_research_test.go")
	require.NoError(t, readErr)
	require.Contains(t, string(research), "adaptiveRate",
		"the guard must be looking for an identifier that exists")

	// The research file is tagged out of the release run, so the guard also pins that: if the tag
	// were dropped while the wall-clock comparison is still in there, the release gate it was
	// moved out of would silently come back.
	require.Contains(t, string(research), "//go:build trafficresearch",
		"the research file must stay behind the trafficresearch tag, or its wall-clock comparison "+
			"rejoins the release gate it was taken out of")

	// The seam the research uses is production, and that is deliberate: FixedRate and a future
	// learned rate must be able to share one scheduler. Only the controller is research.
	rateSource, readErr := os.ReadFile("scheduler.go")
	require.NoError(t, readErr)
	require.Contains(t, string(rateSource), "type RateSource interface",
		"the rate-source seam must stay in production code, or promoting a controller would mean "+
			"changing the scheduler rather than adding to it")
}
