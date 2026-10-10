# .advg - Adversary G's D2 differential harness

This directory holds the two files the D2 verdict (`truncatedRouteFailure` refuses no legal
configuration) was measured against. The `go` tool ignores dot-directories, so nothing here is part of
any package.

  * `before_dryrun.go`  - `common/physicalpath/dryrun.go` as of 686c937cbb13aafdfe6276c8813993dfcb51d9ac,
                          the commit before 8299f30ec added `truncatedRouteFailure`.
  * `overlay_before.json` - a `go build -overlay` mapping that runs the CURRENT tree with that one file
                          replaced by the text above. Its paths are absolute and machine-specific; the
                          command below regenerates it.

Reproduce the differential (both runs use the same assertions, so a line that changes verdict between
them is the whole result):

    cd C:\Deepseek\内核\wG
    $TAGS = (Get-Content release\DEFAULT_BUILD_TAGS_OTHERS -Raw).Trim()

    # post-change (the tree as it is)
    go test -tags "$TAGS" -run TestAdvGD2 -v ./common/physicalpath/

    # pre-change (same test binary, dryrun.go replaced by the 686c937 text)
    go test -tags "$TAGS" -overlay .advg/overlay_before.json -run TestAdvGD2 -v ./common/physicalpath/

Regenerate the two files if they are ever lost:

    cmd /c "git show 686c937cbb13aafdfe6276c8813993dfcb51d9ac:common/physicalpath/dryrun.go > .advg\before_dryrun.go"
    # then write overlay_before.json as:
    # {"Replace":{"<abs>/common/physicalpath/dryrun.go":"<abs>/.advg/before_dryrun.go"}}

Positive control for the overlay itself: with the overlay in place,
`-run TestValidateRootsRefusesARouteWhoseDeclaredDetourDoesNotExist` FAILS (the pre-change predicate
accepted the truncated route), and without it the same test PASSES.
