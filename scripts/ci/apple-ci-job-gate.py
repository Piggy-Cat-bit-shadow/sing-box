#!/usr/bin/env python3
"""Decide whether a GitHub Apple client run may be published from.

Reads the JSON that `gh run view --json jobs` produces on stdin and requires that the run actually
built all three platforms the publish pipeline ships:

    libbox   builds and packs the framework both clients link
    ios      archives and exports the iOS client
    macos    archives and exports the macOS client

# Why a run's conclusion is not enough

`client-apple.yml` takes `build_ios` and `build_macos` inputs, and each job carries the matching
`if:`. A dispatch with one of them false produces a run that concludes **success** while one platform
was never built at all - and skipped jobs are not failures, so the run-level conclusion cannot tell
the two apart. Publishing from such a run signs and uploads a client whose framework was verified for
the other platform only, and nothing in the pipeline reports it.

# Fail closed

Every way the run can fail to prove all three platforms is a failure here: a job missing entirely, a
job not completed, a job skipped, cancelled, timed out or failed. There is no partial acceptance and
no warning-only mode - the caller is about to upload to App Store Connect.

Output: one `<job>=<conclusion>` line per required job, in the order above, so the caller can put
them in its summary. Diagnostics go to stderr.
"""

from __future__ import annotations

import json
import sys

REQUIRED_JOBS = ("libbox", "ios", "macos")


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        print("apple-ci-job-gate: no run data on stdin", file=sys.stderr)
        return 2

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        print(f"apple-ci-job-gate: run data is not JSON: {error}", file=sys.stderr)
        return 2

    jobs = payload.get("jobs")
    if not isinstance(jobs, list) or not jobs:
        print("apple-ci-job-gate: the run reports no jobs at all", file=sys.stderr)
        return 1

    # Job display names can be prefixed by the matrix or the caller; the required name is matched as
    # a whole name or as the first word of a longer one, so "libbox (ios)" still counts as libbox.
    by_name: dict[str, dict] = {}
    for job in jobs:
        name = job.get("name") or ""
        for required in REQUIRED_JOBS:
            if name == required or name.startswith(f"{required} "):
                # The first match wins: a workflow that runs one job per platform names them
                # distinctly, and a duplicate name is a workflow problem this gate should not
                # resolve by picking the healthier of the two.
                by_name.setdefault(required, job)

    problems: list[str] = []
    results: list[str] = []
    for required in REQUIRED_JOBS:
        job = by_name.get(required)
        if job is None:
            problems.append(f"the run has no {required} job")
            continue
        status = job.get("status") or "unknown"
        conclusion = job.get("conclusion")
        if status != "completed":
            problems.append(f"the {required} job is {status}, not completed")
            continue
        if conclusion != "success":
            problems.append(f"the {required} job concluded {conclusion or 'nothing'}")
            continue
        results.append(f"{required}={conclusion}")

    if problems:
        print("apple-ci-job-gate: this run may not be published from.", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "  A run-level 'success' does not prove both clients were built: the workflow's "
            "build_ios and build_macos inputs skip a job without failing the run. Re-dispatch with "
            "both enabled and wait for all three jobs.",
            file=sys.stderr,
        )
        return 1

    print("\n".join(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
