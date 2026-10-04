#!/usr/bin/env python3
"""Exits 0 when the named workflow job declares `needs: libbox`.

Reads the workflow on stdin. The job graph is a real dependency, so it is read from parsed YAML
rather than matched textually: a job whose `steps:` list follows the key makes a line-range match
end in the wrong place, which is how the first version of this check passed while proving nothing.
"""
import sys

import yaml

job = sys.argv[1]
jobs = yaml.safe_load(sys.stdin)["jobs"]
sys.exit(0 if jobs.get(job, {}).get("needs") == "libbox" else 1)
