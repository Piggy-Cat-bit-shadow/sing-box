#!/usr/bin/env python3
"""Read-only missing-line report, whitespace-normalised.

For every upstream-only commit and every file it touches, print the '+' lines that are NOT
present in the fork tip's copy of that file.

Two normalisations make the answer trustworthy where the shell probe (line-presence.sh) is noisy:

  * every run of internal whitespace collapses to one space, so a gofmt column-aligned struct
    literal is not reported as missing merely because the fork aligned it differently;
  * the comparison is a set membership test against the whole file, so a line that merely moved
    is still reported present.

What the report still cannot see: a line that a LATER upstream commit deleted is reported
"missing" here even when the fork matches upstream's final state. `tip-parity.tsv` is the control
for that case - a path that is byte-identical at both tips is at parity whatever this says.

Usage: missing-lines.py > missing-lines.txt
"""
import re
import subprocess

BASE = "origin/testing"
UP = "upstream/testing"


def git(*args):
    return subprocess.run(("git",) + args, capture_output=True, text=True).stdout


def norm(line):
    return re.sub(r"\s+", " ", line).strip()


def main():
    shas = [l.split("\t")[0] for l in
            subprocess.run(["git", "rev-list", "--reverse", f"{BASE}..{UP}"],
                           capture_output=True, text=True).stdout.splitlines()]
    subjects = {}
    for l in subprocess.run(["git", "log", "--reverse", "--format=%H\t%s", f"{BASE}..{UP}"],
                            capture_output=True, text=True).stdout.splitlines():
        h, s = l.split("\t", 1)
        subjects[h] = s
    cache = {}
    for sha in shas:
        diff = git("show", "--format=", sha)
        cur_file = None
        added = {}
        for line in diff.splitlines():
            if line.startswith("diff --git "):
                cur_file = line.split(" b/", 1)[1] if " b/" in line else None
                added.setdefault(cur_file, [])
            elif line.startswith("+++") or line.startswith("---"):
                continue
            elif line.startswith("+") and cur_file:
                n = norm(line[1:])
                if n:
                    added[cur_file].append(n)
        for path, lines in added.items():
            if path not in cache:
                content = git("show", f"{BASE}:{path}")
                cache[path] = set(norm(l) for l in content.splitlines()) if content else set()
            have = cache[path]
            missing = [l for l in lines if l not in have]
            if not missing:
                continue
            print(f"### {sha[:12]}  {subjects[sha]}")
            print(f"    {path}: {len(missing)}/{len(lines)} added lines absent from the fork tip")
            for m in missing:
                print(f"      - {m[:160]}")


if __name__ == "__main__":
    main()
