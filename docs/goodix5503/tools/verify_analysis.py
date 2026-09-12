#!/usr/bin/env python3
"""Tabulate a labelled verify run produced by verify-loop.sh.

One row per attempt: the finger label typed before it (e = enrolled finger,
o = another finger, p = another person; older logs used m for the enrolled
finger), finger detection, frame mean, the SIGFM score of every enrolled
sample, the best score and the result.

The log must come from examples/verify, which enables debug output itself,
so that the per-sample "sigfm_score" lines are present.

Usage: verify_analysis.py LOG
"""
import re
import sys

atts, cur = [], None
for line in open(sys.argv[1], errors="replace"):
    # "=== attempt N finger=X"; older logs used "=== intento N dedo=X"
    m = re.match(r"=== (?:attempt|intento) (\d+) (?:finger|dedo)=(\S*)", line)
    if m:
        cur = {"n": int(m.group(1)), "who": m.group(2), "scores": [],
               "res": None, "extra": []}
        atts.append(cur)
        continue
    if cur is None:
        continue
    m = re.search(r"Finger down detected after ([\d.]+) s \(largest zone drop (\d+)\)", line)
    if m:
        cur["det"] = f"{m.group(1)}s/{m.group(2)}"
    m = re.search(r"Captured finger frame \d+: .* mean (\d+)", line)
    if m:
        cur["mean"] = int(m.group(1))
    m = re.search(r"verify: sample \d+ sigfm_score (-?\d+)", line)
    if m:
        cur["scores"].append(int(m.group(1)))
    if re.search(r"verify: sample \d+ invalid", line):
        cur["scores"].append("inv")
    m = re.search(r"Verify best SIGFM score: (-?\d+)", line)
    if m:
        cur["best"] = int(m.group(1))
    if "NO MATCH!" in line:
        cur["res"] = "NO MATCH"
    elif "MATCH!" in line:
        cur["res"] = "MATCH"
    if "Failed to verify" in line:
        cur["res"] = cur["res"] or "RETRY/FAIL"
        cur["extra"].append(line.split("**:")[-1].strip()[:100])

for a in atts:
    print(f"#{a['n']:2} finger={a['who']:2} det={a.get('det', '-'):10} "
          f"mean={a.get('mean', '-'):>4} best={a.get('best', '-'):>7} "
          f"res={a['res']}  samples={a['scores']}")
    for e in a["extra"]:
        print(f"      {e}")

for who in sorted({a["who"] for a in atts}):
    rows = [a for a in atts if a["who"] == who]
    matches = sum(1 for a in rows if a["res"] == "MATCH")
    print(f"finger={who}: {matches}/{len(rows)} MATCH")
