#!/usr/bin/env python3
"""Summarise the finger-detection polls of a log captured with
GOODIX5503_FDT_DEBUG=1 (see README.md, "Pruebas sin fprintd").

For every wait it prints how many polls ran and the result. For finger-down
waits it shows the polls around the touch; for finger-up waits it counts how
often the "at baseline" streak was reset (oscillation) and shows the tail.

Usage: fdt_poll_analysis.py LOG
"""
import re
import sys

waits, cur = [], None
for line in open(sys.argv[1], errors="replace"):
    ts = re.search(r"(\d\d:\d\d:\d\d\.\d+)", line)
    if "Waiting for finger" in line:
        cur = {"kind": "down" if "down" in line else "up",
               "start": ts.group(1) if ts else "?", "polls": [], "end": None}
        waits.append(cur)
    m = re.search(r"FDT-POLL (down|up) t=\+\s*([\d.]+) zones=([\d ]+?) "
                  r"drop=\s*([-\d ]+?) consecutive=(\d+)", line)
    if m and cur:
        cur["polls"].append((float(m.group(2)),
                             [int(x) for x in m.group(4).split()],
                             int(m.group(5))))
    if "detected after" in line and cur:
        cur["end"] = line.split("detected after")[1].strip()
    if "retaking the no-finger reference" in line and cur:
        cur.setdefault("retakes", 0)
        cur["retakes"] = cur["retakes"] + 1

for i, w in enumerate(waits):
    p = w["polls"]
    print(f"\n#{i} wait {w['kind']:4} start {w['start']}  polls={len(p)}  "
          f"retakes={w.get('retakes', 0)}  result: {w['end']}")
    if not p:
        continue
    if w["kind"] == "down":
        for t, d, c in p[-6:]:
            print(f"   t=+{t:5.2f} maxdrop={max(d):4} drops={d} consec={c}")
        pre = [max(d) for t, d, c in p[:-6]]
        if pre:
            print(f"   before onset: {len(pre)} polls, maxdrop {min(pre)}..{max(pre)}")
    else:
        resets = sum(1 for a, b in zip(p, p[1:]) if a[2] > 0 and b[2] == 0)
        print(f"   streak resets (at baseline, then not): {resets}")
        for t, d, c in p[-8:]:
            print(f"   t=+{t:5.2f} maxabs={max(abs(x) for x in d):4} drops={d} consec={c}")
