#!/usr/bin/env python3
"""Finger contact coverage of frames saved with GOODIX5503_DUMP_DIR.

For every clear-N.pgm / finger-N.pgm pair in DIR, prints the fraction of
the sensor where the finger frame is at least THRESHOLD darker than the
no-finger reference (1-pixel border excluded). Good enrollment samples
measured 93-99 %, partial ones (fingertip, half-covered) 43-83 %.

Note: frames are biometric data. Don't publish them.

Usage: coverage.py DIR [THRESHOLD]   (default threshold 300)
"""
import os
import re
import sys

W, H = 64, 80


def load(path):
    tok = open(path).read().split()
    return [int(t) for t in tok[4:]]


d = sys.argv[1]
thr = int(sys.argv[2]) if len(sys.argv) > 2 else 300
inner = [r * W + x for r in range(1, H - 1) for x in range(1, W - 1)]
seqs = sorted(int(m.group(1)) for f in os.listdir(d)
              if (m := re.fullmatch(r"finger-(\d+)\.pgm", f)))
for n in seqs:
    clear = os.path.join(d, f"clear-{n}.pgm")
    if not os.path.exists(clear):
        continue
    c, f = load(clear), load(os.path.join(d, f"finger-{n}.pgm"))
    cov = sum(1 for k in inner if c[k] - f[k] > thr) / len(inner)
    print(f"finger-{n}: coverage {cov * 100:5.1f}%  mean {sum(f) // len(f)}")
