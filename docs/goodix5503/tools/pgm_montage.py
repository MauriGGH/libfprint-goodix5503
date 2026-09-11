#!/usr/bin/env python3
"""Put several 12-bit PGM frames (as written by the driver or by
goodix-fp-dump's tool.write_pgm) side by side in one PNG. Each frame is
normalised to its own range and scaled x3; the label shows the file name
and the mean raw value (no finger ~1150, finger ~220-490).

Note: frames are biometric data. Don't publish them.

Requires Pillow. Usage: pgm_montage.py OUT.png A.pgm [B.pgm ...]
"""
import os
import sys

from PIL import Image, ImageDraw

out_path, paths = sys.argv[1], sys.argv[2:]
scale, pad = 3, 8
tiles = []
for p in paths:
    tok = open(p).read().split()
    w, h = int(tok[1]), int(tok[2])
    px = [int(t) for t in tok[4:]]
    lo, hi = min(px), max(px)
    im = Image.new("L", (w, h))
    im.putdata([int(255 * (v - lo) / max(1, hi - lo)) for v in px])
    tiles.append((os.path.basename(p), im.resize((w * scale, h * scale), Image.NEAREST),
                  sum(px) // len(px)))

W = sum(t[1].width + pad for t in tiles) + pad
H = max(t[1].height for t in tiles) + 30
out = Image.new("L", (W, H), 255)
draw = ImageDraw.Draw(out)
x = pad
for name, im, mean in tiles:
    out.paste(im, (x, 25))
    draw.text((x, 5), f"{name} m={mean}", fill=0)
    x += im.width + pad
out.save(out_path)
