"""Refine r2 of Snib (c3): r1 plus the r1-critic side-face fix (x=23 joins the shaded side face).
Writes grid32 + grid16, plus a die-cut ring and an idle loop of the 32.
Run: python3 -I build.py, then render each JSON with tools/px.py --scale 16.
Edits use pre-shift coordinates; the top-margin shift runs last (it moves rows 0-9 down by 1)."""
import json, shutil, sys
import os
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))  # sheet helpers; -I drops the script dir
from sheet import blit, write_png

M = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the mascot/ dir
OUT = f"{M}/refine/r2"
c32 = json.load(open(f"{M}/concepts/c3/grid32.json"))
PAL = c32["palette"]


def edit(rows, *eds):
    r = [list(x) for x in rows]
    for x, y, new, old in eds:
        assert r[y][x] == old, (x, y, r[y][x], old)  # each edit must hit the pixel the review describes
        r[y][x] = new
    return ["".join(x) for x in r]


A = edit(c32["rows"],
         (10, 20, "f", "o"), (16, 20, "f", "o"),  # cut the inner top eye corners: eyes tilt in, cheeky
         (9, 23, "s", "o"), (18, 23, "s", "o"),   # soft second catchlight, bottom-right of each eye
         (17, 5, "G", "g"), (17, 6, "G", "g"),    # lock: right column in shade, like the box
         (6, 29, "f", "s"), (17, 29, "f", "s"),   # feet: top-left highlight, one ramp step up
         # r2: the front-right edge faces away from the light, so x=23 joins the side face (4px deep, like the top);
         # gives a clean 45-degree top/side diagonal and centres the face on a front face of x=4..22
         (23, 15, "s", "h"), *[(23, y, "s", "t") for y in range(16, 27)])
A = ["." * 32] + A[:10] + A[11:]                  # 1px top margin: drop one stalk row, add a blank top row
assert len(A) == 32 and all(len(r) == 32 for r in A)
assert not any(c != "." for c in A[0] + A[-1] + "".join(r[0] + r[-1] for r in A))  # border empty, so the ring fits

# die-cut / dark-mode variant: 1px #f6f2ff ring on every empty pixel 8-touching the art
at = lambda x, y: A[y][x] if 0 <= x < 32 and 0 <= y < 32 else "."
ring = [list(r) for r in A]
for y in range(32):
    for x in range(32):
        if A[y][x] == "." and any(at(x + dx, y + dy) != "." for dx in (-1, 0, 1) for dy in (-1, 0, 1)):
            ring[y][x] = "W"
R = ["".join(r) for r in ring]

# idle loop: mint LED goes dark once, then a blink (eyes close to a line on their bottom row)
EYES = [*range(7, 11), *range(16, 20)]
assert all(A[y][x] in "ohsf" for y in (20, 21, 22, 23) for x in EYES)
blink = [list(r) for r in A]
for x in EYES:
    for y in (20, 21, 22): blink[y][x] = "f"
    blink[23][x] = "o"
blink = edit(["".join(r) for r in blink], (8, 24, "f", "o"), (9, 24, "f", "o"), (17, 24, "f", "o"), (18, 24, "f", "o"))
led_off = edit(A, (25, 19, "d", "m"))  # unlit LED = the same deep shade as the unlit LED below it

dump = lambda name, obj: json.dump(obj, open(f"{OUT}/{name}", "w"), indent=1)
dump("grid32.json", {"palette": PAL, "rows": A})
shutil.copyfile(f"{M}/concepts/c3/grid16.json", f"{OUT}/grid16.json")  # unchanged on purpose (j3: best 16 in the set)
dump("grid32-ring.json", {"palette": {**PAL, "W": "#f6f2ff"}, "rows": R})
dump("idle32.json", {"palette": PAL, "frames": [A, A, A, led_off, A, A, A, blink], "ms": 300})

# before/after sheet: r1 vs r2 vs r2-ring at 1x/2x/4x on white and GitHub dark, plus solid silhouettes
prev = json.load(open(f"{M}/refine/r1/grid32.json"))["rows"]
rgb = lambda p: {k: None if v == "transparent" else tuple(int(v[i:i + 2], 16) for i in (1, 3, 5)) for k, v in p.items()}
P, PR = rgb(PAL), rgb({**PAL, "W": "#f6f2ff"})
SIL = {k: None if v is None else (0, 0, 0) for k, v in P.items()}
cw, bh = 32 + 64 + 128 + 16, 136
W = 3 * cw
px = [(255, 255, 255)] * (W * bh) + [(13, 17, 23)] * (W * bh) + [(255, 255, 255)] * (W * bh)
for bi, items in enumerate(([(P, prev), (P, A), (PR, R)],) * 2 + ([(SIL, prev), (SIL, A)],)):
    for i, (p, rows) in enumerate(items):
        x = i * cw + 4
        for s in (1, 2, 4):
            blit(px, W, p, rows, x, bi * bh + 4, s); x += 32 * s + 4
write_png(f"{OUT}/compare32.png", W, 3 * bh, px)
print("ok")
