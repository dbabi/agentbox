"""Idle loop for Snib: 4 frames x 500 ms (2 s loop), built from the final 32x32 in refine/r2/grid32.json.
f0 rest | f1 blink | f2 breathe out: lid, lock and glint 1px down (face, LEDs, feet stay planted) | f3 same, mint LED dark.
The blink sits at rest height and the dip keeps the eyes open, so the loop never reads as nodding off.
Each transition changes at most two things: blink / eyes open + dip / LED off / rise + LED on.
Run: python3 -I build.py, then render with tools/px.py: idle.json (default scale 16), idle-sheet.json --scale 8."""
import json
import os

M = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the mascot/ dir
OUT = f"{M}/anim"
base = json.load(open(f"{M}/refine/r2/grid32.json"))
PAL, A = base["palette"], base["rows"]


def edit(rows, *eds):
    r = [list(x) for x in rows]
    for x, y, new, old in eds:
        assert r[y][x] == old, (x, y, r[y][x], old)  # each edit must hit the pixel it means to
        r[y][x] = new
    return ["".join(x) for x in r]


def paint(rows, pts, c):
    r = [list(x) for x in rows]
    for x, y in pts: r[y][x] = c
    return ["".join(x) for x in r]


# blink: same as the r2 loop, the eyes close to a line on their lower row (y=23)
EYES = (*range(7, 11), *range(16, 20))
BOX = [(x, y) for x in EYES for y in range(20, 25)]
assert all(A[y][x] in "ohsf" for x, y in BOX)  # the eye boxes hold only eye and face pixels
blink = paint(paint(A, BOX, "f"), [(x, 23) for x in EYES], "o")

# breathe out: drop the plain front-face row 19, so everything above it moves down 1px; the LED column stays put
assert A[19][4:23] == "f" * 19 and A[18][25] == "s"
exhale = edit(["." * 32] + A[:19] + A[20:], (25, 19, "m", "s"))
exhale_dark = edit(exhale, (25, 19, "d", "m"))  # unlit = the deep shade of the unlit LED below it
frames = [A, blink, exhale, exhale_dark]

# self-check: clean frames, outlined silhouette, no new stray pixels, planted base, 4 distinct frames
N4 = ((1, 0), (-1, 0), (0, 1), (0, -1))
at = lambda f, x, y: f[y][x] if 0 <= x < 32 and 0 <= y < 32 else "."
edge = lambda f: {f[y][x] for y in range(32) for x in range(32) if f[y][x] != "." and any(at(f, x + a, y + b) == "." for a, b in N4)}
orphans = lambda f: sum(f[y][x] != "." and all(at(f, x + a, y + b) != f[y][x] for a, b in N4) for y in range(32) for x in range(32))
for f in frames:
    assert len(f) == 32 and all(len(r) == 32 and set(r) <= set(PAL) for r in f)
    assert edge(f) <= {"o", "d"} and orphans(f) <= orphans(A) and f[25:] == A[25:]
assert len({tuple(f) for f in frames}) == 4

json.dump({"palette": PAL, "frames": frames, "ms": 500}, open(f"{OUT}/idle.json", "w"), indent=1)
G = 2  # transparent gutter between frames on the contact sheet
json.dump({"palette": PAL, "rows": [("." * G).join(f[y] for f in frames) for y in range(32)]}, open(f"{OUT}/idle-sheet.json", "w"), indent=1)
print("ok")
