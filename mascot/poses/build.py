"""Poses of the final r2 mascot: happy (default), thinking, guarding, sleeping.
Each pose is the r2 grid32 plus stamped edits; the body never moves, so poses swap in place.
Run: python3 -I build.py, then render each <pose>.json with tools/px.py --scale 16."""
import json, sys
import os
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))  # sheet helpers; -I drops the script dir
from sheet import blit, write_png

M = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the mascot/ dir
OUT = f"{M}/poses"
base = json.load(open(f"{M}/refine/r2/grid32.json"))
PAL, BASE = base["palette"], base["rows"]
EYES = [(x, y) for y in range(20, 25) for x in (*range(7, 11), *range(16, 20))]
MOUTH = [(12, 24), (14, 24), (12, 25), (13, 25)]


def stamp(g, x0, y0, art):
    """Paint art onto grid g at x0,y0; '_' keeps the pixel underneath."""
    for dy, row in enumerate(art):
        for dx, c in enumerate(row):
            if c != "_":
                g[y0 + dy][x0 + dx] = c


def fill(g, cells, c):
    for x, y in cells: g[y][x] = c


def pose(*steps):
    g = [list(r) for r in BASE]
    for f, *a in steps: f(g, *a)
    return ["".join(r) for r in g]


EYE_L = ["ooo_", "ohoo", "oooo", "ooso", "_oo_"]
EYE_R = ["_ooo", "ohoo", "oooo", "ooso", "_oo_"]

happy = pose()

thinking = pose(
    (fill, EYES, "f"), (fill, MOUTH, "f"),
    (stamp, 8, 19, EYE_L), (stamp, 17, 19, EYE_R),   # eyes glance up-right, at the bubble
    (stamp, 14, 25, ["oo"]),                         # mouth: a small flat "hmm", pushed to the side
    (stamp, 20, 1, ["_ooooooooo_",                   # thought bubble, "..." inside; shade bottom-right (light is top-left)
                    "ohhhhhhhhho",
                    "ohohhohhoto",
                    "ohhhhhhhtto",
                    "_ooooooooo_"]),
    (stamp, 27, 7, ["_oo_", "ohho", "ohto", "_oo_"]),  # trail bubble, rising from the top-right corner
)

guarding = pose(
    (stamp, 9, 20, ["f"]), (stamp, 17, 20, ["f"]),  # brows down: each eye loses its inner top pixel, a braver tilt
    (stamp, 22, 16, ["ooooooooo",                   # gold shield like the lock: keyhole emblem, shade right and low
                     "ohhggggGo",
                     "ohgggggGo",
                     "oggooogGo",
                     "oggooogGo",
                     "ogggoggGo",
                     "ogggoggGo",
                     "ogggggGGo",
                     "_oggggGo_",
                     "__oggGo__",
                     "___oGo___",
                     "____o____"]),
)

sleeping = pose(
    (fill, EYES, "f"), (fill, MOUTH, "f"),
    (stamp, 7, 22, ["o__o", "_oo_"]), (stamp, 16, 22, ["o__o", "_oo_"]),  # closed lids
    (stamp, 13, 25, ["o"]),                                               # tiny breathing mouth
    (stamp, 25, 19, ["d"]),                                               # mint LED off: standby (gold stays on)
    (stamp, 20, 6, ["ssss", "__s_", "_s__", "ssss"]),                     # z then Z, rising away; mid purple reads on light and dark
    (stamp, 25, 1, ["sssss", "___s_", "__s__", "_s___", "sssss"]),
)

POSES = {"happy": happy, "thinking": thinking, "guarding": guarding, "sleeping": sleeping}
assert happy == BASE  # happy is the default mascot, pixel for pixel
for name, rows in POSES.items():
    assert len(rows) == 32 and all(len(r) == 32 for r in rows), name
    assert not any(c != "." for c in rows[0] + rows[-1] + "".join(r[0] + r[-1] for r in rows)), name  # 1px empty border kept
    json.dump({"palette": PAL, "rows": rows}, open(f"{OUT}/{name}.json", "w"), indent=1)

# review sheet: each pose at 1x/2x/4x on white and GitHub dark, plus solid silhouettes
P = {k: None if v == "transparent" else tuple(int(v[i:i + 2], 16) for i in (1, 3, 5)) for k, v in PAL.items()}
SIL = {k: None if v is None else (0, 0, 0) for k, v in P.items()}
cw, bh = 32 + 64 + 128 + 16, 136
W = len(POSES) * cw
px = [(255, 255, 255)] * (W * bh) + [(13, 17, 23)] * (W * bh) + [(255, 255, 255)] * (W * bh)
for bi, p in enumerate((P, P, SIL)):
    for i, rows in enumerate(POSES.values()):
        x = i * cw + 4
        for s in (1, 2, 4):
            blit(px, W, p, rows, x, bi * bh + 4, s); x += 32 * s + 4
write_png(f"{OUT}/review/sheet.png", W, 3 * bh, px)
print("ok")
