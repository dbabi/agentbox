"""Judge-3 review aid: real-size contact sheet + pixel lint for concept grids (stdlib only)."""
import json, struct, sys, zlib
import os
from collections import Counter

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "concepts")  # design history, kept out of the repo
CS = ["c1", "c2", "c3", "c4", "c5"]

def load(path):
    g = json.load(open(path))
    pal = {k: (None if v == "transparent" else tuple(int(v.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))) for k, v in g["palette"].items()}
    return pal, g["rows"]

def write_png(path, w, h, px):
    raw = b"".join(b"\x00" + bytes(c for p in px[y * w:(y + 1) * w] for c in p) for y in range(h))
    ck = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    open(path, "wb").write(b"\x89PNG\r\n\x1a\n" + ck(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + ck(b"IDAT", zlib.compress(raw, 9)) + ck(b"IEND", b""))

def blit(px, W, pal, rows, x0, y0, s):
    for y, r in enumerate(rows):
        for x, c in enumerate(r):
            col = pal[c]
            if col is None: continue
            for dy in range(s):
                for dx in range(s):
                    px[(y0 + y * s + dy) * W + x0 + x * s + dx] = col

def sheet(out, bgs):
    cell, gap = 160, 4
    W, H = cell * len(CS), 72 * len(bgs)
    px = [(0, 0, 0)] * (W * H)
    for bi, bg in enumerate(bgs):
        for i in range(W * 72): px[bi * 72 * W + i] = bg
        for ci, c in enumerate(CS):
            p32, r32 = load(f"{BASE}/{c}/grid32.json"); p16, r16 = load(f"{BASE}/{c}/grid16.json")
            x, y = ci * cell + 2, bi * 72 + 4
            blit(px, W, p32, r32, x, y, 1); x += 32 + gap
            blit(px, W, p32, r32, x, y, 2); x += 64 + gap
            blit(px, W, p16, r16, x, y, 1); x += 16 + gap
            blit(px, W, p16, r16, x, y, 2)
    write_png(out, W, H, px)

def lint(c, which):
    pal, rows = load(f"{BASE}/{c}/{which}.json")
    h, w = len(rows), len(rows[0])
    at = lambda x, y: rows[y][x] if 0 <= x < w and 0 <= y < h else "."
    used = Counter(ch for r in rows for ch in r if pal[ch] is not None)
    # orphan = pixel with no 4-neighbour of the same colour (glints/LEDs are expected; outline orphans are the noise)
    orph = [(x, y, rows[y][x]) for y in range(h) for x in range(w) if pal[rows[y][x]] is not None
            and all(at(x + dx, y + dy) != rows[y][x] for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)))]
    # 4-connected solid islands (silhouette pieces)
    seen, islands = set(), []
    for y in range(h):
        for x in range(w):
            if pal[rows[y][x]] is None or (x, y) in seen: continue
            st, n = [(x, y)], 0; seen.add((x, y))
            while st:
                a, b = st.pop(); n += 1
                for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                    q = (a + dx, b + dy)
                    if q not in seen and pal[at(*q)] is not None: seen.add(q); st.append(q)
            islands.append(n)
    print(f"{c}/{which}: {w}x{h} colours={len(used)} islands={sorted(islands, reverse=True)} orphans={len(orph)}")
    print("   ", " ".join(f"{ch}@{x},{y}" for x, y, ch in orph))

if __name__ == "__main__":
    d = os.path.dirname(os.path.abspath(__file__))
    sheet(f"{d}/sheet-light-dark.png", [(255, 255, 255), (13, 17, 23)])
    sheet(f"{d}/sheet-laptop.png", [(201, 204, 209), (58, 61, 66)])
    for c in CS:
        for wh in ("grid32", "grid16"): lint(c, wh)
