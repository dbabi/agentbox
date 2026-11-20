"""Icon set for the agentbox mascot (Snib), from the final r2 grids. Stdlib only.
Run: python3 -I build.py   (renders with tools/px.py, checks every PNG pixel-exactly, writes preview.png)

Outputs (icons/): favicon-16 (16 grid x1), favicon-32 (32 grid x1), icon-64/128/256 (32 grid x2/x4/x8),
avatar-460 (32 grid x12 on solid mint, centred on the art's bounding box; fits GitHub's circle crop).
Outputs (mascot/): agentbox-mascot.png (32 grid x16 = 512 px) and agentbox-mascot.svg."""
import json, math, os, struct, subprocess, sys, zlib

M = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the mascot/ dir
OUT = f"{M}/icons"
G16, G32 = f"{M}/refine/r2/grid16.json", f"{M}/refine/r2/grid32.json"
AV_N, AV_S, AV_BG = 460, 12, "m"  # avatar size, integer scale, palette key of the solid background


def px(grid, out, scale, keep_svg=False):
    subprocess.run([sys.executable, "-I", f"{M}/tools/px.py", grid, out, "--scale", str(scale)], check=True)
    if not keep_svg: os.remove(out + ".svg")  # px.py always writes an SVG; only the master needs one
    return out + ".png"


def read_png(path):  # reads px.py output only: 8-bit RGBA, filter 0 on every row
    d = open(path, "rb").read()
    w, h, depth, ctype = struct.unpack(">IIBB", d[16:26])
    assert (depth, ctype) == (8, 6), path
    idat, i = b"", 8
    while i < len(d):
        n = struct.unpack(">I", d[i:i + 4])[0]
        if d[i + 4:i + 8] == b"IDAT": idat += d[i + 8:i + 8 + n]
        i += 12 + n
    raw, st = zlib.decompress(idat), 4 * w + 1
    assert all(raw[y * st] == 0 for y in range(h)), path
    return w, h, [tuple(raw[y * st + 1 + 4 * x:y * st + 5 + 4 * x]) for y in range(h) for x in range(w)]


def rgba(v): return (0, 0, 0, 0) if v == "transparent" else tuple(int(v[i:i + 2], 16) for i in (1, 3, 5)) + (255,)


def check(path, grid, scale, ox=0, oy=0, size=None, bg=None):
    """Every output pixel must equal the grid cell it maps to (integer scale, integer offset), or the background."""
    pal, rows = grid["palette"], grid["rows"]
    w, h, p = read_png(path)
    size = size or len(rows[0]) * scale
    assert (w, h) == (size, size), (path, w, h)
    for y in range(h):
        for x in range(w):
            gx, gy = (x - ox) // scale, (y - oy) // scale
            inside = x >= ox and y >= oy and gx < len(rows[0]) and gy < len(rows)
            want = rgba(pal[rows[gy][gx]]) if inside else (0, 0, 0, 0)
            if bg and want[3] == 0: want = rgba(pal[bg])
            assert p[y * w + x] == want, (path, x, y, p[y * w + x], want)
    return w, h, p


g16, g32 = json.load(open(G16)), json.load(open(G32))
assert g16["palette"] == g32["palette"]
PAL, R32 = g32["palette"], g32["rows"]
made = {}
made["favicon-16"] = check(px(G16, f"{OUT}/favicon-16", 1), g16, 1)
made["favicon-32"] = check(px(G32, f"{OUT}/favicon-32", 1), g32, 1)
for s in (2, 4, 8):
    made[f"icon-{32 * s}"] = check(px(G32, f"{OUT}/icon-{32 * s}", s), g32, s)
check(px(G32, f"{M}/agentbox-mascot", 16, keep_svg=True), g32, 16)

# avatar: centre the art's bounding box (not the 32 canvas: the art sits 0.5px left in it), so the lock is on the centre line
art = [(x, y) for y, r in enumerate(R32) for x, c in enumerate(r) if PAL[c] != "transparent"]
bx0, bx1 = min(x for x, _ in art), max(x for x, _ in art)
by0, by1 = min(y for _, y in art), max(y for _, y in art)
ox = (AV_N - (bx1 - bx0 + 1) * AV_S) // 2 - bx0 * AV_S
oy = (AV_N - (by1 - by0 + 1) * AV_S) // 2 - by0 * AV_S
assert ox >= 0 and oy >= 0 and ox + 32 * AV_S <= AV_N and oy + 32 * AV_S <= AV_N
# shortcut: GitHub shows user avatars as circles; every art pixel corner must sit inside the inscribed circle
far = max(math.hypot(ox + (x + dx) * AV_S - AV_N / 2, oy + (y + dy) * AV_S - AV_N / 2) for x, y in art for dx in (0, 1) for dy in (0, 1))
assert far <= AV_N / 2 - 8, far
cells = [[AV_BG] * AV_N for _ in range(AV_N)]
for x, y in art:
    for dy in range(AV_S):
        cells[oy + y * AV_S + dy][ox + x * AV_S:ox + (x + 1) * AV_S] = R32[y][x] * AV_S
tmp = f"{OUT}/.avatar-460.json"
json.dump({"palette": PAL, "rows": ["".join(r) for r in cells]}, open(tmp, "w"))
made["avatar-460"] = check(px(tmp, f"{OUT}/avatar-460", 1), g32, AV_S, ox, oy, AV_N, AV_BG)
os.remove(tmp)
print(f"avatar: scale {AV_S}, offset ({ox},{oy}), farthest art corner {far:.1f}px from centre (circle r={AV_N // 2})")

# preview: each file at 1x on white, GitHub dark, light and dark browser tab bars; small ones also at 4x nearest
BGS = [(255, 255, 255), (13, 17, 23), (222, 225, 230), (53, 54, 58)]
items = [("favicon-16", 1), ("favicon-16", 4), ("favicon-32", 1), ("favicon-32", 4), ("icon-64", 1), ("icon-128", 1), ("icon-256", 1)]
W = sum(made[n][0] * s for n, s in items) + 8 * (len(items) + 1)
BH = 256 + 16
img = [bg for bg in BGS for _ in range(W * BH)]
for bi, bg in enumerate(BGS):
    x0 = 8
    for n, s in items:
        w, h, p = made[n]
        for y in range(h * s):
            for x in range(w * s):
                r, g, b, a = p[(y // s) * w + x // s]
                if a: img[(bi * BH + 8 + y) * W + x0 + x] = (r, g, b)
        x0 += w * s + 8
aw = made["avatar-460"][0]
q = 2  # avatar at half size (box filter, like a browser), square and circle crop
AW = 8 + 2 * (aw // q + 8)
av = [(255, 255, 255)] * (AW * (aw // q + 16))
_, _, ap = made["avatar-460"]
for y in range(aw // q):
    for x in range(aw // q):
        cs = [ap[(y * q + j) * aw + x * q + i] for j in range(q) for i in range(q)]
        c = tuple(sum(v[k] for v in cs) // len(cs) for k in range(3))
        av[(8 + y) * AW + 8 + x] = c
        if math.hypot(x + .5 - aw / q / 2, y + .5 - aw / q / 2) <= aw / q / 2:
            av[(8 + y) * AW + 16 + aw // q + x] = c


def write_rgb(path, w, h, p):
    raw = b"".join(b"\x00" + bytes(c for v in p[y * w:(y + 1) * w] for c in v) for y in range(h))
    ck = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    open(path, "wb").write(b"\x89PNG\r\n\x1a\n" + ck(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + ck(b"IDAT", zlib.compress(raw, 9)) + ck(b"IEND", b""))


write_rgb(f"{OUT}/preview-icons.png", W, BH * len(BGS), img)
write_rgb(f"{OUT}/preview-avatar.png", AW, aw // q + 16, av)
print("ok:", ", ".join(f"{n} {v[0]}px" for n, v in made.items()), "+ agentbox-mascot 512px")
