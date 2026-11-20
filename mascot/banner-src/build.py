"""README banner and GitHub social preview for agentbox. Stdlib only.
Run: python3 -I build.py

Each image is one pixel grid in the mascot's own palette, rendered with tools/px.py --scale 8:
  mascot/banner.png          160x40 grid -> 1280x320 (rounded corners are transparent)
  mascot/social-preview.png  160x80 grid -> 1280x640 (fully opaque: some sites draw transparency black)
Every art pixel is 8x8 screen pixels, including the mascot (the final refine/r2 32x32 grid at 1x),
so no element is drawn at a different pixel size. The wordmark and tagline letters are drawn here as pixels.
Also writes banner-src/banner.json, banner-src/social-preview.json and banner-src/preview.png (README light/dark mock)."""
import json, os, struct, subprocess, sys, zlib

M = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the mascot/ dir
SRC = f"{M}/banner-src"
SCALE = 8
g = json.load(open(f"{M}/refine/r2/grid32.json"))
PAL = g["palette"]
ART = [r[3:28] for r in g["rows"][1:31]]  # the mascot's 25x30 art box (the grid has a 1px empty margin)
assert all(set(r) - {"."} for r in (ART[0], ART[-1])) and any(r[0] != "." for r in ART) and any(r[-1] != "." for r in ART)

# wordmark font: x-height 11, 3px stems, 2px bars; (top row relative to the x-height top, rows)
WORD = {
    "a": (0, [".######.", "########", ".....###", ".....###", ".#######", "########", "###..###", "###..###", "###..###",
              "########", ".#######"]),
    "g": (0, [".#######", "########", "###..###", "###..###", "###..###", "###..###", "###..###", "###..###", "###..###",
              "########", ".#######", ".....###", ".....###", "#######.", "######.."]),
    "e": (0, [".######.", "########", "###..###", "###..###", "########", "########", "###.....", "###.....", "###.....",
              "########", ".#######"]),
    "n": (0, ["#######.", "########", "###..###", "###..###", "###..###", "###..###", "###..###", "###..###", "###..###",
              "###..###", "###..###"]),
    "t": (-3, [".###...", ".###...", ".###...", "#######", "#######", ".###...", ".###...", ".###...", ".###...", ".###...",
               ".###...", ".###...", ".######", "..#####"]),
    "b": (-5, ["###.....", "###.....", "###.....", "###.....", "###.....", "#######.", "########", "###..###", "###..###",
               "###..###", "###..###", "###..###", "###..###", "###..###", "########", "#######."]),
    "o": (0, [".######.", "########", "###..###", "###..###", "###..###", "###..###", "###..###", "###..###", "###..###",
              "########", ".######."]),
    "x": (0, ["##....##", "###..###", ".######.", "..####..", "...##...", "...##...", "...##...", "..####..", ".######.",
              "###..###", "##....##"]),
}
LETTER_GAP = 3  # body gap: outline, 1px of background, outline

# tagline font: 3x5 caps (M, N, W wider); a space is 1px, so words sit 3px apart
TINY = {
    "A": [".#.", "#.#", "###", "#.#", "#.#"], "C": [".##", "#..", "#..", "#..", ".##"], "D": ["##.", "#.#", "#.#", "#.#", "##."],
    "E": ["###", "#..", "##.", "#..", "###"], "F": ["###", "#..", "##.", "#..", "#.."], "G": [".##", "#..", "#.#", "#.#", ".##"],
    "H": ["#.#", "#.#", "###", "#.#", "#.#"], "I": ["###", ".#.", ".#.", ".#.", "###"], "M": ["#...#", "##.##", "#.#.#", "#...#", "#...#"],
    "N": ["#..#", "##.#", "#.##", "#..#", "#..#"], "O": [".#.", "#.#", "#.#", "#.#", ".#."], "R": ["##.", "#.#", "##.", "#.#", "#.#"],
    "S": [".##", "#..", ".#.", "..#", "##."], "T": ["###", ".#.", ".#.", ".#.", ".#."], " ": [".", ".", ".", ".", "."],
}
N4 = ((1, 0), (-1, 0), (0, 1), (0, -1))


def ring(pix):
    """4-neighbour outline: convex corners stay cut, as on the mascot"""
    return {(x + dx, y + dy) for x, y in pix for dx, dy in N4} - pix


def fill_holes(pix):
    xs, ys = [x for x, _ in pix], [y for _, y in pix]
    x0, x1, y0, y1 = min(xs) - 1, max(xs) + 1, min(ys) - 1, max(ys) + 1
    outside, todo = set(), [(x0, y0)]
    while todo:
        p = todo.pop()
        if p in outside or p in pix or not (x0 <= p[0] <= x1 and y0 <= p[1] <= y1): continue
        outside.add(p)
        todo += [(p[0] + dx, p[1] + dy) for dx, dy in N4]
    return {(x, y) for x in range(x0, x1 + 1) for y in range(y0, y1 + 1)} - outside


def wordmark(word):
    """purple letters like the mascot's body: fill f, lit top edges t, outline o, dark counters, drop shadow t at (1,1)"""
    letters, x = [], 0
    for ch in word:
        top, rows = WORD[ch]
        letters.append({(x + i, top + j) for j, r in enumerate(rows) for i, c in enumerate(r) if c == "#"})
        x += len(rows[0]) + LETTER_GAP
    body = set().union(*letters)
    solid = set().union(*map(fill_holes, letters))
    edge = ring(solid)
    out = {(x + 1, y + 1): "t" for x, y in solid | edge}  # light comes from the top-left
    out.update({p: "o" for p in edge | (solid - body)})
    out.update({(x, y): "t" if (x, y - 1) not in solid else "f" for x, y in body})
    return normalise(out)


def tiny(s):
    out, x = {}, 0
    for ch in s:
        rows = TINY[ch]
        out.update({(x + i, j): "#" for j, r in enumerate(rows) for i, c in enumerate(r) if c == "#"})
        x += len(rows[0]) + 1
    return out


def normalise(d):
    x0, y0 = min(x for x, _ in d), min(y for _, y in d)
    return {(x - x0, y - y0): c for (x, y), c in d.items()}


def size(d):
    return max(x for x, _ in d) + 1, max(y for _, y in d) + 1


def put(cv, d, ox, oy, colour=None):
    for (x, y), c in d.items():
        assert cv[oy + y][ox + x] in "ht", ("overlap", ox + x, oy + y)  # nothing lands on art or off the canvas
        cv[oy + y][ox + x] = colour or c


def mascot(cv, x, y):
    for i in range(x + 2, x + 22): cv[y + 30][i] = "t"  # ground shadow under the feet, nudged right (light from top-left)
    for j, r in enumerate(ART):
        for i, c in enumerate(r):
            if c != ".": cv[y + j][x + i] = c


WM = wordmark("agentbox")
WW, WH = size(WM)
GAP = 9  # mascot to wordmark


def banner():
    W, H = 160, 40
    tag = tiny("SAFE HOME FOR AI AGENTS")
    tw, th = size(tag)
    cv = [["h"] * W for _ in range(H)]
    x = (W - (25 + GAP + max(WW, tw))) // 2
    y = (H - 30) // 2
    mascot(cv, x, y)
    by = y + (30 - (WH + 4 + th)) // 2  # wordmark + tagline block centred on the mascot
    put(cv, WM, x + 25 + GAP, by)
    put(cv, tag, x + 25 + GAP, by + WH + 4, "s")
    for cx, cy in ((0, 0), (1, 0), (0, 1)):  # 2px rounded corners
        for X, Y in ((cx, cy), (W - 1 - cx, cy), (cx, H - 1 - cy), (W - 1 - cx, H - 1 - cy)): cv[Y][X] = "."
    return cv


def social():
    W, H = 160, 80
    tag = tiny("SAFE HOME FOR AI AGENTS")
    tw, th = size(tag)
    cv = [["h"] * W for _ in range(H)]
    lw = 25 + GAP + WW
    y = (H - (31 + 7 + th)) // 2
    x = (W - lw) // 2
    mascot(cv, x, y)
    put(cv, WM, x + 25 + GAP, y + (30 - WH) // 2 + 1)
    put(cv, tag, (W - tw) // 2, y + 38, "s")
    i = 5  # 1px frame with rounded corners, 40 screen px in: survives the ~30px side crop of 1.91:1 link cards
    for X in range(i + 2, W - i - 2): cv[i][X] = cv[H - 1 - i][X] = "t"
    for Y in range(i + 2, H - i - 2): cv[Y][i] = cv[Y][W - 1 - i] = "t"
    for X, Y in ((i + 1, i + 1), (W - 2 - i, i + 1), (i + 1, H - 2 - i), (W - 2 - i, H - 2 - i)): cv[Y][X] = "t"
    return cv


def read_png(path):  # px.py output only: 8-bit RGBA, filter 0 on every row
    d = open(path, "rb").read()
    w, h, depth, ctype = struct.unpack(">IIBB", d[16:26])
    assert (depth, ctype) == (8, 6), path
    idat, i = b"", 8
    while i < len(d):
        n = struct.unpack(">I", d[i:i + 4])[0]
        if d[i + 4:i + 8] == b"IDAT": idat += d[i + 8:i + 8 + n]
        i += 12 + n
    raw, st = zlib.decompress(idat), 4 * w + 1
    assert all(raw[y * st] == 0 for y in range(h))
    return w, h, lambda x, y: tuple(raw[y * st + 1 + 4 * x:y * st + 5 + 4 * x])


def rgba(v):
    return (0, 0, 0, 0) if v == "transparent" else tuple(int(v[i:i + 2], 16) for i in (1, 3, 5)) + (255,)


def render(name, cv, want, opaque):
    rows = ["".join(r) for r in cv]
    path = f"{SRC}/{name}.json"
    json.dump({"palette": PAL, "rows": rows}, open(path, "w"), indent=0)
    subprocess.run([sys.executable, "-I", f"{M}/tools/px.py", path, f"{M}/{name}", "--scale", str(SCALE)], check=True)
    os.remove(f"{M}/{name}.svg")  # only the PNG is a deliverable; the JSON re-renders the SVG if ever needed
    w, h, at = read_png(f"{M}/{name}.png")
    assert (w, h) == want, (name, w, h)
    for y in range(h):  # pixel-perfect: every screen pixel is exactly its grid cell's palette colour
        for x in range(w):
            assert at(x, y) == rgba(PAL[rows[y // SCALE][x // SCALE]]), (name, x, y)
    assert not opaque or "." not in "".join(rows), name
    return rows


def preview(banner_rows, social_rows):
    """README mock: banner at 5px per art pixel (about GitHub's README width) on white and on GitHub dark, social at 4px"""
    pal = {k: rgba(v) for k, v in PAL.items()}
    s1, s2, pad = 5, 4, 24
    bw, bh = 160 * s1, 40 * s1
    W = bw + 2 * pad
    H = 2 * (bh + 2 * pad) + 80 * s2 + 2 * pad
    px = []
    for y in range(H):
        page = (255, 255, 255) if y < bh + 2 * pad else (13, 17, 23)
        px.append([page] * W)
    def blit(rows, ox, oy, s):
        for y in range(len(rows) * s):
            for x in range(len(rows[0]) * s):
                c = pal[rows[y // s][x // s]]
                if c[3]: px[oy + y][ox + x] = c[:3]
    blit(banner_rows, pad, pad, s1)
    blit(banner_rows, pad, bh + 3 * pad, s1)
    blit(social_rows, pad, 2 * (bh + 2 * pad) + pad, s2)
    raw = b"".join(b"\x00" + bytes(c for p in r for c in p) for r in px)
    ck = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    png = b"\x89PNG\r\n\x1a\n" + ck(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0)) + ck(b"IDAT", zlib.compress(raw, 9)) + ck(b"IEND", b"")
    open(f"{SRC}/preview.png", "wb").write(png)


if __name__ == "__main__":
    b = render("banner", banner(), (1280, 320), opaque=False)
    s = render("social-preview", social(), (1280, 640), opaque=True)
    preview(b, s)
    print("ok: banner.png 1280x320, social-preview.png 1280x640, both pixel-exact")
