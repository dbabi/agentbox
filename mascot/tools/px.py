#!/usr/bin/env python3
"""Render a pixel-art grid to PNG and SVG (stdlib only).

Input JSON: {"palette": {"<char>": "#RRGGBB" | "#RRGGBBAA" | "transparent"}, "rows": ["...", ...]}
            or {"palette": ..., "frames": [[rows...], ...], "ms": 400} for an animated SVG.
Usage: px.py grid.json out-basename [--scale N]   -> out.png (scaled), out.svg (crisp rects)
"""
import json, struct, sys, zlib

def color(v):
    if v == "transparent": return (0, 0, 0, 0)
    v = v.lstrip("#")
    r, g, b = int(v[0:2], 16), int(v[2:4], 16), int(v[4:6], 16)
    a = int(v[6:8], 16) if len(v) == 8 else 255
    return (r, g, b, a)

def check(pal, rows):
    w = len(rows[0])
    for i, r in enumerate(rows):
        if len(r) != w: sys.exit(f"row {i} has width {len(r)}, want {w}")
        for c in r:
            if c not in pal: sys.exit(f"row {i}: char {c!r} not in palette")
    return w, len(rows)

def png(path, pal, rows, scale):
    w, h = check(pal, rows)
    raw = bytearray()
    for r in rows:
        line = bytearray()
        for c in r: line += bytes(color(pal[c])) * scale
        for _ in range(scale): raw += b"\x00" + line
    def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    data = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w * scale, h * scale, 8, 6, 0, 0, 0))
    data += chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b"")
    open(path, "wb").write(data)

def rects(pal, rows):
    out = []
    for y, r in enumerate(rows):
        x = 0
        while x < len(r):
            c = r[x]; x0 = x
            while x < len(r) and r[x] == c: x += 1
            if pal[c] != "transparent":
                out.append(f'<rect x="{x0}" y="{y}" width="{x - x0}" height="1" fill="{pal[c]}"/>')
    return "".join(out)

def svg(path, pal, frames, ms):
    w, h = check(pal, frames[0])
    head = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" shape-rendering="crispEdges">'
    if len(frames) == 1:
        body = rects(pal, frames[0])
    else:
        n, dur = len(frames), ms * len(frames) / 1000
        body = ""
        for i, f in enumerate(frames):
            check(pal, f)
            vals = ";".join("visible" if j == i else "hidden" for j in range(n))
            body += f'<g visibility="{"visible" if i == 0 else "hidden"}"><animate attributeName="visibility" values="{vals}" dur="{dur}s" calcMode="discrete" repeatCount="indefinite"/>{rects(pal, f)}</g>'
    open(path, "w").write(head + body + "</svg>")

if __name__ == "__main__":
    if len(sys.argv) < 3: sys.exit(__doc__)
    spec = json.load(open(sys.argv[1]))
    scale = int(sys.argv[sys.argv.index("--scale") + 1]) if "--scale" in sys.argv else 16
    pal = spec["palette"]
    frames = spec.get("frames") or [spec["rows"]]
    png(sys.argv[2] + ".png", pal, frames[0], scale)
    for i, f in enumerate(frames[1:], 1): png(f"{sys.argv[2]}-f{i}.png", pal, f, scale)
    svg(sys.argv[2] + ".svg", pal, frames, spec.get("ms", 400))
