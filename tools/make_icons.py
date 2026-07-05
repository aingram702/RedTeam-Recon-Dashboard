#!/usr/bin/env python3
"""Generate the extension's PNG icons with no third-party dependencies.

Draws a "recon target": a dark rounded tile with concentric red rings and a
crosshair. Pure stdlib (zlib + struct) PNG encoder so it runs anywhere.
"""
import math
import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(__file__), "..", "icons")

BG = (13, 17, 23, 255)        # near-black tile
RING = (255, 77, 77, 255)     # red-team red
RING_DIM = (140, 40, 40, 255)
CROSS = (230, 237, 243, 255)  # light crosshair


def blend(dst, src, a):
    return tuple(round(dst[i] * (1 - a) + src[i] * a) for i in range(3)) + (255,)


def make(size):
    px = [[(0, 0, 0, 0) for _ in range(size)] for _ in range(size)]
    c = (size - 1) / 2.0
    radius = size / 2.0
    corner = size * 0.22  # rounded-corner radius
    ring_w = max(1.0, size * 0.055)

    rings = [size * 0.42, size * 0.30, size * 0.18]
    for y in range(size):
        for x in range(size):
            dx, dy = x - c, y - c
            dist = math.hypot(dx, dy)

            # rounded-square tile mask (distance from corner regions)
            inside = True
            ex = abs(dx) - (radius - corner)
            ey = abs(dy) - (radius - corner)
            if ex > 0 and ey > 0:
                inside = math.hypot(ex, ey) <= corner
            elif abs(dx) > radius or abs(dy) > radius:
                inside = False
            if not inside:
                continue

            col = BG
            # concentric rings
            for r in rings:
                if abs(dist - r) <= ring_w:
                    edge = 1.0 - min(1.0, abs(dist - r) / ring_w)
                    col = blend(col, RING, 0.85 * edge + 0.15)
            # center dot
            if dist <= size * 0.07:
                col = blend(col, RING, 1.0)
            # crosshair arms
            arm = max(1.0, size * 0.035)
            if abs(dx) <= arm and abs(dy) <= size * 0.46:
                col = blend(col, CROSS, 0.9)
            if abs(dy) <= arm and abs(dx) <= size * 0.46:
                col = blend(col, CROSS, 0.9)

            px[y][x] = col
    return px


def write_png(path, px):
    size = len(px)
    raw = bytearray()
    for row in px:
        raw.append(0)  # no filter
        for (r, g, b, a) in row:
            raw += bytes((r, g, b, a))
    comp = zlib.compress(bytes(raw), 9)

    def chunk(tag, data):
        out = struct.pack(">I", len(data)) + tag + data
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return out + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", comp) + chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


def main():
    os.makedirs(OUT, exist_ok=True)
    for size in (16, 32, 48, 128):
        write_png(os.path.join(OUT, f"icon{size}.png"), make(size))
        print(f"wrote icon{size}.png")


if __name__ == "__main__":
    main()
