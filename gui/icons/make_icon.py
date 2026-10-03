#!/usr/bin/env python3
# genereaza iconita aplicatiei (lacat alb pe fundal albastru) fara biblioteci externe:
# icon.png (256x256), 32x32.png, 128x128.png si icon.ico (cu PNG-ul inclus, format acceptat din Vista)
#   python3 gui/icons/make_icon.py

import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
BG = (29, 78, 216, 255)
FG = (255, 255, 255, 255)
CLEAR = (0, 0, 0, 0)


def pixel(x, y, s):
    # coordonate normalizate 0..1
    u, v = (x + 0.5) / s, (y + 0.5) / s
    # patrat cu colturi rotunjite
    r = 0.18
    cx = min(max(u, r), 1 - r)
    cy = min(max(v, r), 1 - r)
    if (u - cx) ** 2 + (v - cy) ** 2 > r * r:
        return CLEAR
    # corpul lacatului
    if 0.28 <= u <= 0.72 and 0.46 <= v <= 0.80:
        # gaura cheii
        if (u - 0.5) ** 2 + (v - 0.59) ** 2 < 0.045 ** 2 or (0.485 <= u <= 0.515 and 0.59 <= v <= 0.70):
            return BG
        return FG
    # toarta: inel intre raza 0.12 si 0.18, doar jumatatea de sus + bratele
    d = ((u - 0.5) ** 2 + (v - 0.40) ** 2) ** 0.5
    if v <= 0.40 and 0.115 <= d <= 0.175:
        return FG
    if 0.40 < v < 0.47 and (0.325 <= u <= 0.385 or 0.615 <= u <= 0.675):
        return FG
    return BG


def png(s):
    rows = b"".join(b"\x00" + b"".join(bytes(pixel(x, y, s)) for x in range(s)) for y in range(s))

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", s, s, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows, 9))
        + chunk(b"IEND", b"")
    )


def ico(png_data, s):
    # ICONDIR + o intrare ICONDIRENTRY care arata spre PNG (0 = 256 px)
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(png_data), 6 + 16)
    return header + entry + png_data


big = png(256)
for name, data in [
    ("icon.png", big),
    ("32x32.png", png(32)),
    ("128x128.png", png(128)),
    ("icon.ico", ico(big, 256)),
]:
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(data)
    print(name, len(data), "bytes")
