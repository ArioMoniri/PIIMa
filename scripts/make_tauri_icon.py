#!/usr/bin/env python3
"""Generate the desktop application icon.

WHY A GENERATOR AND NOT A COMMITTED BINARY: `bindings/tauri/icons/icon.png` is
the only binary file this repository would otherwise carry, and a binary nobody
can regenerate is a binary nobody can review. Running this script reproduces the
exact bytes, so the PNG in the tree is checkable rather than trusted.

It writes the PNG by hand -- zlib plus four chunks -- because Pillow is not a
dependency of this repository and acquiring one to draw a rectangle would be a
network operation on a project whose release gate is that it needs none.

The image is deliberately plain: a dark panel with three redaction bars, one of
which is deliberately left UNREDACTED. That is the product's honest state - the
name is still there - and an icon that showed everything blacked out would be
the first place this build overstates itself.

Usage:  python3 scripts/make_tauri_icon.py
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

SIZE = 512
BACKGROUND = (18, 22, 27, 255)
PANEL = (241, 244, 247, 255)
BAR = (24, 28, 33, 255)
LEFT_IN = (192, 57, 43, 255)  # the bar that is NOT redacted


def rounded(
    x: int, y: int, left: int, top: int, right: int, bottom: int, radius: int
) -> bool:
    """True when (x, y) is inside a rounded rectangle."""
    if not (left <= x < right and top <= y < bottom):
        return False
    for corner_x, corner_y in (
        (left + radius, top + radius),
        (right - radius, top + radius),
        (left + radius, bottom - radius),
        (right - radius, bottom - radius),
    ):
        inside_x = (
            (x < left + radius) if corner_x == left + radius else (x >= right - radius)
        )
        inside_y = (
            (y < top + radius) if corner_y == top + radius else (y >= bottom - radius)
        )
        if inside_x and inside_y:
            return (x - corner_x) ** 2 + (y - corner_y) ** 2 <= radius * radius
    return True


def pixel(x: int, y: int) -> tuple[int, int, int, int]:
    if not rounded(x, y, 0, 0, SIZE, SIZE, 96):
        return (0, 0, 0, 0)
    if not rounded(x, y, 88, 64, SIZE - 88, SIZE - 64, 24):
        return BACKGROUND
    # Three lines of "text". The third is the one nothing masks.
    for index, (top, width, colour) in enumerate(
        (
            (140, 260, BAR),
            (236, 200, BAR),
            (332, 240, LEFT_IN),
        )
    ):
        if top <= y < top + 44 and 128 <= x < 128 + width:
            del index
            return colour
    return PANEL


def chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def main() -> None:
    raw = bytearray()
    for y in range(SIZE):
        raw.append(0)  # filter type 0 for every scanline: no prediction
        for x in range(SIZE):
            raw.extend(pixel(x, y))
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )
    out = (
        Path(__file__).resolve().parent.parent
        / "bindings"
        / "tauri"
        / "icons"
        / "icon.png"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(png)
    print(f"wrote {out} ({len(png)} bytes)")


if __name__ == "__main__":
    main()
