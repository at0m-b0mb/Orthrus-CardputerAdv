#!/usr/bin/env python3
"""Render the device screens from real engine output.

Every number, grade, finding and confidence in these images comes from
build/screens.json, which is produced by tools/screendump -- the same parser,
census and grader the firmware links. Nothing here invents a value. If a grade
in the README is wrong, the engine is wrong, and a host test will say so.

These are mockups of the panel, not photographs of it: the fonts are the
desktop nearest-neighbours of the on-device faces. The layout constants are
copied from the firmware so the composition is honest even though the glyphs
are not identical.

Usage:  python3 tools/render_mockups.py
"""

import json
import pathlib
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
OUT = ROOT / "docs" / "screens"

W, H = 240, 135
SCALE = 4

# --- tokens, mirrored from src/app/theme.h ----------------------------------
INK = (0x00, 0x00, 0x00)
SURFACE = (0x14, 0x13, 0x11)
RULE = (0x33, 0x30, 0x2B)
TEXT = (0xED, 0xE9, 0xE0)
MUTED = (0x8A, 0x85, 0x7C)
FAINT = (0x5A, 0x56, 0x50)
BRASS = (0xB8, 0x89, 0x3B)
SHINE = (0xE8, 0xB4, 0x4A)
CRITICAL = (0xD9, 0x48, 0x3B)
HIGH = (0xE0, 0x7A, 0x2F)
MEDIUM = (0xD9, 0xA9, 0x3B)
LOW = (0x7E, 0x8C, 0x6A)
INFO = (0x8A, 0x85, 0x7C)
GOOD = (0x6F, 0xA8, 0x6B)

SEVERITY = {
    "CRITICAL": CRITICAL, "HIGH": HIGH, "MEDIUM": MEDIUM,
    "LOW": LOW, "INFO": INFO,
}
GRADE = {
    "A+": GOOD, "A": GOOD, "B": LOW, "C": MEDIUM, "D": HIGH, "F": CRITICAL,
}

# --- layout, mirrored from the firmware -------------------------------------
HEADER_H = 16
FOOTER_H = 12
BODY_TOP = 21
CENSUS_ROW_H = 14
GRID_X, GRID_Y = 168, 26  # keep in step with kGridX in src/modules/airspace.cpp

FONT_DIRS = [
    "/System/Library/Fonts/Supplemental/",
    "/System/Library/Fonts/",
    "/usr/share/fonts/truetype/dejavu/",
]


def load(names, size):
    for name in names:
        for d in FONT_DIRS:
            p = pathlib.Path(d) / name
            if p.exists():
                try:
                    return ImageFont.truetype(str(p), size)
                except OSError:
                    continue
    return ImageFont.load_default()


# Identity face (FreeSerifBold9pt7b), UI face (FreeSans9pt7b), data face (Font0).
F_ID = load(["Georgia Bold.ttf", "Times New Roman Bold.ttf", "DejaVuSerif-Bold.ttf"], 13)
F_ID_BIG = load(["Georgia Bold.ttf", "Times New Roman Bold.ttf", "DejaVuSerif-Bold.ttf"], 20)
F_UI = load(["Helvetica.ttc", "Arial.ttf", "DejaVuSans.ttf"], 12)
F_DATA = load(["Menlo.ttc", "Monaco.ttf", "Courier New.ttf", "DejaVuSansMono.ttf"], 9)


def new_screen():
    img = Image.new("RGB", (W, H), INK)
    return img, ImageDraw.Draw(img)


def text(dr, xy, s, font, fill, anchor="la"):
    dr.text(xy, s, font=font, fill=fill, anchor=anchor)


def chrome(dr, title, right=None):
    text(dr, (6, HEADER_H // 2), title, F_ID, TEXT, anchor="lm")
    if right:
        text(dr, (W - 6, HEADER_H // 2), right, F_DATA, BRASS, anchor="rm")
    dr.line([(0, HEADER_H), (W, HEADER_H)], fill=BRASS)


def footer(dr, hint):
    top = H - FOOTER_H
    dr.line([(0, top), (W, top)], fill=RULE)
    text(dr, (6, top + FOOTER_H // 2), hint, F_DATA, FAINT, anchor="lm")


def coverage_grid(dr, x, y, cols, rows, lit_c, lit_s):
    cell, gap = 4, 1
    for c in range(cols):
        for s in range(rows):
            cx, cy = x + c * (cell + gap), y + s * (cell + gap)
            box = [cx, cy, cx + cell - 1, cy + cell - 1]
            if c == lit_c and s == lit_s:
                dr.rectangle(box, fill=SHINE)
            else:
                dr.rectangle(box, outline=RULE)


def render_live(d):
    img, dr = new_screen()
    live = d["live"]
    chrome(dr, "Airspace", f"{live['region']} {'HOP' if live['hopping'] else 'PARK'}")

    text(dr, (6, BODY_TOP + 5), f"{live['freqMHz']:.3f} MHz   SF{live['sf']}",
         F_DATA, SHINE, anchor="lm")

    rows = [
        ("devices", str(live["devices"]), TEXT),
        ("frames", str(live["frames"]), TEXT),
        ("crc fail", str(live["crcErrors"]), FAINT),
        ("other rf", str(live["otherRf"]), FAINT),
    ]
    for i, (label, value, colour) in enumerate(rows):
        y = BODY_TOP + 24 + i * 13
        text(dr, (6, y), label, F_DATA, MUTED, anchor="lm")
        text(dr, (96, y), value, F_DATA, colour, anchor="rm")

    text(dr, (6, BODY_TOP + 82), live["lastLine"], F_DATA, BRASS, anchor="lm")

    coverage_grid(dr, GRID_X, GRID_Y, live["channels"], live["sfs"],
                  live["litChannel"], live["litSf"])
    bottom = GRID_Y + live["sfs"] * 5
    text(dr, (GRID_X, bottom + 9), f"{live['coveragePercent']}% heard", F_DATA, TEXT, anchor="lm")
    text(dr, (GRID_X, bottom + 21), "of band", F_DATA, FAINT, anchor="lm")

    footer(dr, "enter census   h hop   s sf   ` back")
    return img


def render_census(d, selected=0):
    img, dr = new_screen()
    rows = d["census"]
    chrome(dr, "Census", f"{len(rows)} seen")

    for i, r in enumerate(rows[:6]):
        y = BODY_TOP + i * CENSUS_ROW_H
        mid = y + CENSUS_ROW_H // 2
        sel = i == selected
        if sel:
            dr.rectangle([0, y, W - 1, y + CENSUS_ROW_H - 1], fill=SURFACE)
            dr.rectangle([0, y, 1, y + CENSUS_ROW_H - 1], fill=SHINE)
        text(dr, (8, mid), r["label"], F_DATA, TEXT, anchor="lm")
        text(dr, (86, mid), f"{r['rssi']}dBm  {r['frames']}fr", F_DATA, MUTED, anchor="lm")
        text(dr, (W - 16, mid), r["grade"], F_DATA, GRADE.get(r["grade"], MUTED), anchor="rm")
        if r.get("provisional"):
            text(dr, (W - 6, mid), "*", F_DATA, FAINT, anchor="rm")

    footer(dr, "enter open  ; . move  c clear  ` back")
    return img


def render_dossier(d):
    img, dr = new_screen()
    dos = d["dossier"]
    chrome(dr, "Dossier", dos["label"])

    text(dr, (8, BODY_TOP + 12), dos["grade"], F_ID_BIG,
         GRADE.get(dos["grade"], MUTED), anchor="lm")
    text(dr, (46, BODY_TOP + 5), f"{dos['score']}/100  {dos['frames']} frames",
         F_DATA, MUTED, anchor="lm")
    if dos.get("provisional"):
        text(dr, (46, BODY_TOP + 16),
             f"provisional: {d['live']['coveragePercent']}% of band",
             F_DATA, FAINT, anchor="lm")

    y = BODY_TOP + 34
    for f in dos["findings"]:
        text(dr, (8, y), f["title"], F_DATA, SEVERITY.get(f["severity"], MUTED), anchor="lm")
        if f["severity"] != "INFO":
            text(dr, (W - 6, y), f"{f['confidence']}%", F_DATA, FAINT, anchor="rm")
        y += 12

    # Explanation of the most severe finding, in the space below the list.
    rule_y = H - FOOTER_H - 36
    dr.line([(6, rule_y), (W - 6, rule_y)], fill=RULE)
    detail = dos["findings"][0]["detail"] if dos["findings"] else ""
    wrap(dr, 8, rule_y + 4, W - 16, 10, 3, MUTED, detail)

    footer(dr, "; . device   ` back")
    return img


def wrap(dr, x, y, max_w, line_h, max_lines, colour, s):
    """Mirror of ui::wrapText: break on spaces, measure, never mid-word."""
    words, line, drawn = s.split(), "", 0
    for word in words:
        if drawn >= max_lines:
            return
        candidate = f"{line} {word}".strip()
        if dr.textlength(candidate, font=F_DATA) <= max_w or not line:
            line = candidate
        else:
            text(dr, (x, y + drawn * line_h), line, F_DATA, colour)
            drawn += 1
            line = word
    if line and drawn < max_lines:
        text(dr, (x, y + drawn * line_h), line, F_DATA, colour)


def main():
    src = BUILD / "screens.json"
    if not src.exists():
        sys.exit("run tools/screendump first: no build/screens.json")
    d = json.loads(src.read_text())

    OUT.mkdir(parents=True, exist_ok=True)
    for name, img in (
        ("airspace", render_live(d)),
        ("census", render_census(d)),
        ("dossier", render_dossier(d)),
    ):
        big = img.resize((W * SCALE, H * SCALE), Image.NEAREST)
        path = OUT / f"{name}.png"
        big.save(path)
        print(f"wrote {path.relative_to(ROOT)}  ({W*SCALE}x{H*SCALE})")


if __name__ == "__main__":
    main()
