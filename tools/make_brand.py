#!/usr/bin/env python3
"""Generate the Orthrus brand assets.

The banner's spectrum trace is not decoration. It is the real 863-930 MHz sweep
this device measured on real hardware, read out of the self-test log. The
coverage grid beside the wordmark is the product's own signature element, drawn
to the same rule it follows on screen: every channel/SF cell present, one lit.

A brand made of the product's own output is harder to fake and says more about
the tool than any illustration would.

Usage:  python3 tools/make_brand.py [path/to/selftest_log.txt]
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "brand"

# Palette, mirrored from src/app/theme.h.
INK = "#000000"
SURFACE = "#141311"
RULE = "#33302B"
TEXT = "#EDE9E0"
MUTED = "#8A857C"
FAINT = "#5A5650"
BRASS = "#B8893B"
SHINE = "#E8B44A"

# Measured on the device on 2026-09-16. Kept as a fallback so the brand can be
# regenerated without a board attached, but the real log wins when present.
FALLBACK = [
    (863, -113.0), (864, -107.2), (865, -115.1), (866, -114.6), (867, -114.8),
    (868, -114.0), (869, -113.2), (870, -110.9), (871, -112.4), (872, -113.1),
    (873, -110.2), (874, -114.8), (875, -109.9), (876, -113.4), (877, -112.8),
    (878, -113.9), (879, -112.1), (880, -113.6), (881, -112.9), (882, -113.2),
    (883, -111.8), (884, -113.5), (885, -112.6), (886, -113.0), (887, -110.9),
    (888, -107.9), (889, -112.2), (890, -113.4), (891, -112.7), (892, -113.8),
    (893, -112.5), (894, -114.1), (895, -113.3), (896, -116.9), (897, -113.7),
    (898, -112.4), (899, -113.1), (900, -112.8), (901, -113.5), (902, -111.9),
    (903, -112.6), (904, -113.2), (905, -112.0), (906, -113.8), (907, -112.3),
    (908, -113.6), (909, -111.7), (910, -112.9), (911, -113.4), (912, -106.6),
    (913, -112.1), (914, -113.0), (915, -112.5), (916, -113.7), (917, -112.2),
    (918, -113.3), (919, -111.6), (920, -112.8), (921, -113.1), (922, -112.4),
    (923, -109.6), (924, -109.4), (925, -112.7), (926, -113.2), (927, -111.5),
    (928, -103.6), (929, -112.0), (930, -113.4),
]


def load_sweep(log_path):
    """Pull (MHz, dBm) points out of a self-test log, if one is available."""
    if not log_path or not pathlib.Path(log_path).exists():
        return FALLBACK
    rows = []
    for line in pathlib.Path(log_path).read_text(errors="replace").splitlines():
        m = re.search(r"([\d.]+) MHz\s+(-[\d.]+) dBm", line)
        if m:
            rows.append((float(m.group(1)), float(m.group(2))))
    return rows if len(rows) > 20 else FALLBACK


def spectrum_path(points, x, y, w, h, floor=-125.0, ceiling=-100.0):
    """A filled area path for the trace, normalised into the given box."""
    n = len(points)
    span = ceiling - floor
    coords = []
    for i, (_, dbm) in enumerate(points):
        px = x + (w * i) / (n - 1)
        frac = max(0.0, min(1.0, (dbm - floor) / span))
        py = y + h - frac * h
        coords.append((px, py))

    d = [f"M {coords[0][0]:.1f} {y + h:.1f}"]
    for px, py in coords:
        d.append(f"L {px:.1f} {py:.1f}")
    d.append(f"L {coords[-1][0]:.1f} {y + h:.1f} Z")
    return " ".join(d), coords


def coverage_grid(x, y, cols=8, rows=6, lit=(2, 0), cell=9, gap=3):
    """The signature element: every cell drawn, exactly one lit."""
    out = []
    for c in range(cols):
        for r in range(rows):
            cx = x + c * (cell + gap)
            cy = y + r * (cell + gap)
            if (c, r) == lit:
                out.append(
                    f'<rect x="{cx}" y="{cy}" width="{cell}" height="{cell}" fill="{SHINE}"/>'
                )
            else:
                out.append(
                    f'<rect x="{cx}" y="{cy}" width="{cell}" height="{cell}" '
                    f'fill="none" stroke="{RULE}" stroke-width="1"/>'
                )
    return "\n    ".join(out)


def build_banner(points):
    W, H = 1280, 400
    area, coords = spectrum_path(points, 0, 250, W, 150)
    line = " ".join(
        f"{'M' if i == 0 else 'L'} {px:.1f} {py:.1f}" for i, (px, py) in enumerate(coords)
    )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="Orthrus - handheld LoRaWAN security assessment">
  <defs>
    <linearGradient id="trace" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="{BRASS}" stop-opacity="0.55"/>
      <stop offset="100%" stop-color="{BRASS}" stop-opacity="0.04"/>
    </linearGradient>
  </defs>

  <rect width="{W}" height="{H}" fill="{INK}"/>

  <!-- The real 863-930 MHz sweep this device measured. Not an illustration. -->
  <path d="{area}" fill="url(#trace)"/>
  <path d="{line}" fill="none" stroke="{SHINE}" stroke-width="1.6" stroke-linejoin="round"/>

  <text x="72" y="150" font-family="Georgia, 'Times New Roman', serif" font-size="94"
        font-weight="bold" fill="{TEXT}" letter-spacing="10">ORTHRUS</text>

  <rect x="76" y="176" width="300" height="2" fill="{SHINE}"/>

  <text x="76" y="212" font-family="ui-monospace, Menlo, Consolas, monospace"
        font-size="21" fill="{BRASS}">handheld LoRaWAN security assessment</text>
  <text x="76" y="242" font-family="ui-monospace, Menlo, Consolas, monospace"
        font-size="16" fill="{FAINT}">M5Stack Cardputer-Adv &#183; SX1262 &#183; authorized testing only</text>

  <!-- Coverage grid: 48 EU868 channel/SF cells, one lit. One radio hears 1 of 48. -->
  <g transform="translate(1000, 64)">
    {coverage_grid(0, 0)}
    <text x="0" y="98" font-family="ui-monospace, Menlo, Consolas, monospace"
          font-size="15" fill="{MUTED}">hearing 1 of 48</text>
  </g>
</svg>
"""


def build_mark():
    """Square mark: the grid alone, which is the thing nothing else has."""
    S = 512
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{S}" height="{S}" viewBox="0 0 {S} {S}" role="img" aria-label="Orthrus mark">
  <rect width="{S}" height="{S}" rx="96" fill="{INK}"/>
  <rect x="8" y="8" width="{S-16}" height="{S-16}" rx="88" fill="none" stroke="{RULE}" stroke-width="2"/>
  <g transform="translate(104, 150)">
    {coverage_grid(0, 0, cols=8, rows=6, lit=(2, 0), cell=26, gap=12)}
  </g>
  <text x="{S/2}" y="430" text-anchor="middle" font-family="Georgia, 'Times New Roman', serif"
        font-size="58" font-weight="bold" fill="{TEXT}" letter-spacing="4">ORTHRUS</text>
</svg>
"""


def main():
    log = sys.argv[1] if len(sys.argv) > 1 else None
    points = load_sweep(log)
    OUT.mkdir(parents=True, exist_ok=True)

    (OUT / "orthrus-banner.svg").write_text(build_banner(points))
    (OUT / "orthrus-mark.svg").write_text(build_mark())

    src = "self-test log" if log and pathlib.Path(log).exists() else "stored measurement"
    print(f"wrote docs/brand/orthrus-banner.svg  ({len(points)} sweep points from {src})")
    print("wrote docs/brand/orthrus-mark.svg")


if __name__ == "__main__":
    main()
