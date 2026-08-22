#!/usr/bin/env python3
"""Generate the Yubel logo set from one palette and one wordmark.

The logo set used to be hand-edited SVGs, which is how the report's accent
ended up a different purple from the logo's, and how the wordmark ended up set
in `<text>` with a system font stack — meaning it rendered in a different
typeface on almost every machine that opened it.

Everything here comes from two files: `brand.py` for colour and
`brand_wordmarks.json` for the wordmark, which ships as outlines so no
renderer, and no CI job, needs a font installed.

    python3 scripts/gen_logo.py            # write docs/logo/*.svg + *.png
    python3 scripts/gen_logo.py --check    # exit 1 if any SVG is stale
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import brand as B                                                # noqa: E402

OUT = ROOT / "docs" / "logo"
WORDMARKS = json.loads(
    (Path(__file__).resolve().parent / "brand_wordmarks.json").read_text())


# --------------------------------------------------------------------------
# Wordmark
# --------------------------------------------------------------------------

def wordmark(key: str, x: float, baseline: float, cap_height: float,
             fill: str) -> str:
    """Place a Cinzel outline so its cap-height is exactly `cap_height` px.

    The stored path is in font units with the baseline at y=0 and the glyphs
    already y-flipped, so the only transform needed is a uniform scale.
    """
    data = WORDMARKS[key]
    scale = cap_height / data["cap"]
    return (f'<g transform="translate({x},{baseline}) scale({scale:.6f})">'
            f'<path d="{data["d"]}" fill="{fill}"/></g>')


def wordmark_width(key: str, cap_height: float) -> float:
    data = WORDMARKS[key]
    return data["advance"] * cap_height / data["cap"]


def matched_cap(key: str, target_width: float) -> float:
    """Cap height that makes `key` exactly `target_width` wide."""
    data = WORDMARKS[key]
    return target_width * data["cap"] / data["advance"]


# --------------------------------------------------------------------------
# Sigil
#
# A four-pointed star inside a ring: the vertical axis is longer than the
# horizontal, which is what stops it reading as a generic sparkle. It carries
# no face and no letterform, so it survives being shrunk to a 16px favicon,
# where any interior detail turns to mud.
# --------------------------------------------------------------------------

def sigil(cx: float, cy: float, size: float, ring: bool = True) -> str:
    """Draw the mark centred on (cx, cy), `size` px from tip to tip vertically."""
    v = size / 2.0                 # vertical reach
    h = v * 0.76                   # horizontal reach
    w = v * 0.13                   # waist — how deep the concave sides cut
    star = (f"M{cx} {cy - v} L{cx + w} {cy - w} L{cx + h} {cy} "
            f"L{cx + w} {cy + w} L{cx} {cy + v} L{cx - w} {cy + w} "
            f"L{cx - h} {cy} L{cx - w} {cy - w} Z")
    parts = []
    if ring:
        r = v * 0.62
        parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r:.2f}" fill="none" '
                     f'stroke="{B.CRIMSON}" stroke-width="{size * 0.022:.2f}"/>')
        r2 = v * 0.70
        parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r2:.2f}" fill="none" '
                     f'stroke="{B.CRIMSON_D}" stroke-width="{size * 0.012:.2f}"/>')
    parts.append(f'<path d="{star}" fill="{B.GOLD}"/>')
    # The left half sits a stop darker so the star reads as a faceted, struck
    # object rather than a flat silhouette.
    half = (f"M{cx} {cy - v} L{cx - w} {cy - w} L{cx - h} {cy} "
            f"L{cx - w} {cy + w} L{cx} {cy + v} Z")
    parts.append(f'<path d="{half}" fill="{B.GOLD_D}"/>')
    parts.append(f'<path d="M{cx} {cy - v * 0.30} L{cx + v * 0.11} {cy} '
                 f'L{cx} {cy + v * 0.30} L{cx - v * 0.11} {cy} Z" '
                 f'fill="{B.CRIMSON_L}"/>')
    return "".join(parts)


# --------------------------------------------------------------------------
# Assets
# --------------------------------------------------------------------------

def _svg(view: str, body: str, label: str, title: str = "") -> str:
    head = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}" '
            f'role="img" aria-label="{label}">')
    if title:
        head += f"<title>{title}</title>"
    return head + body + "</svg>"


def _lockup(ground: str, word_fill: str, tag_fill: str) -> str:
    """YUBEL over its tagline, on a 640x200 canvas.

    No mark in the lockup: the wordmark is the logo. The sigil exists for the
    places a wordmark cannot go — favicon, avatar, the social card.
    """
    cap = 88.0
    width = wordmark_width("YUBEL", cap)
    x = (640 - width) / 2
    baseline = 108.0
    tag_cap = matched_cap("TAGLINE", width)

    body = ""
    if ground:
        body += f'<rect width="640" height="200" fill="{ground}"/>'
    body += wordmark("YUBEL", x, baseline, cap, word_fill)
    body += (f'<rect x="{x:.1f}" y="{baseline + 18:.0f}" width="{width:.1f}" '
             f'height="3" fill="{B.CRIMSON}"/>')
    body += wordmark("TAGLINE", x, baseline + 56, tag_cap, tag_fill)
    return body


def assets() -> dict:
    out = {}

    out["yubel-logo.svg"] = _svg(
        "0 0 640 200", _lockup("", B.INK, B.INK_SOFT), "Yubel logo")

    out["yubel-logo-dark.svg"] = _svg(
        "0 0 640 200", _lockup(B.BLACK, B.GOLD, B.SILVER_M), "Yubel logo")

    # Standalone mark on its own ground, for avatars and READMEs.
    out["yubel-emblem.svg"] = _svg(
        "0 0 300 300",
        f'<rect width="300" height="300" rx="52" fill="{B.BLACK}"/>'
        f'<rect x="6" y="6" width="288" height="288" rx="46" fill="none" '
        f'stroke="{B.GOLD_D}" stroke-width="2"/>'
        + sigil(150, 150, 196),
        "Yubel", "Yubel")

    # Favicon scale: no ground, no ring — at 16px the ring closes up into a
    # smudge around the star.
    out["yubel-mark.svg"] = _svg(
        "0 0 128 128", sigil(64, 64, 116, ring=False), "Yubel", "Yubel")

    # Social card. og:image is read at 1200x630 and thumbnailed hard, so the
    # wordmark is set large and the tagline is the only secondary text.
    cap = 122.0
    word_w = wordmark_width("YUBEL", cap)
    tag_cap = matched_cap("TAGLINE", word_w)
    social = "".join([
        f'<rect width="1200" height="630" fill="{B.BLACK}"/>',
        f'<rect x="0" y="0" width="1200" height="6" fill="{B.CRIMSON}"/>',
        f'<rect x="0" y="624" width="1200" height="6" fill="{B.GOLD}"/>',
        sigil(600, 196, 236),
        wordmark("YUBEL", (1200 - word_w) / 2, 470, cap, B.GOLD),
        f'<rect x="{(1200 - word_w) / 2:.1f}" y="492" width="{word_w:.1f}" '
        f'height="4" fill="{B.CRIMSON}"/>',
        wordmark("TAGLINE", (1200 - word_w) / 2, 546, tag_cap, B.SILVER_M),
    ])
    out["yubel-social.svg"] = _svg("0 0 1200 630", social, "Yubel")

    return out


PNG_WIDTHS = {
    "yubel-logo.svg": 1280,
    "yubel-logo-dark.svg": 1280,
    "yubel-emblem.svg": 600,
    "yubel-social.svg": 1200,
}


def main() -> int:
    built = assets()
    check = "--check" in sys.argv

    stale = [name for name, svg in built.items()
             if not (OUT / name).exists()
             or (OUT / name).read_text(encoding="utf-8") != svg]

    if check:
        if stale:
            print("stale logo assets: " + ", ".join(sorted(stale)))
            print("run: python3 scripts/gen_logo.py")
            return 1
        print("logo set is up to date")
        return 0

    for name, svg in built.items():
        (OUT / name).write_text(svg, encoding="utf-8")

    import cairosvg                                              # noqa: E402
    for name, width in PNG_WIDTHS.items():
        cairosvg.svg2png(bytestring=built[name].encode(),
                         write_to=str(OUT / name.replace(".svg", ".png")),
                         output_width=width)
    print(f"wrote {len(built)} SVGs and {len(PNG_WIDTHS)} PNGs to "
          f"{OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
