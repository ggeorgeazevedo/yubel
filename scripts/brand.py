#!/usr/bin/env python3
"""The Yubel palette — one source of truth for every generated asset.

Before this file the brand lived as literal hex strings inside six hand-edited
SVGs, a diagram generator and the HTML report, and they had already drifted
(the report's accent was a different purple from the logo's). Anything that
paints Yubel's identity imports from here, and `tests/test_brand.py` fails the
build if a committed asset stops matching.

Two rules the palette encodes, both worth stating because they are easy to
break by accident:

1. **Severity colours are not brand colours.** The report's severity scale
   (crimson = Critical, orange = High, gold-olive = Medium, blue = Low, grey =
   Info) is the most important signal in the document. Brand crimson and brand
   gold therefore appear in exactly one place inside a report — the emblem in
   the masthead — and never on links, chips, borders or panels, where a reader
   would have to work out whether a colour means "finding" or "decoration".
2. **The frame stays neutral.** `REPORT_ACCENT` is a graphite, and links carry
   an underline, so the link affordance never depends on hue at all.
"""
from __future__ import annotations

# --------------------------------------------------------------------------
# Ground
# --------------------------------------------------------------------------
BLACK = "#08080b"        #: page/emblem ground
BLACK_2 = "#12121a"      #: raised panel on black
BLACK_3 = "#1d1d28"      #: hairline border on black

# --------------------------------------------------------------------------
# Crimson — the alarm colour of the mark. Never used as report chrome.
# --------------------------------------------------------------------------
CRIMSON = "#a3121c"
CRIMSON_D = "#66070f"
CRIMSON_L = "#d92434"

# --------------------------------------------------------------------------
# Gold — the mark's highlight. Never used as report chrome either: the report's
# Medium severity is a gold-olive and the two would be read as the same thing.
# --------------------------------------------------------------------------
GOLD = "#c9a227"
GOLD_L = "#f0d279"
GOLD_D = "#8a6a1f"

# --------------------------------------------------------------------------
# Silver — the neutral that carries type on black.
# --------------------------------------------------------------------------
SILVER = "#dfe2e6"
SILVER_M = "#a8aeb6"
SILVER_D = "#6d747d"

# --------------------------------------------------------------------------
# Type on light ground
# --------------------------------------------------------------------------
INK = "#0f1013"
INK_SOFT = "#5c636c"

# --------------------------------------------------------------------------
# The report's neutral frame. Deliberately not gold and not crimson — see the
# module docstring. Kept here so `tests/test_brand.py` can assert the HTML
# reporter still uses these exact values.
# --------------------------------------------------------------------------
REPORT_ACCENT = "#343a42"        #: light mode: graphite, darker than Info grey
REPORT_ACCENT_DARK = "#c8ced6"   #: dark mode
REPORT_ACCENT_SOFT = "#f1f3f5"
REPORT_ACCENT_SOFT_DARK = "#1b1f24"

#: The only brand colours allowed inside a report, and only in the emblem.
EMBLEM_IN_REPORT = (GOLD, CRIMSON_L, SILVER)

#: Closest colour GitHub accepts for `branding.color` in action.yml. The
#: Marketplace only allows white, yellow, blue, green, orange, red, purple and
#: gray-dark, so the palette collapses to one word.
ACTION_COLOR = "red"

#: Display face for logo and docs. Cinzel by Natanael Gama, SIL Open Font
#: License 1.1 — https://github.com/NDISCOVER/Cinzel. The wordmark ships as
#: outlines in `brand_wordmarks.json`, so nothing at build or render time
#: depends on the font being installed.
DISPLAY_FONT = "Cinzel"
DISPLAY_FONT_LICENSE = "SIL Open Font License 1.1"
