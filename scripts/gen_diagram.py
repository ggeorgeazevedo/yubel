#!/usr/bin/env python3
"""Generate the Yubel "how it works" diagram as SVG + PNG.

Two things changed here beyond the palette, both because the old drawing was
wrong rather than merely off-brand:

* **Discovery is a phase, not a footnote.** `orchestrator.run()` runs katana
  and httpx first and feeds up to `crawl_max_urls` discovered URLs into the
  scanners. The old four-card flow started at "run engines", so the step that
  decides how much attack surface is even looked at was invisible in the one
  picture people actually read.
* **The title is set in outlines.** It used to be an SVG `<text>` in a system
  serif stack, so the committed PNG's typography depended on whichever fonts
  happened to be installed on the machine that last ran this script.

    python3 scripts/gen_diagram.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import brand as B                                                # noqa: E402
from gen_logo import sigil, wordmark, wordmark_width             # noqa: E402

W, H = 1200, 680

FS = 'font-family="-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif"'
MONO = 'font-family="ui-monospace,Menlo,Consolas,monospace"'

s = []
s.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
         f'role="img" aria-label="How Yubel works">')
s.append('<defs>')
s.append('<radialGradient id="bg" cx="28%" cy="18%" r="100%">'
         f'<stop offset="0%" stop-color="{B.BLACK_2}"/>'
         f'<stop offset="100%" stop-color="{B.BLACK}"/></radialGradient>')
s.append('</defs>')
s.append(f'<rect width="{W}" height="{H}" fill="url(#bg)"/>')
s.append(f'<rect width="{W}" height="5" fill="{B.CRIMSON}"/>')

# --- header ---
title_cap = 30.0
s.append(wordmark("HOW_IT_WORKS", 60, 76, title_cap, B.GOLD))
s.append(f'<rect x="60" y="88" '
         f'width="{wordmark_width("HOW_IT_WORKS", title_cap):.1f}" height="2" '
         f'fill="{B.CRIMSON}"/>')
s.append(f'<text x="62" y="116" {FS} font-size="18" fill="{B.SILVER_M}">'
         f'discover &#8594; orchestrate best-of-breed OSS engines &#8594; '
         f'correlate &#8594; decide</text>')
s.append(sigil(W - 92, 74, 62))

targets = "web  ·  REST / GraphQL APIs  ·  cloud  ·  containers  ·  Kubernetes"
s.append(f'<text x="{W - 140}" y="80" {FS} font-size="14" letter-spacing="1" '
         f'fill="{B.SILVER_D}" text-anchor="end">{targets}</text>')

# --- flow cards ---
top, bh = 158, 356
bw = 196
gap = 32
left = (W - (5 * bw + 4 * gap)) / 2
xs = [left + i * (bw + gap) for i in range(5)]


def card(x, accent, title, subtitle, items, hero=False):
    stroke = B.CRIMSON if hero else B.BLACK_3
    sw = 3 if hero else 1.5
    s.append(f'<rect x="{x}" y="{top}" width="{bw}" height="{bh}" rx="16" '
             f'fill="{B.BLACK_2}" stroke="{stroke}" stroke-width="{sw}"/>')
    if hero:
        s.append(f'<rect x="{x}" y="{top}" width="{bw}" height="34" rx="16" '
                 f'fill="{B.CRIMSON}"/>')
        s.append(f'<rect x="{x}" y="{top + 18}" width="{bw}" height="16" '
                 f'fill="{B.CRIMSON}"/>')
        s.append(f'<text x="{x + bw / 2}" y="{top + 23}" {FS} font-size="12" '
                 f'font-weight="700" letter-spacing="1.4" fill="{B.GOLD_L}" '
                 f'text-anchor="middle">THE DIFFERENTIATOR</text>')
    ty = top + (64 if hero else 46)
    s.append(f'<text x="{x + 20}" y="{ty}" {FS} font-size="21" '
             f'font-weight="700" fill="{accent}">{title}</text>')
    s.append(f'<text x="{x + 20}" y="{ty + 24}" {FS} font-size="13" '
             f'fill="{B.SILVER_D}">{subtitle}</text>')
    iy = ty + 58
    for label, sub in items:
        s.append(f'<circle cx="{x + 25}" cy="{iy - 5}" r="3.6" '
                 f'fill="{accent}"/>')
        s.append(f'<text x="{x + 38}" y="{iy}" {FS} font-size="14.5" '
                 f'font-weight="600" fill="{B.SILVER}">{label}</text>')
        if sub:
            s.append(f'<text x="{x + 38}" y="{iy + 18}" {FS} font-size="11.5" '
                     f'fill="{B.SILVER_M}">{sub}</text>')
            iy += 44
        else:
            iy += 29


card(xs[0], B.SILVER, "Discover", "map the surface first", [
    ("katana · httpx", "crawl, JS endpoints, known files"),
    ("Seeds the scanners", "up to crawl_max_urls (150)"),
    ("--no-crawl", "opt out; caps are logged"),
])
card(xs[1], B.GOLD, "Run engines", "13 OSS scanners", [
    ("ZAP · Nuclei · Nikto", "Wapiti · testssl.sh"),
    ("dalfox · sqlmap", "XSS + injection"),
    ("schemathesis", "API / OpenAPI fuzz"),
    ("kube-hunter · +more", "cloud / Kubernetes"),
])
card(xs[2], B.SILVER, "Normalize", "one shared model", [
    ("Dedupe", "merge duplicates"),
    ("Severity scale", "5 levels, unified"),
    ("Stable fingerprint", "track across runs"),
])
card(xs[3], B.CRIMSON_L, "Correlate", "what scanners can't do alone", [
    ("Consensus", "seen by 2+ engines"),
    ("Attack chains", "SSRF+IMDS &#8594; takeover"),
    ("Systemic", "same flaw on N targets"),
    ("Evidence trail", "deterministic, auditable"),
], hero=True)
card(xs[4], B.GOLD, "Decide", "actionable output", [
    ("Reports", "HTML · SARIF · MD · JSON"),
    ("Risk + grade", "0–100 score · A–F"),
    ("Taxonomy", "OWASP · CWE · MITRE"),
])

# arrows between cards
ay = top + bh / 2
for i in range(4):
    x1 = xs[i] + bw + 8
    x2 = xs[i + 1] - 8
    s.append(f'<line x1="{x1}" y1="{ay}" x2="{x2 - 6}" y2="{ay}" '
             f'stroke="{B.GOLD_D}" stroke-width="2.5"/>')
    s.append(f'<path d="M{x2 - 6} {ay - 6} L{x2 + 2} {ay} '
             f'L{x2 - 6} {ay + 6} Z" fill="{B.GOLD}"/>')

# --- bottom badge ---
by = top + bh + 40
bw2, bx = 760, (W - 760) / 2
s.append(f'<rect x="{bx}" y="{by}" width="{bw2}" height="52" rx="26" '
         f'fill="{B.BLACK}" stroke="{B.GOLD_D}" stroke-width="1.5"/>')
s.append(f'<text x="{W / 2}" y="{by + 33}" {FS} font-size="17" '
         f'font-weight="700" letter-spacing="0.5" fill="{B.GOLD}" '
         f'text-anchor="middle">No LLM &#183; No cloud &#183; deterministic '
         f'&#183; air-gapped ready</text>')

s.append(f'<text x="{W / 2}" y="{H - 20}" {MONO} font-size="14" '
         f'fill="{B.SILVER_D}" text-anchor="middle">'
         f'github.com/ggeorgeazevedo/yubel</text>')
s.append(f'<rect y="{H - 5}" width="{W}" height="5" fill="{B.GOLD}"/>')

s.append('</svg>')
svg = "".join(s)

OUT = ROOT / "docs" / "logo"


def main() -> int:
    path = OUT / "yubel-howitworks.svg"
    if "--check" in sys.argv:
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if current != svg:
            print("docs/logo/yubel-howitworks.svg is stale — "
                  "run scripts/gen_diagram.py")
            return 1
        print("diagram is up to date")
        return 0

    path.write_text(svg, encoding="utf-8")
    import cairosvg                                              # noqa: E402
    cairosvg.svg2png(bytestring=svg.encode(),
                     write_to=str(OUT / "yubel-howitworks.png"),
                     output_width=1200)
    print("wrote docs/logo/yubel-howitworks.svg + .png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
