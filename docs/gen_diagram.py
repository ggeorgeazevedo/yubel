#!/usr/bin/env python3
"""Generates the Yubel 'how it works' diagram (brand-colored) as SVG + PNG."""
import cairosvg

W, H = 1200, 680
NAVY, NAVY2 = "#120e24", "#2a2050"
CARD = "#1c1533"
PURPLE, PURPLE_L = "#5b4aa6", "#8a72d8"
TEAL = "#2fb2a4"
ORANGE = "#d67a2f"
CREAM = "#f3efe6"
MUTE = "#b9b2cf"
MUTE2 = "#7d76a0"

FS = 'font-family="-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif"'
SERIF = 'font-family="Iowan Old Style, Palatino, Georgia, serif"'
MONO = 'font-family="ui-monospace,Menlo,Consolas,monospace"'

s = []
s.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" role="img" aria-label="How Yubel works">')
s.append('<defs>')
s.append('<radialGradient id="bg" cx="28%" cy="20%" r="100%">'
         f'<stop offset="0%" stop-color="{NAVY2}"/><stop offset="100%" stop-color="{NAVY}"/></radialGradient>')
s.append('</defs>')
s.append(f'<rect width="{W}" height="{H}" fill="url(#bg)"/>')

# --- header ---
s.append(f'<text x="60" y="72" {SERIF} font-size="42" font-weight="700" fill="{CREAM}">How Yubel works</text>')
s.append(f'<text x="62" y="104" {FS} font-size="19" fill="{MUTE}">orchestrate best-of-breed OSS engines &#8594; correlate &#8594; decide</text>')

# targets ribbon (top-right)
targets = "web  ·  REST / GraphQL APIs  ·  cloud  ·  containers  ·  Kubernetes"
s.append(f'<text x="{W-60}" y="72" {FS} font-size="15" letter-spacing="1" fill="{TEAL}" text-anchor="end">{targets}</text>')

# --- flow cards ---
top, bh = 150, 360
xs = [60, 355, 650, 945]
bw = 210

def card(x, accent, title, subtitle, items, hero=False):
    stroke = PURPLE_L if hero else "#332a52"
    sw = 3 if hero else 1.5
    s.append(f'<rect x="{x}" y="{top}" width="{bw}" height="{bh}" rx="16" fill="{CARD}" stroke="{stroke}" stroke-width="{sw}"/>')
    if hero:
        s.append(f'<rect x="{x}" y="{top}" width="{bw}" height="34" rx="16" fill="{PURPLE}"/>')
        s.append(f'<rect x="{x}" y="{top+18}" width="{bw}" height="16" fill="{PURPLE}"/>')
        s.append(f'<text x="{x+bw/2}" y="{top+23}" {FS} font-size="13" font-weight="700" letter-spacing="1.5" fill="{CREAM}" text-anchor="middle">THE DIFFERENTIATOR</text>')
    ty = top + (66 if hero else 46)
    s.append(f'<text x="{x+22}" y="{ty}" {FS} font-size="23" font-weight="700" fill="{accent}">{title}</text>')
    s.append(f'<text x="{x+22}" y="{ty+26}" {FS} font-size="14" fill="{MUTE2}">{subtitle}</text>')
    iy = ty + 62
    for label, sub in items:
        s.append(f'<circle cx="{x+27}" cy="{iy-5}" r="4" fill="{accent}"/>')
        s.append(f'<text x="{x+42}" y="{iy}" {FS} font-size="16" font-weight="600" fill="{CREAM}">{label}</text>')
        if sub:
            s.append(f'<text x="{x+42}" y="{iy+19}" {FS} font-size="12.5" fill="{MUTE}">{sub}</text>')
            iy += 46
        else:
            iy += 30

card(xs[0], TEAL, "Run engines", "13 OSS scanners", [
    ("ZAP · Nuclei · Nikto", "Wapiti · testssl.sh"),
    ("dalfox · sqlmap", "XSS + injection"),
    ("schemathesis", "API / OpenAPI fuzz"),
    ("kube-hunter · +more", "cloud / Kubernetes"),
])
card(xs[1], CREAM, "Normalize", "one shared model", [
    ("Dedupe", "merge duplicates"),
    ("Severity scale", "5 levels, unified"),
    ("Stable fingerprint", "track across runs"),
])
card(xs[2], PURPLE_L, "Correlation brain", "what scanners can't do alone", [
    ("Consensus", "seen by 2+ engines = corroborated"),
    ("Attack chains", "SSRF+IMDS → takeover"),
    ("Systemic correlation", "same flaw on N targets = 1 fix"),
    ("Evidence trail", "deterministic “why”, auditable"),
], hero=True)
card(xs[3], ORANGE, "Decide", "actionable output", [
    ("Reports", "HTML · SARIF · MD · JSON"),
    ("Risk + grade", "0–100 score · A–F"),
    ("Taxonomy", "OWASP · CWE · MITRE"),
])

# arrows between cards
ay = top + bh/2
for i in range(3):
    x1 = xs[i] + bw + 12
    x2 = xs[i+1] - 12
    s.append(f'<line x1="{x1}" y1="{ay}" x2="{x2-6}" y2="{ay}" stroke="{PURPLE_L}" stroke-width="2.5"/>')
    s.append(f'<path d="M{x2-6} {ay-6} L{x2+2} {ay} L{x2-6} {ay+6} Z" fill="{PURPLE_L}"/>')

# --- bottom badge ---
by = top + bh + 40
bw2, bx = 720, (W-720)/2
s.append(f'<rect x="{bx}" y="{by}" width="{bw2}" height="52" rx="26" fill="#0d1a16" stroke="{TEAL}" stroke-width="1.5"/>')
s.append(f'<text x="{W/2}" y="{by+33}" {FS} font-size="18" font-weight="700" letter-spacing="0.5" fill="{TEAL}" text-anchor="middle">No LLM &#183; No cloud &#183; zero outbound calls &#183; air-gapped ready</text>')

# footer url
s.append(f'<text x="{W/2}" y="{H-22}" {MONO} font-size="15" fill="{MUTE2}" text-anchor="middle">github.com/ggeorgeazevedo/yubel</text>')

s.append('</svg>')
svg = "".join(s)
with open("docs/logo/yubel-howitworks.svg", "w") as fh:
    fh.write(svg)
cairosvg.svg2png(bytestring=svg.encode(), write_to="docs/logo/yubel-howitworks.png", output_width=1200)
print("OK - diagrama gerado")
