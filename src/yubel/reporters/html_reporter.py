"""Self-contained HTML report — editorial, print-friendly, no external assets.

Deliberately styled like a professional security assessment report (masthead,
executive summary with a risk grade, an attack-path section, an OWASP coverage
matrix and structured findings) rather than a dashboard of emoji cards.
"""
from __future__ import annotations

import html
from datetime import datetime

from ..models import ScanResult
from ..analysis.taxonomy import target_risk, grade, owasp_coverage

_SEV = {
    "Critical": "#9d2235", "High": "#bf5a1a", "Medium": "#93790c",
    "Low": "#2c5282", "Info": "#5b6470",
}
_GRADE_COLOR = {"A": "#1f7a4d", "B": "#3d7a2f", "C": "#93790c",
                "D": "#bf5a1a", "F": "#9d2235"}


def _e(s) -> str:
    return html.escape(str(s if s is not None else ""))


def write_html(result: ScanResult, path: str) -> None:
    findings = result.findings
    risk = target_risk(findings)
    g = grade(risk)
    counts = result.counts()
    total = counts["Total"] or 1
    diff = result.diff_counts()
    chains = [f for f in findings if f.is_chain]
    coverage = owasp_coverage(findings)
    # local timezone of the machine running Yubel (Brazil, US, wherever)
    ts = datetime.fromtimestamp(result.finished_at or _now()).astimezone()\
        .strftime("%d %b %Y, %H:%M %Z")

    # severity distribution bar
    seg = "".join(
        f'<span class="seg" style="width:{counts[s]/total*100:.2f}%;'
        f'background:{_SEV[s]}" title="{s}: {counts[s]}"></span>'
        for s in ["Critical", "High", "Medium", "Low", "Info"] if counts[s]
    )
    sev_legend = " ".join(
        f'<span class="lg"><i style="background:{_SEV[s]}"></i>{s} '
        f'<b>{counts[s]}</b></span>'
        for s in ["Critical", "High", "Medium", "Low", "Info"]
    )

    diff_line = ""
    if result.baseline:
        diff_line = (
            f'<div class="diff">vs baseline&nbsp;·&nbsp;'
            f'<b class="new">{diff["new"]} new</b> · '
            f'<b class="reg">{diff["regressed"]} regressed</b> · '
            f'{diff["existing"]} existing · '
            f'<b class="fix">{diff["fixed"]} fixed</b></div>')

    systemic = [f for f in findings if f.is_systemic]
    corroborated = [f for f in findings if f.corroboration >= 2]
    chains_html = _chains_section(chains)
    systemic_html = _systemic_section(systemic)
    coverage_html = _coverage_section(coverage)
    runs_html = _runs_section(result)
    findings_html = _findings_section(
        [f for f in findings if not f.is_chain and not f.is_systemic])
    fixed_html = _fixed_section(result)

    lede = _executive_lede(g, risk, counts, len(chains), len(systemic),
                           len(corroborated), result)

    doc = _TEMPLATE.format(
        ts=ts, version=_e(result.version), total=counts["Total"],
        grade=g, grade_color=_GRADE_COLOR[g], risk=risk,
        seg=seg, sev_legend=sev_legend, diff_line=diff_line, lede=lede,
        chains=chains_html, systemic=systemic_html, coverage=coverage_html,
        runs=runs_html, findings=findings_html, fixed=fixed_html,
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def _executive_lede(g, risk, counts, n_chains, n_systemic, n_corr, result) -> str:
    posture = {"A": "a strong", "B": "a reasonable", "C": "a mixed",
               "D": "a weak", "F": "a critical"}[g]
    parts = [f"This assessment covers {len(result.targets())} target(s) and "
             f"{len(result.runs)} engine run(s), yielding {counts['Total']} "
             f"distinct findings. The overall posture is <b>{posture}</b> "
             f"(grade {g}, risk {risk}/100)."]
    if counts["Critical"] or counts["High"]:
        parts.append(f"{counts['Critical']} critical and {counts['High']} "
                     f"high-severity issues require prompt attention.")
    corr_bits = []
    if n_corr:
        corr_bits.append(f"<b>{n_corr} corroborated</b> by ≥2 independent engines")
    if n_chains:
        corr_bits.append(f"<b>{n_chains} attack chain(s)</b> synthesized")
    if n_systemic:
        corr_bits.append(f"<b>{n_systemic} systemic</b> across targets")
    if corr_bits:
        parts.append("Yubel's correlation engine flagged " +
                     ", ".join(corr_bits) +
                     " — signal no single scanner produces in isolation.")
    if result.findings:
        confirmed = sum(1 for f in result.findings if f.verified)
        review = len(result.findings) - confirmed
        parts.append(f"<b>{confirmed} confirmed</b> with reproducible evidence "
                     f"(corroboration, chain, or a payload with observable proof); "
                     f"<b>{review}</b> flagged for review.")
    return " ".join(parts)


def _systemic_section(systemic) -> str:
    if not systemic:
        return ""
    cards = []
    for c in systemic:
        cards.append(f"""
        <article class="chain" style="--sev:{_SEV[c.severity.label]}">
          <div class="chain-hd">
            <span class="tag" style="background:{_SEV[c.severity.label]}">{c.severity.label}</span>
            <h3>{_e(c.title)}</h3>
          </div>
          <p>{_e(c.description)}</p>
          <div class="chain-steps"><span>targets</span><ol>{"".join(f"<li>{_e(t)}</li>" for t in c.affected_targets)}</ol></div>
        </article>""")
    return (f'<section><h2>Systemic issues <small>{len(systemic)} across targets</small></h2>'
            f'<p class="section-note">The same weakness class found on multiple '
            f'targets — fix once, centrally, to resolve everywhere.</p>'
            + "".join(cards) + "</section>")


def _chains_section(chains) -> str:
    if not chains:
        return ""
    cards = []
    for c in chains:
        steps = "".join(
            f'<li>{_e(s)}</li>' for s in c.chain_steps
        )
        cards.append(f"""
        <article class="chain" style="--sev:{_SEV[c.severity.label]}">
          <div class="chain-hd">
            <span class="tag" style="background:{_SEV[c.severity.label]}">{c.severity.label}</span>
            <h3>{_e(c.title)}</h3>
          </div>
          <p>{_e(c.description)}</p>
          <div class="chain-steps"><span>chain</span><ol>{steps}</ol></div>
          {f'<p class="fix"><b>Remediation.</b> {_e(c.remediation)}</p>' if c.remediation else ''}
        </article>""")
    return (f'<section><h2>Attack paths <small>{len(chains)} synthesized</small></h2>'
            f'<p class="section-note">Composite findings Yubel derived by '
            f'correlating multiple engines against the same target.</p>'
            + "".join(cards) + "</section>")


def _coverage_section(coverage) -> str:
    cells = []
    for cat, n in coverage.items():
        code = cat.split()[0]                     # A01:2021
        short = " ".join(cat.split()[1:])
        active = "on" if n else "off"
        cells.append(
            f'<div class="cov {active}"><span class="code">{_e(code)}</span>'
            f'<span class="ct">{n}</span><span class="nm">{_e(short)}</span></div>')
    return (f'<section><h2>OWASP Top 10 coverage</h2>'
            f'<div class="cov-grid">{"".join(cells)}</div></section>')


def _runs_section(result) -> str:
    """The `Why` column is the point of this table.

    A row reading "skipped" and nothing else looks like housekeeping. The
    reason is what tells a reader that an engine was left out of *this* scan:
    the binary was missing, or `--offline` could not be honoured and the
    engine was dropped rather than run under a promise nobody checked. The
    text was already on the run record and only `yubel.json` ever showed it.
    """
    rows = "".join(
        f"<tr><td><code>{_e(r.engine)}</code></td><td>{_e(r.target)}</td>"
        f'<td><span class="st st-{r.status}">{_e(r.status)}</span></td>'
        f'<td class="num">{r.findings}</td><td class="num">{r.duration}s</td>'
        f'<td class="why">{_e(r.message) if r.message else "&mdash;"}</td></tr>'
        for r in sorted(result.runs, key=lambda x: (x.target, x.engine)))
    skipped = sum(1 for r in result.runs if r.status == "skipped")
    note = (f'<p class="muted">{skipped} engine run(s) did not execute; the '
            f'reason for each is in the last column.</p>' if skipped else "")
    return (f'<section><h2>Engine coverage</h2>{note}<table class="runs">'
            f'<thead><tr><th>Engine</th><th>Target</th><th>Status</th>'
            f'<th class="num">Findings</th><th class="num">Time</th>'
            f'<th>Why</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></section>')


def _chip(label, kind="") -> str:
    return f'<span class="chip {kind}">{_e(label)}</span>'


def _proof_block(f) -> str:
    """The 'where is it / prove it' block: parameter, payload, evidence and the
    raw request/response that demonstrate the finding."""
    rows = []
    if f.param:
        rows.append(f'<div class="prow"><span>parameter</span>'
                    f'<code>{_e(f.param)}</code></div>')
    if f.payload:
        rows.append(f'<div class="prow"><span>payload</span>'
                    f'<code>{_e(f.payload)[:400]}</code></div>')
    if f.evidence and f.evidence != f.payload:
        rows.append(f'<div class="prow"><span>evidence</span>'
                    f'<code>{_e(f.evidence)[:600]}</code></div>')
    raw = ""
    if f.request:
        raw += (f'<details><summary>request</summary>'
                f'<pre>{_e(f.request)}</pre></details>')
    if f.response:
        raw += (f'<details><summary>response</summary>'
                f'<pre>{_e(f.response)}</pre></details>')
    if not rows and not raw:
        return ""
    return f'<div class="proof"><div class="proof-hd">Proof</div>{"".join(rows)}{raw}</div>'


def _findings_section(findings) -> str:
    if not findings:
        return '<section><h2>Findings</h2><p class="empty">No findings.</p></section>'
    items = []
    for f in findings:
        chips = []
        if f.owasp:
            chips.append(_chip(f.owasp.split()[0], "owasp"))
        if f.owasp_api:
            chips.append(_chip(f.owasp_api.split()[0], "api"))
        if f.cwe:
            chips.append(_chip(f"CWE-{f.cwe}", "cwe"))
        for m in f.mitre[:2]:
            chips.append(_chip(m, "mitre"))
        if f.corroboration >= 2:
            chips.append(f'<span class="chip corrob">✓ corroborated ×{f.corroboration}</span>')
        engines = _e(f.engine)
        if f.also_reported_by:
            engines += f' <span class="corr">+{len(f.also_reported_by)} '\
                       f'({_e(", ".join(f.also_reported_by))})</span>'
        status_badge = ""
        if f.status in ("new", "regressed"):
            status_badge = f'<span class="stbadge {f.status}">{f.status}</span>'
        vbadge = ('<span class="vbadge confirmed" title="reproducible evidence '
                  '— corroborated, chained, or a payload with observable proof">'
                  '✓ confirmed</span>' if f.verified else
                  '<span class="vbadge review" title="single-engine heuristic — '
                  'verify before acting">needs review</span>')
        evidence = _proof_block(f)
        refs = ""
        # only render safe http(s) links (never javascript:/data: from a rogue
        # engine template)
        rlist = [r for r in f.references
                 if r and str(r).lower().startswith(("http://", "https://"))]
        if rlist:
            refs = '<div class="refs">' + " · ".join(
                f'<a href="{_e(r)}" rel="noopener noreferrer">reference</a>'
                for r in rlist[:4]) + '</div>'
        items.append(f"""
        <article class="finding" data-sev="{f.severity.label}"
                 style="--sev:{_SEV[f.severity.label]}">
          <div class="f-hd">
            <span class="score" title="risk score">{f.risk_score:.0f}</span>
            <div class="f-t">
              <h3>{_e(f.title)} {status_badge} {vbadge}</h3>
              <div class="f-meta">
                <span class="sev" style="color:{_SEV[f.severity.label]}">{f.severity.label}</span>
                · {engines} · confidence {_e(f.confidence)}
                {f'· {f.instances} instances' if f.instances > 1 else ''}
              </div>
            </div>
          </div>
          <div class="chips">{"".join(chips)}</div>
          {f'<div class="loc"><code>{_e(f.location)}</code></div>' if f.location else ''}
          {f'<p>{_e(f.description)}</p>' if f.description else ''}
          {evidence}
          {f'<p class="why"><b>Why we believe this.</b> {_e(f.rationale)}</p>' if f.rationale else ''}
          {f'<p class="fix"><b>Remediation.</b> {_e(f.remediation)}</p>' if f.remediation else ''}
          {refs}
        </article>""")
    return (f'<section><h2>Findings <small>{len(findings)}</small></h2>'
            f'<div class="filters" id="filters"></div>'
            f'<div id="findings">{"".join(items)}</div></section>')


def _fixed_section(result) -> str:
    if not result.fixed:
        return ""
    rows = "".join(
        f'<li><span class="sev" style="color:{_SEV[f.severity.label]}">'
        f'{f.severity.label}</span> {_e(f.title)} '
        f'<code>{_e(f.location or f.target)}</code></li>'
        for f in result.fixed)
    return (f'<section class="resolved"><h2>Resolved since baseline '
            f'<small>{len(result.fixed)}</small></h2><ul>{rows}</ul></section>')


def _now():
    import time
    return time.time()


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yubel — Security Assessment</title>
<style>
:root{{
  --ink:#16191d; --body:#2b3038; --muted:#6a7280; --line:#e2e5ea;
  --bg:#ffffff; --panel:#fbfcfd; --accent:#343a42; --accent-soft:#f1f3f5;
  /* The frame is deliberately neutral. Brand crimson and brand gold appear
     in exactly one place in this document — the mark in the masthead —
     because every other hue here already means a severity, and a reader
     should never have to work out whether a colour is a finding or a
     decoration. See scripts/brand.py. */
  --brand-gold:#c9a227; --brand-gold-dim:#8a6a1f; --brand-crimson:#a3121c;
  --serif:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,"Times New Roman",serif;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:"SFMono-Regular",Menlo,Consolas,"Liberation Mono",monospace;
}}
@media(prefers-color-scheme:dark){{
  :root{{--ink:#eef1f4;--body:#c4cad2;--muted:#8b93a0;--line:#2a2f37;
    --bg:#101317;--panel:#161a1f;--accent:#c8ced6;--accent-soft:#1b1f24;}}
}}
*{{box-sizing:border-box}}
html{{-webkit-text-size-adjust:100%}}
body{{margin:0;background:var(--bg);color:var(--body);
  font:16px/1.6 var(--sans);}}
.wrap{{max-width:960px;margin:0 auto;padding:0 28px 80px}}
/* underlined, because the accent is now a neutral graphite: a link must not
   depend on hue alone to be recognisable as one */
a{{color:var(--accent);text-decoration:underline;text-underline-offset:2px}}
h1,h2,h3{{font-family:var(--serif);color:var(--ink);font-weight:600;letter-spacing:-.01em}}
small{{font-family:var(--sans);font-weight:600;font-size:.55em;color:var(--muted);
  text-transform:uppercase;letter-spacing:.08em;margin-left:.6em;vertical-align:middle}}

/* masthead */
.mast{{border-bottom:3px double var(--line);padding:34px 0 20px;margin-bottom:8px;
  display:flex;align-items:flex-end;justify-content:space-between;gap:24px}}
.brand{{display:flex;align-items:center;gap:14px}}
.eye{{width:40px;height:40px;flex:none}}
.brand h1{{margin:0;font-size:30px;line-height:1}}
.brand .sub{{color:var(--muted);font-size:13px;margin-top:3px;
  text-transform:uppercase;letter-spacing:.14em}}
.mast .meta{{text-align:right;color:var(--muted);font-size:12.5px;line-height:1.5}}

/* executive summary */
.exec{{display:grid;grid-template-columns:150px 1fr;gap:28px;
  padding:26px 0 30px;border-bottom:1px solid var(--line)}}
.gradebox{{text-align:center}}
.gradebox .g{{font-family:var(--serif);font-size:74px;line-height:.9;font-weight:700}}
.gradebox .s{{color:var(--muted);font-size:12px;margin-top:6px;
  text-transform:uppercase;letter-spacing:.1em}}
.exec .prose h2{{margin:0 0 8px;font-size:15px;text-transform:uppercase;
  letter-spacing:.12em;color:var(--muted)}}
.exec .prose p{{margin:0 0 14px;font-size:15.5px}}
.bar{{display:flex;height:12px;border-radius:2px;overflow:hidden;
  background:var(--line);margin:2px 0 10px}}
.seg{{height:100%}}
.legend{{display:flex;flex-wrap:wrap;gap:14px;font-size:12.5px;color:var(--muted)}}
.lg i{{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px}}
.lg b{{color:var(--ink)}}
.diff{{margin-top:12px;font-size:13px;color:var(--muted)}}
.diff .new{{color:#9d2235}} .diff .reg{{color:#bf5a1a}} .diff .fix{{color:#1f7a4d}}

section{{padding:26px 0;border-bottom:1px solid var(--line)}}
h2{{font-size:22px;margin:0 0 14px}}
.section-note{{color:var(--muted);font-size:14px;margin:-6px 0 16px}}

/* attack chains */
.chain{{border:1px solid var(--line);border-left:4px solid var(--sev);
  border-radius:6px;padding:16px 18px;margin:14px 0;background:var(--panel)}}
.chain-hd{{display:flex;align-items:baseline;gap:10px}}
.chain-hd h3{{margin:0;font-size:18px}}
.chain p{{font-size:14.5px}}
.chain-steps{{display:flex;gap:12px;align-items:flex-start;margin:10px 0 4px}}
.chain-steps>span{{font-size:11px;text-transform:uppercase;letter-spacing:.1em;
  color:var(--muted);padding-top:3px}}
.chain-steps ol{{margin:0;padding-left:18px;font-size:13.5px;color:var(--body)}}
.chain-steps li{{margin:2px 0}}
.tag{{color:#fff;font-size:10.5px;font-weight:700;text-transform:uppercase;
  letter-spacing:.06em;padding:3px 8px;border-radius:3px}}

/* owasp coverage */
.cov-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}}
.cov{{border:1px solid var(--line);border-radius:6px;padding:10px 12px;
  display:flex;flex-direction:column;gap:2px;min-height:78px;background:var(--panel)}}
.cov.off{{opacity:.45}}
.cov .code{{font-family:var(--mono);font-size:12px;color:var(--accent);font-weight:700}}
.cov .ct{{font-family:var(--serif);font-size:24px;color:var(--ink);line-height:1}}
.cov .nm{{font-size:11px;color:var(--muted);line-height:1.25}}
.cov.on{{border-color:var(--accent);background:var(--accent-soft)}}

/* tables */
table{{width:100%;border-collapse:collapse;font-size:13.5px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}}
th{{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;
  letter-spacing:.08em}}
td.num,th.num{{text-align:right;font-variant-numeric:tabular-nums}}
code{{font-family:var(--mono);font-size:12.5px}}
.st{{font-size:11px;font-weight:600}}
.st-ok{{color:#1f7a4d}} .st-skipped{{color:var(--muted)}}
.st-error,.st-timeout{{color:#9d2235}}
td.why{{color:var(--muted);font-size:12.5px;max-width:38ch}}

/* filters */
.filters{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px}}
.filters button{{font:600 12px var(--sans);border:1px solid var(--line);
  background:var(--panel);color:var(--body);padding:5px 12px;border-radius:3px;cursor:pointer}}
.filters button.active{{background:var(--ink);color:var(--bg);border-color:var(--ink)}}

/* findings */
.finding{{border:1px solid var(--line);border-left:4px solid var(--sev);
  border-radius:6px;padding:15px 18px;margin:12px 0;background:var(--panel)}}
.f-hd{{display:flex;gap:14px;align-items:flex-start}}
.score{{font-family:var(--serif);font-size:26px;font-weight:700;color:var(--sev);
  min-width:42px;text-align:center;line-height:1.1}}
.f-t h3{{margin:0;font-size:17px}}
.f-meta{{font-size:12.5px;color:var(--muted);margin-top:3px}}
.f-meta .sev{{font-weight:700;text-transform:uppercase;letter-spacing:.05em;font-size:11.5px}}
.corr{{color:var(--accent)}}
.stbadge{{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;
  padding:2px 6px;border-radius:3px;vertical-align:middle;margin-left:6px}}
.stbadge.new{{background:#9d2235;color:#fff}} .stbadge.regressed{{background:#bf5a1a;color:#fff}}
.chips{{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0 6px}}
.chip{{font:600 11px var(--mono);padding:2px 7px;border-radius:3px;
  border:1px solid var(--line);color:var(--muted)}}
.chip.owasp{{color:var(--accent);border-color:var(--accent)}}
.chip.api{{color:#1f6f6b;border-color:#1f6f6b}}
.chip.mitre{{color:#8a5a1a;border-color:#c9a26a}}
.chip.corrob{{color:#1f7a4d;border-color:#1f7a4d;background:#1f7a4d14}}
.loc{{margin:4px 0}} .loc code{{color:var(--body);word-break:break-all}}
.finding p{{font-size:14.5px;margin:8px 0}}
.finding .fix{{font-size:13.5px;color:var(--body);background:var(--accent-soft);
  padding:8px 12px;border-radius:4px}}
.finding .why{{font-size:12.5px;color:var(--muted);border-left:2px solid var(--line);
  padding:2px 0 2px 10px;margin:8px 0}}
.finding .why b{{color:var(--body)}}
details{{margin:8px 0;font-size:13px}}
summary{{cursor:pointer;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}}
pre{{background:rgba(127,127,127,.09);padding:10px;border-radius:4px;overflow:auto;
  font-size:12px;max-height:240px;margin:8px 0 0}}
.vbadge{{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;
  padding:2px 7px;border-radius:3px;vertical-align:middle;margin-left:6px}}
.vbadge.confirmed{{background:#1f7a4d;color:#fff}}
.vbadge.review{{background:transparent;color:var(--muted);border:1px solid var(--line)}}
.proof{{margin:10px 0;border:1px solid var(--line);border-radius:5px;
  background:var(--bg);overflow:hidden}}
.proof-hd{{font-size:10.5px;text-transform:uppercase;letter-spacing:.1em;
  color:var(--muted);background:rgba(127,127,127,.06);padding:5px 10px;
  border-bottom:1px solid var(--line)}}
.prow{{display:flex;gap:10px;padding:6px 10px;font-size:12.5px;
  border-bottom:1px solid var(--line)}}
.prow>span{{flex:none;width:78px;color:var(--muted);text-transform:uppercase;
  font-size:10.5px;letter-spacing:.05em;padding-top:2px}}
.prow code{{word-break:break-all;color:var(--body)}}
.proof details{{margin:0;border-top:1px solid var(--line)}}
.proof summary{{padding:6px 10px}}
.proof pre{{margin:0;border-radius:0;max-height:300px}}
.refs{{font-size:12px;margin-top:8px}}
.resolved{{opacity:.75}} .resolved ul{{list-style:none;padding:0;font-size:13.5px}}
.resolved li{{padding:4px 0;border-bottom:1px solid var(--line)}}
.resolved .sev{{font-weight:700;font-size:11px;text-transform:uppercase;margin-right:8px}}
.empty{{color:var(--muted)}}
footer{{color:var(--muted);font-size:12px;padding:26px 0 0;line-height:1.6}}
@media(max-width:640px){{.exec{{grid-template-columns:1fr}}.cov-grid{{grid-template-columns:repeat(2,1fr)}}}}
@media print{{.filters{{display:none}}.finding,.chain{{break-inside:avoid}}body{{font-size:12px}}}}
</style></head><body><div class="wrap">

<div class="mast">
  <div class="brand">
    <svg class="eye" viewBox="0 0 100 100" aria-hidden="true">
      <circle cx="50" cy="50" r="30" fill="none" stroke="var(--brand-crimson)" stroke-width="2.4"/>
      <path d="M50 4 L56 44 L87 50 L56 56 L50 96 L44 56 L13 50 L44 44 Z" fill="var(--brand-gold)"/>
      <path d="M50 4 L44 44 L13 50 L44 56 L50 96 Z" fill="var(--brand-gold-dim)"/>
      <path d="M50 36 L55 50 L50 64 L45 50 Z" fill="var(--brand-crimson)"/>
    </svg>
    <div><h1>Yubel</h1><div class="sub">Security Assessment</div></div>
  </div>
  <div class="meta">Dynamic application security testing<br>{ts}<br>Yubel v{version} · {total} findings</div>
</div>

<div class="exec">
  <div class="gradebox">
    <div class="g" style="color:{grade_color}">{grade}</div>
    <div class="s">risk {risk}/100</div>
  </div>
  <div class="prose">
    <h2>Executive summary</h2>
    <p>{lede}</p>
    <div class="bar">{seg}</div>
    <div class="legend">{sev_legend}</div>
    {diff_line}
  </div>
</div>

{chains}
{systemic}
{coverage}
{findings}
{fixed}
{runs}

<footer>
  Generated by <b>Yubel</b> — an open-source, multi-target DAST orchestrator.
  Deterministic &amp; air-gapped by design: no LLM, no data egress — Yubel's core
  never phones home. Findings are corroborated across independent engines; attack
  paths and systemic issues are synthesized by correlation and should be validated
  before remediation. Test only systems you are authorized to assess.
</footer>
</div>
<script>
const bar=document.getElementById("filters");
if(bar){{
  const cards=[...document.querySelectorAll(".finding")];
  const order=["All","Critical","High","Medium","Low","Info"];
  const counts={{All:cards.length}};
  cards.forEach(c=>{{const s=c.dataset.sev;counts[s]=(counts[s]||0)+1;}});
  let active="All";
  const draw=()=>{{
    bar.innerHTML=order.filter(k=>k==="All"||counts[k]).map(k=>
      `<button data-k="${{k}}" class="${{k===active?'active':''}}">${{k}} ${{counts[k]||0}}</button>`).join("");
    bar.querySelectorAll("button").forEach(b=>b.onclick=()=>{{active=b.dataset.k;draw();
      cards.forEach(c=>c.style.display=(active==="All"||c.dataset.sev===active)?"":"none");}});
  }};
  draw();
}}
</script>
</body></html>"""
