from __future__ import annotations

from datetime import datetime

from ..models import ScanResult
from ..analysis.taxonomy import target_risk, grade, owasp_coverage


def write_markdown(result: ScanResult, path: str) -> None:
    c = result.counts()
    risk = target_risk(result.findings)
    g = grade(risk)
    chains = [f for f in result.findings if f.is_chain]
    lines = []

    lines.append("# Yubel — Security Assessment\n")
    lines.append(f"*{_ts(result.finished_at)} · Yubel v{result.version} · "
                 f"{result.duration}s*\n")

    lines.append("## Executive summary\n")
    lines.append(f"- **Risk grade:** {g}  (score {risk}/100)")
    lines.append(f"- **Findings:** {c['Total']} — "
                 f"{c['Critical']} critical, {c['High']} high, {c['Medium']} medium, "
                 f"{c['Low']} low, {c['Info']} info")
    if chains:
        lines.append(f"- **Attack chains synthesized:** {len(chains)}")
    if result.baseline:
        d = result.diff_counts()
        lines.append(f"- **vs baseline:** {d['new']} new · {d['regressed']} regressed "
                     f"· {d['existing']} existing · {d['fixed']} fixed")
    lines.append("")

    if chains:
        lines.append("## Attack paths\n")
        lines.append("_Composite findings correlated across engines — paths no "
                     "single scanner reports alone._\n")
        for c0 in chains:
            lines.append(f"### {c0.title} — {c0.severity.label} "
                         f"(risk {c0.risk_score:.0f})\n")
            lines.append(f"{c0.description}\n")
            if c0.chain_steps:
                lines.append("**Chain:** " + " → ".join(c0.chain_steps) + "\n")
            if c0.remediation:
                lines.append(f"**Remediation:** {c0.remediation}\n")

    systemic = [f for f in result.findings if f.is_systemic]
    if systemic:
        lines.append("## Systemic issues (across targets)\n")
        lines.append("_Same weakness class on multiple targets — fix centrally._\n")
        for s in systemic:
            lines.append(f"### {s.title} — {s.severity.label}\n")
            lines.append(f"{s.description}\n")
            lines.append(f"**Affected targets:** {', '.join(s.affected_targets)}\n")

    lines.append("## OWASP Top 10 coverage\n")
    lines.append("| Category | Findings |")
    lines.append("|---|---|")
    for cat, n in owasp_coverage(result.findings).items():
        if n:
            lines.append(f"| {cat} | {n} |")
    lines.append("")

    lines.append("## Findings\n")
    plain = [f for f in result.findings if not f.is_chain and not f.is_systemic]
    if not plain:
        lines.append("_No findings._\n")
    for i, f in enumerate(plain, 1):
        engines = f"`{f.engine}`"
        if f.also_reported_by:
            engines += f" (+{', '.join(f.also_reported_by)})"
        tags = []
        if f.owasp:
            tags.append(f.owasp.split()[0])
        if f.owasp_api:
            tags.append(f.owasp_api.split()[0])
        if f.cwe:
            tags.append(f"CWE-{f.cwe}")
        tags += f.mitre[:2]
        stat = f" · _{f.status}_" if f.status in ("new", "regressed") else ""
        lines.append(f"### {i}. {f.title} — {f.severity.label} "
                     f"(risk {f.risk_score:.0f}){stat}\n")
        lines.append(f"- **Engine:** {engines} · confidence {f.confidence}"
                     + (f" · corroborated ×{f.corroboration}" if f.corroboration > 1 else ""))
        if tags:
            lines.append(f"- **Taxonomy:** {' · '.join(tags)}")
        if f.location:
            lines.append(f"- **Location:** `{f.location}`")
        if f.instances > 1:
            lines.append(f"- **Instances:** {f.instances}")
        if f.description:
            lines.append(f"\n{f.description}\n")
        if f.rationale:
            lines.append(f"- **Why we believe this:** {f.rationale}")
        if f.evidence:
            lines.append(f"**Evidence:**\n\n```\n{_clip(f.evidence)}\n```\n")
        if f.remediation:
            lines.append(f"**Remediation:** {f.remediation}\n")
        rlist = [r for r in f.references if r]
        if rlist:
            lines.append("**References:** " + " · ".join(rlist[:5]) + "\n")
        lines.append("---\n")

    if result.fixed:
        lines.append("## Resolved since baseline\n")
        for f in result.fixed:
            lines.append(f"- {f.severity.label}: {f.title} `{f.location or f.target}`")
        lines.append("")

    lines.append("## Engine coverage\n")
    lines.append("| Engine | Target | Status | Findings | Time |")
    lines.append("|---|---|---|---|---|")
    for r in sorted(result.runs, key=lambda x: (x.target, x.engine)):
        lines.append(f"| `{r.engine}` | {r.target} | {r.status} | "
                     f"{r.findings} | {r.duration}s |")
    lines.append("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def _ts(epoch: float) -> str:
    # local timezone of the machine running Yubel
    dt = datetime.fromtimestamp(epoch or datetime.now().timestamp()).astimezone()
    return dt.strftime("%Y-%m-%d %H:%M %Z")


def _clip(s: str, n: int = 1200) -> str:
    s = s or ""
    # neutralize any ``` so engine evidence can't break out of the code fence
    s = s.replace("```", "ʼʼʼ")
    return s if len(s) <= n else s[:n] + "…"
