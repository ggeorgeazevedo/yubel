"""Cross-engine consensus and noise clustering.

Having many engines look at the same target is Yubel's structural advantage.
`consensus()` turns agreement into signal: a finding independently reported by
two or more engines is far less likely to be a false positive, so its confidence
is upgraded and it is flagged as corroborated. `cluster_noise()` does the
opposite for low-value repetition — 200 "missing header" hits become one finding
with an instance count, so the real issues aren't buried.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import List

from ..models import Finding, ScanResult
from ..severity import Severity


def consensus(result: ScanResult) -> None:
    """Upgrade confidence for findings multiple engines agree on.

    Assumes `dedupe()` already populated `corroboration`/`also_reported_by`.
    """
    for f in result.findings:
        if f.corroboration >= 2:
            f.confidence = "high"
            note = f"Corroborated by {f.corroboration} engines " \
                   f"({', '.join([f.engine] + f.also_reported_by)})."
            if note not in (f.description or ""):
                f.description = (f.description + "\n\n" + note).strip() \
                    if f.description else note


def cluster_noise(result: ScanResult, threshold: int = 8) -> None:
    """Collapse large groups of low-value, same-class findings into one.

    Only INFO/LOW findings sharing (title, cwe) on the same target are eligible,
    so nothing MEDIUM+ is ever hidden. The representative keeps a few example
    locations and an `instances` count.
    """
    if threshold <= 1:
        return
    groups: dict = defaultdict(list)
    passthrough: List[Finding] = []
    for f in result.findings:
        if f.severity <= Severity.LOW and not f.is_chain:
            key = (f.target, f.title.strip().lower(), f.cwe or "")
            groups[key].append(f)
        else:
            passthrough.append(f)

    clustered: List[Finding] = []
    for key, items in groups.items():
        if len(items) >= threshold:
            rep = max(items, key=lambda x: int(x.severity))
            locations = [i.location for i in items if i.location][:10]
            rep.instances = len(items)
            # NB: do NOT bake the count into the title — the fingerprint is
            # derived from the title, so a changing count would make the whole
            # cluster churn as new/fixed on every baseline diff. The instance
            # count is carried in `instances` and rendered by the reporters.
            rep.evidence = "\n".join(locations)
            rep.description = (rep.description + "\n\n" if rep.description else "") \
                + f"Clustered {len(items)} similar occurrences across this target."
            clustered.append(rep)
        else:
            clustered.extend(items)

    result.findings = passthrough + clustered
    result.findings.sort(key=lambda x: (-int(x.severity), x.title))


def _class_key(f: Finding) -> str:
    """A stable 'issue class' key: the CWE if present, else the title with any
    parameter/URL noise stripped, so the same class matches across targets."""
    if f.cwe:
        return f"cwe-{f.cwe}"
    t = f.title.lower()
    t = re.sub(r"\(.*?\)", "", t)          # drop "(12 instances)" etc.
    t = re.sub(r"[^a-z ]", "", t).strip()
    return t


def explain(result: ScanResult) -> None:
    """Attach a deterministic 'why we believe this' rationale to each finding.

    This is Yubel's answer to LLM validators: the reasoning is explicit,
    reproducible and auditable — no model, no guessing.
    """
    for f in result.findings:
        bits = []
        engines = [f.engine] + list(f.also_reported_by)
        if f.corroboration >= 2:
            bits.append(f"Corroborated by {f.corroboration} independent engines "
                        f"({', '.join(engines)}) — agreement lowers false-positive risk.")
        elif f.is_chain:
            bits.append("Synthesized by correlating multiple findings on this "
                        "target into a single exploitation path.")
        elif f.is_systemic:
            bits.append(f"Observed as the same class across "
                        f"{len(f.affected_targets)} targets "
                        f"({', '.join(f.affected_targets)}).")
        else:
            bits.append(f"Reported by {f.engine}.")
        tax = " · ".join([x for x in [
            f"CWE-{f.cwe}" if f.cwe else None, f.owasp, f.owasp_api,
            ("MITRE " + ", ".join(f.mitre)) if f.mitre else None] if x])
        if tax:
            bits.append(f"Classified as {tax}.")
        if f.instances > 1:
            bits.append(f"{f.instances} occurrences clustered.")
        bits.append(f"Confidence {f.confidence}; composite risk {f.risk_score:.0f}/100.")
        f.rationale = " ".join(bits)


def cross_target(result: ScanResult) -> None:
    """Systemic correlation: when the same issue class appears on 2+ distinct
    targets, surface a single 'systemic' finding. A monolithic scanner that sees
    one app at a time cannot do this — Yubel sees the whole fleet."""
    groups: dict = defaultdict(list)
    for f in result.findings:
        if f.is_chain or f.is_systemic or f.severity <= Severity.INFO:
            continue
        groups[_class_key(f)].append(f)

    systemic: List[Finding] = []
    for _key, items in groups.items():
        targets = sorted({i.target for i in items})
        if len(targets) < 2:
            continue
        worst = max(items, key=lambda x: int(x.severity))
        systemic.append(Finding(
            title=f"Systemic: {worst.title} across {len(targets)} targets",
            severity=worst.severity,
            engine="yubel-correlator",
            target=", ".join(targets),
            description=f"The same issue class ({worst.title}) was found on "
                        f"{len(targets)} independent targets, indicating a "
                        f"systemic control gap rather than an isolated bug. "
                        f"Fixing it centrally (shared library, gateway policy, "
                        f"baseline hardening) resolves it everywhere at once.",
            cwe=worst.cwe,
            confidence="high",
            is_systemic=True,
            affected_targets=targets,
            references=worst.references,
        ))
    result.findings.extend(systemic)
