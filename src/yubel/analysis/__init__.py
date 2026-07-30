"""Yubel analysis pipeline — the layer that turns a pile of raw engine output
into intelligence no single scanner produces:

  * taxonomy   — map every finding to OWASP Top 10 / API Top 10 / CWE / MITRE
  * scoring    — a composite 0-100 risk score and per-target grade
  * correlate  — cross-engine consensus + noise clustering
  * chains     — synthesize multi-engine attack chains
  * baseline   — diff against a previous run (new / fixed / regressed)

`analyze()` runs them in the right order over a deduped ScanResult.
"""
from __future__ import annotations

from typing import Optional

from ..models import Finding, ScanResult
from . import taxonomy, correlate, chains, baseline as _baseline, remediation


def _verified(f: Finding) -> bool:
    """Deterministic 'confirmed vs needs-review' tier — Yubel's auditable answer
    to proof-based scanning (no LLM, no destructive exploit). A finding is
    *confirmed* when we hold concrete, reproducible evidence that it is real:
      • it is a synthesized attack chain (demonstrated multi-step impact), or
      • two or more independent engines reported it (consensus), or
      • a payload produced observable proof (reflected value / PoC / response), or
      • it is a direct transport observation (testssl reads the live config), or
      • a high-confidence detection that captured request/response evidence.
    Everything else is *reported* — surfaced, but flagged for human review."""
    if f.is_chain or f.corroboration >= 2:
        return True
    if f.payload and (f.evidence or f.response):
        return True
    if f.engine == "testssl":
        return True
    if f.confidence == "high" and (f.evidence or f.response):
        return True
    return False


def analyze(result: ScanResult, baseline_path: Optional[str] = None,
            cluster_threshold: int = 8, enable_chains: bool = True) -> ScanResult:
    """Full post-processing pipeline. Input should already be deduped."""
    # 1. enrich taxonomy + base risk score on every finding
    for f in result.findings:
        taxonomy.enrich(f)
    # 2. cross-engine consensus (confidence uplift) + noise clustering
    correlate.consensus(result)
    correlate.cluster_noise(result, threshold=cluster_threshold)
    # 3. synthesize attack chains (added as new composite findings)
    if enable_chains:
        chains.synthesize(result)
    # 4. systemic correlation across targets (same class on 2+ targets)
    correlate.cross_target(result)
    # 5. enrich any new (chain/systemic) findings + recompute risk now that
    #    corroboration and chains are known; fill remediation + proof tier
    for f in result.findings:
        taxonomy.enrich(f)
        taxonomy.score(f)
        remediation.remediate(f)
        f.verified = _verified(f)
    # 6. attach the deterministic "why we believe this" rationale
    correlate.explain(result)
    result.findings.sort(key=lambda x: (-x.risk_score, -int(x.severity), x.title))
    # 7. baseline diff (marks new/existing/regressed + collects fixed)
    if baseline_path:
        _baseline.apply(result, baseline_path)
    return result


__all__ = ["analyze", "taxonomy", "correlate", "chains", "remediation"]
