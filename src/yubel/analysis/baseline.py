"""Baseline diffing: compare this run against a previous yubel.json.

Every finding is tagged new / existing / regressed, and issues present in the
baseline but gone now are collected as `fixed`. This makes CI gating precise —
you can fail only on *new* criticals — and gives reports a real trend instead of
an undifferentiated wall of findings on every run.
"""
from __future__ import annotations

import json
import os
from typing import Dict

from ..models import Finding, ScanResult
from ..severity import Severity


def _load(path: str) -> Dict[str, dict]:
    """Return {fingerprint: finding_dict} from a prior yubel.json."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}
    out = {}
    for f in data.get("findings", []):
        fp = f.get("fingerprint")
        if fp:
            out[fp] = f
    return out


def apply(result: ScanResult, baseline_path: str) -> None:
    prior = _load(baseline_path)
    result.baseline = baseline_path
    current_fps = set()

    for f in result.findings:
        fp = f.fingerprint
        current_fps.add(fp)
        if fp not in prior:
            f.status = "new"
        else:
            old_sev = Severity.from_any(prior[fp].get("severity"))
            f.status = "regressed" if f.severity > old_sev else "existing"

    # anything in the baseline no longer present is fixed
    for fp, old in prior.items():
        if fp not in current_fps:
            result.fixed.append(Finding(
                title=old.get("title", "(fixed)"),
                severity=old.get("severity", "info"),
                engine=old.get("engine", "baseline"),
                target=old.get("target", ""),
                location=old.get("location", ""),
                cwe=old.get("cwe"),
                status="fixed",
            ))
