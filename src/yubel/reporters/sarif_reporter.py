"""SARIF 2.1.0 writer so findings surface in GitHub code scanning / IDEs."""
from __future__ import annotations

import json

from ..models import ScanResult
from ..severity import Severity

_LEVEL = {
    Severity.INFO: "note", Severity.LOW: "note",
    Severity.MEDIUM: "warning", Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def write_sarif(result: ScanResult, path: str) -> None:
    rules = {}
    results = []
    for f in result.findings:
        rule_id = (f.cwe and f"CWE-{f.cwe}") or (f.title[:60].strip()) \
            or "yubel.finding"
        tags = [t for t in [f.owasp and f.owasp.split()[0],
                            f.owasp_api and f.owasp_api.split()[0],
                            "attack-chain" if f.is_chain else None] if t] + f.mitre
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title[:120],
                "shortDescription": {"text": f.title[:120]},
                # help text carries the remediation so it shows in code scanning
                "help": {"text": ("Remediation: " + f.remediation) if f.remediation
                         else (f.description or f.title)},
                "fullDescription": {"text": (f.description or f.title)[:1000]},
                "helpUri": (f.references or ["https://owasp.org/"])[0],
                "properties": {
                    # SARIF security-severity is a 0-10 float; map our 0-100 score
                    "security-severity": f"{min(10.0, f.risk_score / 10.0):.1f}",
                    "tags": tags,
                },
            }
        results.append({
            "ruleId": rule_id,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f"[{f.engine}] {f.title}: {f.description}"[:1000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location or f.target},
                }
            }],
            "properties": {"engine": f.engine, "confidence": f.confidence,
                           "risk_score": f.risk_score, "status": f.status,
                           "verified": f.verified, "corroboration": f.corroboration,
                           "parameter": f.param, "payload": f.payload,
                           "remediation": f.remediation,
                           "owasp": f.owasp, "mitre": f.mitre,
                           "fingerprint": f.fingerprint},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Yubel",
                "version": result.version,
                "informationUri": "https://github.com/ggeorgeazevedo/yubel",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)


def _cvss(sev: Severity) -> str:
    return {Severity.INFO: "0.0", Severity.LOW: "3.0", Severity.MEDIUM: "5.5",
            Severity.HIGH: "8.0", Severity.CRITICAL: "9.5"}[sev]
