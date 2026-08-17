"""SARIF 2.1.0 writer so findings surface in GitHub code scanning / IDEs."""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from ..models import ScanResult
from ..severity import Severity

_LEVEL = {
    Severity.INFO: "note", Severity.LOW: "note",
    Severity.MEDIUM: "warning", Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

# Where DAST findings get anchored in the repo tree. They do not correspond to
# a source file, so we synthesise a stable pseudo-path under this prefix.
_URI_PREFIX = "dast"
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _artifact_uri(raw: str) -> str:
    """Turn a scanned URL/host into a checkout-relative SARIF artifact URI.

    GitHub code scanning resolves every `artifactLocation.uri` against the
    checkout, whose scheme is `file`. An absolute `https://...` URI (or a
    bare `host:port/...`, where the parser reads the host as the scheme) is
    rejected outright with "SARIF URI scheme ... did not match the checkout
    URI scheme file", and the whole upload is dropped.

    So we emit a relative pseudo-path — `dast/<host>/<path>` — and keep the
    real URL in the result message and properties, where it stays readable.
    The path is deterministic, so an alert tracks across runs.
    """
    raw = (raw or "").strip()
    if not raw:
        return f"{_URI_PREFIX}/unknown"

    host, path, port = "", "", None
    try:                             # never let a weird target break the report
        split = urlsplit(raw if "//" in raw else f"//{raw}", scheme="")
        host, path = split.hostname or "", split.path or ""
        try:
            port = split.port        # raises on things like an ARN
        except ValueError:
            port = None
    except ValueError:
        pass
    if not host:                     # not URL-shaped (k8s host, ARN, free text)
        host, path, port = raw, "", None

    parts = [_UNSAFE.sub("-", host).strip("-") or "unknown"]
    if port:
        parts[0] = f"{parts[0]}-{port}"
    for seg in path.split("/"):
        seg = _UNSAFE.sub("-", seg).strip("-")
        if seg and seg not in (".", ".."):
            parts.append(seg)
    return "/".join([_URI_PREFIX, *parts])[:2000]


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
        where = f.location or f.target
        results.append({
            "ruleId": rule_id,
            "level": _LEVEL.get(f.severity, "warning"),
            # the real URL leads the message: the anchor below is a pseudo-path,
            # so this is where a reader actually sees what was scanned
            "message": {"text": f"[{f.engine}] {where} - {f.title}: "
                                f"{f.description}"[:1000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(where)},
                }
            }],
            # stable across runs, so code scanning tracks an alert instead of
            # closing and reopening it every scan
            "partialFingerprints": {"yubel/v1": f.fingerprint},
            "properties": {"url": where,
                           "engine": f.engine, "confidence": f.confidence,
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
