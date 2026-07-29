"""Map findings to security taxonomies and compute a composite risk score.

Mappings are CWE-driven (the one identifier almost every engine emits) and
follow the official OWASP CWE cross-references for the 2021 Top 10 and the
2023 API Top 10. MITRE ATT&CK is mapped at the category level (defensible and
stable) rather than guessing per-CWE techniques.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..models import Finding
from ..severity import Severity

# ---- OWASP Top 10 : 2021  (category -> set of CWE ids) --------------------
_OWASP_2021: Dict[str, set] = {
    "A01:2021 Broken Access Control": {
        22, 23, 35, 59, 200, 201, 219, 275, 276, 284, 285, 352, 359, 377, 402,
        425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862,
        863, 913, 922, 1275},
    "A02:2021 Cryptographic Failures": {
        261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330,
        331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916},
    "A03:2021 Injection": {
        20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97,
        98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917},
    "A04:2021 Insecure Design": {
        73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316,
        419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642,
        646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173},
    "A05:2021 Security Misconfiguration": {
        2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756,
        776, 942, 1004, 1032, 1174},
    "A06:2021 Vulnerable & Outdated Components": {937, 1035, 1104},
    "A07:2021 Identification & Authentication Failures": {
        255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346,
        384, 521, 613, 620, 640, 798, 940, 1216},
    "A08:2021 Software & Data Integrity Failures": {
        345, 353, 426, 494, 502, 565, 784, 829, 830, 915},
    "A09:2021 Security Logging & Monitoring Failures": {117, 223, 532, 778},
    "A10:2021 Server-Side Request Forgery": {918},
}

# ---- OWASP API Security Top 10 : 2023 -------------------------------------
_OWASP_API_2023: Dict[str, set] = {
    "API1:2023 Broken Object Level Authorization": {284, 285, 566, 639},
    "API2:2023 Broken Authentication": {
        287, 290, 294, 295, 297, 298, 306, 307, 345, 522, 613, 798},
    "API3:2023 Broken Object Property Level Authorization": {213, 915},
    "API4:2023 Unrestricted Resource Consumption": {400, 770, 799},
    "API5:2023 Broken Function Level Authorization": {285, 862, 863},
    "API7:2023 Server Side Request Forgery": {918},
    "API8:2023 Security Misconfiguration": {2, 16, 209, 319, 611, 614, 942, 1004},
    "API10:2023 Unsafe Consumption of APIs": {345, 494, 829},
}

# ---- MITRE ATT&CK (mapped by OWASP-2021 category prefix) ------------------
_MITRE_BY_CAT: Dict[str, List[str]] = {
    "A01": ["T1190", "T1078"],           # exploit public app / valid accounts
    "A02": ["T1040", "T1557"],           # network sniffing / adversary-in-the-middle
    "A03": ["T1190", "T1059"],           # exploit public app / command & scripting
    "A04": ["T1190"],
    "A05": ["T1190", "T1526"],           # cloud service discovery
    "A06": ["T1190"],
    "A07": ["T1110", "T1078"],           # brute force / valid accounts
    "A08": ["T1195", "T1554"],           # supply chain / compromise host software
    "A09": ["T1562"],                    # impair defenses
    "A10": ["T1190", "T1526"],
}


def _cwe_int(f: Finding) -> Optional[int]:
    if not f.cwe:
        return None
    digits = "".join(ch for ch in str(f.cwe) if ch.isdigit())
    return int(digits) if digits else None


def enrich(f: Finding) -> None:
    """Attach OWASP / API / MITRE labels to a finding (idempotent)."""
    # TLS/transport findings are always Cryptographic Failures — override the
    # generic CWE (e.g. testssl tags BEAST as CWE-20, which would wrongly bucket
    # it under Injection).
    if f.title.startswith("TLS:") or f.engine == "testssl":
        f.owasp = "A02:2021 Cryptographic Failures"
        f.mitre = f.mitre or _MITRE_BY_CAT.get("A02", [])
        score(f)
        return
    cwe = _cwe_int(f)
    if cwe is not None:
        for cat, cwes in _OWASP_2021.items():
            if cwe in cwes:
                f.owasp = cat
                break
        for cat, cwes in _OWASP_API_2023.items():
            if cwe in cwes:
                f.owasp_api = cat
                break
    # keyword fallback when no CWE (common for TLS/info findings)
    if not f.owasp:
        f.owasp = _keyword_owasp(f)
    if f.owasp and not f.mitre:
        f.mitre = _MITRE_BY_CAT.get(f.owasp[:3], [])
    score(f)


def _keyword_owasp(f: Finding) -> Optional[str]:
    t = f"{f.title} {f.description}".lower()
    if any(k in t for k in ("tls", "ssl", "cipher", "certificate", "hsts")):
        return "A02:2021 Cryptographic Failures"
    if any(k in t for k in ("header", "misconfig", "directory listing",
                            "default", "verbose error", "introspection")):
        return "A05:2021 Security Misconfiguration"
    if "ssrf" in t:
        return "A10:2021 Server-Side Request Forgery"
    if any(k in t for k in ("auth", "login", "password", "token", "jwt")):
        return "A07:2021 Identification & Authentication Failures"
    return None


# ---- composite risk score -------------------------------------------------
_SEV_BASE = {Severity.INFO: 6, Severity.LOW: 22, Severity.MEDIUM: 46,
             Severity.HIGH: 74, Severity.CRITICAL: 92}


def score(f: Finding) -> float:
    """0-100 composite: severity base, adjusted by corroboration, confidence,
    exposure and whether it is a synthesized attack chain. Stored on f."""
    s = float(_SEV_BASE[f.severity])
    # corroboration: multiple independent engines => more real
    if f.corroboration >= 2:
        s += min(8.0, (f.corroboration - 1) * 4.0)
    # analyst confidence
    s += {"high": 4.0, "medium": 0.0, "low": -6.0}.get(f.confidence, 0.0)
    # attack chains are, by definition, demonstrated impact
    if f.is_chain:
        s += 10.0
    s = max(0.0, min(100.0, s))
    f.risk_score = round(s, 1)
    return f.risk_score


def target_risk(findings: List[Finding]) -> float:
    """Aggregate per-target risk with diminishing returns on stacked findings."""
    scores = sorted((f.risk_score for f in findings), reverse=True)
    total, weight = 0.0, 1.0
    for sc in scores:
        total += sc * weight
        weight *= 0.35
    return round(min(100.0, total), 1)


def grade(risk: float) -> str:
    return ("A" if risk < 15 else "B" if risk < 35 else "C" if risk < 55
            else "D" if risk < 78 else "F")


def owasp_coverage(findings: List[Finding]) -> Dict[str, int]:
    """Count findings per OWASP 2021 category (for the coverage matrix)."""
    out = {cat: 0 for cat in _OWASP_2021}
    for f in findings:
        if f.owasp in out:
            out[f.owasp] += 1
    return out
