#!/usr/bin/env python3
"""Regenerate `docs/sample-report.html` — the showcase a stranger clicks first.

The committed sample was cut from v0.4.0 and had been stale for three releases:
it still carried the old palette, and it showed none of the reporting the tool
actually does now — no proof block, no remediation, no confirmed/needs-review
tier, no systemic correlation. A screenshot of an old version is worse than no
screenshot, because it undersells the tool while looking authoritative.

The scenario below is synthetic and fixed, so the page is reproducible: no
network, no engines, no clock. It is built to exercise the parts of the report
that only appear when there is something interesting to show — corroboration
across engines, an attack chain, the same flaw on several targets, and a
finding with a real request/response pair.

    python3 scripts/gen_sample_report.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from yubel.analysis import analyze                               # noqa: E402
from yubel.models import EngineRun, Finding, ScanResult          # noqa: E402
from yubel.reporters.html_reporter import write_html             # noqa: E402
from yubel.severity import Severity                              # noqa: E402

API = "https://api.example.com"
APP = "https://app.example.com"
ADMIN = "https://admin.example.com"


def _f(**kw) -> Finding:
    kw.setdefault("confidence", "medium")
    return Finding(**kw)


def build() -> ScanResult:
    result = ScanResult()
    result.add([
        # Corroborated by two engines with different CWE spellings — the case
        # `canon_cwe` exists for. Renders as "confirmed, 2 engines".
        _f(title="Reflected Cross-Site Scripting", severity=Severity.HIGH,
           engine="nuclei", target=APP, location=f"{APP}/search?q=1",
           cwe="cwe-79", param="q", payload="<svg/onload=alert(1)>",
           confidence="high",
           request=("GET /search?q=%3Csvg%2Fonload%3Dalert(1)%3E HTTP/1.1\n"
                    "Host: app.example.com\n"
                    "User-Agent: Mozilla/5.0\n"
                    "Accept: text/html\n"),
           response=("HTTP/1.1 200 OK\n"
                     "Content-Type: text/html; charset=utf-8\n\n"
                     "<div class=\"results\">no hits for "
                     "<svg/onload=alert(1)></div>"),
           evidence="payload reflected unencoded in the response body"),
        _f(title="Reflected Cross-Site Scripting", severity=Severity.HIGH,
           engine="dalfox", target=APP, location=f"{APP}/search?q=1",
           cwe="79", param="q", payload="<svg/onload=alert(1)>",
           confidence="high", evidence="verified reflection, PoC generated"),

        # The two halves of an attack chain.
        _f(title="Server-Side Request Forgery", severity=Severity.HIGH,
           engine="nuclei", target=API, location=f"{API}/v1/fetch?url=",
           cwe="918", param="url", confidence="high",
           payload="http://169.254.169.254/latest/meta-data/",
           evidence="response body contains cloud metadata keys"),
        _f(title="Cloud metadata endpoint reachable", severity=Severity.MEDIUM,
           engine="nuclei", target=API, location=f"{API}/v1/fetch",
           cwe="200", confidence="high"),

        # The same misconfiguration on three hosts — systemic correlation
        # collapses this into "one fix, three instances".
        _f(title="Missing Strict-Transport-Security header",
           severity=Severity.LOW, engine="zap", target=APP, location=APP,
           cwe="319"),
        _f(title="Missing Strict-Transport-Security header",
           severity=Severity.LOW, engine="zap", target=API, location=API,
           cwe="319"),
        _f(title="Missing Strict-Transport-Security header",
           severity=Severity.LOW, engine="zap", target=ADMIN, location=ADMIN,
           cwe="319"),

        _f(title="TLS 1.0 and TLS 1.1 accepted", severity=Severity.MEDIUM,
           engine="testssl", target=ADMIN, location=f"{ADMIN}:443",
           cwe="327", confidence="high",
           evidence="TLSv1.0 offered, TLSv1.1 offered"),
        _f(title="SQL Injection (boolean-based blind)",
           severity=Severity.CRITICAL, engine="sqlmap", target=API,
           location=f"{API}/v1/items?id=1", cwe="89", param="id",
           payload="id=1 AND 4823=4823", confidence="high",
           evidence="parameter 'id' is vulnerable, back-end DBMS: PostgreSQL"),
        _f(title="Directory listing enabled", severity=Severity.INFO,
           engine="nikto", target=ADMIN, location=f"{ADMIN}/backups/"),
        _f(title="Outdated jQuery 1.8.3 in use", severity=Severity.MEDIUM,
           engine="nuclei", target=APP, location=f"{APP}/static/jquery.js",
           cwe="1104"),
    ])

    # Fixed start/finish stamps so the rendered durations are stable.
    for name, findings, seconds in (("katana", 0, 18.3), ("nuclei", 5, 42.1),
                                    ("zap", 3, 128.4), ("dalfox", 1, 11.2),
                                    ("testssl", 1, 33.8), ("sqlmap", 1, 96.0),
                                    ("nikto", 1, 51.7)):
        result.runs.append(EngineRun(engine=name, target=APP, status="ok",
                                     findings=findings, started_at=0.0,
                                     finished_at=seconds,
                                     command=f"{name} …"))
    return result


def main() -> int:
    result = analyze(build().dedupe())
    out = ROOT / "docs" / "sample-report.html"
    write_html(result, str(out))
    print(f"wrote {out.relative_to(ROOT)} "
          f"({len(result.findings)} findings, "
          f"{out.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
