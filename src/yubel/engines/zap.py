"""OWASP/Checkmarx ZAP adapter.

Runs ZAP's packaged automation scripts (zap-baseline.py / zap-full-scan.py for
web, zap-api-scan.py for OpenAPI/SOAP/GraphQL) and parses the JSON report.
These scripts ship inside the official `zaproxy/zap-stable` Docker image, which
is exactly what the Yubel container bundles.
"""
from __future__ import annotations

import json
import os
import shutil
from typing import List

from ..models import Finding, Target, TargetType
from .base import Engine


class ZapEngine(Engine):
    name = "zap"
    category = "full DAST (crawl + active scan)"
    supports = (TargetType.WEB, TargetType.API, TargetType.GRAPHQL)
    binary = ""  # resolved dynamically (script name varies)
    default_timeout = 1800
    homepage = "https://www.zaproxy.org/"

    #: candidate entrypoints in priority order per target type
    WEB_SCRIPTS = ("zap-full-scan.py", "zap-baseline.py")
    API_SCRIPTS = ("zap-api-scan.py",)

    def _script(self, target: Target) -> str:
        candidates = self.API_SCRIPTS if target.type in (
            TargetType.API, TargetType.GRAPHQL) else self._web_scripts()
        for c in candidates:
            if shutil.which(c):
                return c
        return ""

    def _web_scripts(self):
        if self.options.get("mode") == "baseline":
            return ("zap-baseline.py", "zap-full-scan.py")
        return self.WEB_SCRIPTS

    def available(self) -> bool:
        return any(shutil.which(s) for s in
                   self.WEB_SCRIPTS + self.API_SCRIPTS)

    def unavailable_reason(self) -> str:
        return ("ZAP automation scripts (zap-baseline.py / zap-full-scan.py / "
                "zap-api-scan.py) not found on PATH — use the Yubel Docker image "
                "or install ZAP")

    def build_command(self, target: Target, workdir: str) -> List[str]:
        script = self._script(target)
        if not script:
            raise FileNotFoundError("no zap-*.py automation script on PATH")
        report = os.path.join(workdir, "zap.json")
        cmd = [script, "-t", target.endpoint(), "-J", os.path.basename(report),
               "-w", "zap.md", "-I"]
        if target.type in (TargetType.API, TargetType.GRAPHQL):
            fmt = "graphql" if target.type == TargetType.GRAPHQL else \
                self.options.get("api_format", "openapi")
            cmd += ["-f", fmt]
            if target.openapi:
                cmd[cmd.index(target.endpoint())] = target.openapi
        if self.options.get("ajax"):
            cmd += ["-j"]
        return cmd

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        report = os.path.join(workdir, "zap.json")
        raw = self._read(report)
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        findings: List[Finding] = []
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                instances = alert.get("instances", [{}])
                loc = instances[0].get("uri", site.get("@name", "")) if instances else ""
                findings.append(Finding(
                    title=alert.get("alert", alert.get("name", "ZAP alert")),
                    severity=alert.get("riskcode", alert.get("riskdesc", "0")),
                    engine=self.name,
                    target=target.label,
                    description=_strip_html(alert.get("desc", "")),
                    location=loc,
                    evidence=instances[0].get("evidence", "") if instances else "",
                    cwe=str(alert.get("cweid")) if alert.get("cweid", "-1") not in ("-1", "") else None,
                    references=[r for r in _strip_html(alert.get("reference", "")).split("\n") if r],
                    confidence=_confidence(alert.get("confidence", "2")),
                    remediation=_strip_html(alert.get("solution", "")),
                    raw={"pluginid": alert.get("pluginid"), "count": alert.get("count")},
                ))
        return findings

    def _ok_returncodes(self):
        return (0, 1, 2)  # zap uses exit codes for warn/fail thresholds


def _strip_html(s: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", s or "").replace("&lt;", "<").replace("&gt;", ">").strip()


def _confidence(c: str) -> str:
    return {"0": "low", "1": "low", "2": "medium", "3": "high", "4": "high"}.get(str(c), "medium")
