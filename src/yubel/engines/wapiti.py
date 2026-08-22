"""Wapiti adapter — black-box web DAST with per-vulnerability modules."""
from __future__ import annotations

import json
import os
from typing import List

from ..models import Finding, Target, TargetType
from ..redact import redact_text, secrets_of
from .base import Engine

# Wapiti category -> CWE hint for nicer normalization
_CWE = {
    "SQL Injection": "89", "Blind SQL Injection": "89",
    "Cross Site Scripting": "79", "Command execution": "78",
    "Path Traversal": "22", "CRLF Injection": "93",
    "Server Side Request Forgery": "918", "XML External Entity": "611",
    "Open Redirect": "601", "Secure Flag cookie": "614",
}


class WapitiEngine(Engine):
    name = "wapiti"
    category = "web DAST (per-vuln modules)"
    supports = (TargetType.WEB, TargetType.API)
    binary = "wapiti"
    header_flag = "-H"
    default_timeout = 1500
    homepage = "https://wapiti-scanner.github.io/"

    def build_command(self, target: Target, workdir: str) -> List[str]:
        out = os.path.join(workdir, "wapiti.json")
        cmd = [self.binary, "-u", target.endpoint(),
               "-f", "json", "-o", out, "--flush-session",
               "--scope", self.options.get("scope", "folder")]
        depth = self.options.get("depth")
        if depth:
            cmd += ["-d", str(depth)]
        auth = target.auth
        if auth.kind == "basic" and auth.username:
            # wapiti drives basic auth natively (it manages the session), which
            # is better than sending the header ourselves
            cmd += ["--auth-method", "basic", "--auth-user", auth.username,
                    "--auth-password", auth.password or ""]
            cmd += [arg for h in (auth.headers or {}).items()
                    for arg in ("-H", f"{h[0]}: {h[1]}")]
        else:
            cmd += self.auth_args(target)
        return cmd

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        _sec = secrets_of(target.auth)
        raw = self._read(os.path.join(workdir, "wapiti.json"))
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        findings: List[Finding] = []
        classifications = data.get("classifications", {})
        for category, items in data.get("vulnerabilities", {}).items():
            for it in items:
                sev = _sev_from_level(it.get("level", 1))
                findings.append(Finding(
                    title=category,
                    severity=sev,
                    engine=self.name,
                    target=target.label,
                    description=classifications.get(category, {}).get("desc", ""),
                    location=it.get("path", target.endpoint()),
                    evidence=it.get("parameter", "") or it.get("info", ""),
                    cwe=_CWE.get(category),
                    references=list(classifications.get(category, {}).get("ref", {}).values()),
                    remediation=classifications.get(category, {}).get("sol", ""),
                    # wapiti stores the full curl line, auth headers included
                    raw={"http_request": redact_text(
                             it.get("http_request", "")[:500], _sec),
                         "curl": redact_text(it.get("curl_command", ""), _sec)},
                ))
        return findings

    def _ok_returncodes(self):
        return (0, 1, 2, 3, 4)


def _sev_from_level(level) -> str:
    return {1: "low", 2: "medium", 3: "high", 4: "critical"}.get(int(level or 1), "low")
