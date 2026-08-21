"""Spec-driven API DAST: schemathesis (OpenAPI/GraphQL property testing)."""
from __future__ import annotations

import json
import os
from typing import List

from ..models import Finding, Target, TargetType
from .base import Engine


class SchemathesisEngine(Engine):
    name = "schemathesis"
    category = "API property-based fuzzing"
    supports = (TargetType.API, TargetType.GRAPHQL)
    binary = "schemathesis"
    header_flag = "-H"
    default_timeout = 1200
    homepage = "https://github.com/schemathesis/schemathesis"

    def available(self) -> bool:
        import shutil
        return shutil.which("schemathesis") is not None or shutil.which("st") is not None

    def _bin(self):
        import shutil
        return "schemathesis" if shutil.which("schemathesis") else "st"

    def build_command(self, target: Target, workdir: str) -> List[str]:
        spec = target.openapi or target.endpoint()
        report = os.path.join(workdir, "st.json")
        cmd = [self._bin(), "run", spec,
               "--checks", "all",
               "--report", "json", "--report-json-path", report,
               "--hypothesis-max-examples", str(self.options.get("examples", 50))]
        base = self.options.get("base_url") or (target.url if target.openapi else None)
        if base:
            cmd += ["--base-url", base]
        cmd += self.auth_args(target)
        return cmd

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        raw = self._read(os.path.join(workdir, "st.json"))
        findings: List[Finding] = []
        if raw:
            try:
                data = json.loads(raw)
                for res in _iter_failures(data):
                    findings.append(Finding(
                        title=f"API contract/security failure: {res.get('check', 'check')}",
                        severity="medium",
                        engine=self.name,
                        target=target.label,
                        description=res.get("message", "")[:800],
                        location=res.get("path", target.endpoint()),
                        evidence=res.get("example", ""),
                        cwe="20",
                        confidence="medium",
                    ))
            except json.JSONDecodeError:
                # malformed JSON report — fall through to the stdout summary below
                findings = []
        # fallback: parse stdout summary if JSON report absent
        if not findings and stdout and "FAILED" in stdout:
            findings.append(Finding(
                title="API failures detected by schemathesis",
                severity="medium", engine=self.name, target=target.label,
                description=_tail(stdout), location=target.endpoint(),
                confidence="low",
            ))
        return findings

    def _ok_returncodes(self):
        return (0, 1)


def _iter_failures(data):
    # schemathesis report structure varies by version; walk defensively
    if isinstance(data, dict):
        for key in ("results", "failures", "checks"):
            for item in data.get(key, []) or []:
                if isinstance(item, dict):
                    if item.get("status") in ("failure", "error") or item.get("check"):
                        yield item
                    for sub in item.get("checks", []) or []:
                        if isinstance(sub, dict) and sub.get("status") in ("failure", "error"):
                            yield sub


def _tail(s: str, n: int = 15) -> str:
    return "\n".join(s.strip().splitlines()[-n:])
