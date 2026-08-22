"""GraphQL DAST: graphw00f (engine fingerprint) + graphql-cop (security audit)."""
from __future__ import annotations

import json
import shutil
from typing import List

from ..models import Finding, Target, TargetType
from .base import Engine


class GraphwoofEngine(Engine):
    name = "graphw00f"
    category = "GraphQL fingerprint"
    supports = (TargetType.GRAPHQL,)
    binary = "graphw00f"
    default_timeout = 180
    homepage = "https://github.com/dolevf/graphw00f"

    def available(self) -> bool:
        return shutil.which("graphw00f") is not None

    def build_command(self, target: Target, workdir: str) -> List[str]:
        return [self.binary, "-f", "-d", "-t", target.endpoint()]

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        text = stdout or ""
        findings: List[Finding] = []
        for line in text.splitlines():
            if "Discovered GraphQL Engine" in line or "Attack Surface" in line:
                findings.append(Finding(
                    title="GraphQL engine fingerprinted",
                    severity="info", engine=self.name, target=target.label,
                    description=line.strip(), location=target.endpoint(),
                    confidence="high",
                ))
        return findings

    def _ok_returncodes(self):
        return (0, 1)


class GraphqlCopEngine(Engine):
    name = "graphql-cop"
    category = "GraphQL security audit"
    supports = (TargetType.GRAPHQL,)
    binary = "graphql-cop"
    header_flag = "-H"
    # graphql-cop parses -H with json.loads() and, on failure, prints a line
    # and carries on scanning — so a colon-style header does not fail the run,
    # it just silently drops the credentials.
    header_style = "json"
    default_timeout = 300
    homepage = "https://github.com/dolevf/graphql-cop"

    def available(self) -> bool:
        return shutil.which("graphql-cop") is not None

    def build_command(self, target: Target, workdir: str) -> List[str]:
        cmd = [self.binary, "-t", target.endpoint(), "-o", "json"]
        cmd += self.auth_args(target)
        return cmd

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        text = (stdout or "").strip()
        findings: List[Finding] = []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return findings
        for item in (data if isinstance(data, list) else data.get("results", [])):
            if not isinstance(item, dict):
                continue
            vulnerable = item.get("result") in (True, "true", "True")
            sev = _sev(item.get("severity", "LOW")) if vulnerable else "info"
            if not vulnerable:
                continue
            findings.append(Finding(
                title=item.get("title", "GraphQL issue"),
                severity=sev, engine=self.name, target=target.label,
                description=item.get("description", ""),
                location=item.get("curl_verify", target.endpoint()),
                remediation=item.get("remediation", ""),
                confidence="medium",
            ))
        return findings

    def _ok_returncodes(self):
        return (0, 1)


def _sev(s: str) -> str:
    m = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
    return m.get(str(s).upper(), "low")
