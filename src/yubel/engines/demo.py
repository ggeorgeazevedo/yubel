"""A synthetic engine used only by `yubel selftest`.

It produces representative findings without touching the network, so the
pipeline, de-duplication and every reporter can be validated in CI and on a
fresh checkout even when no scanning binaries are installed.
"""
from __future__ import annotations

from typing import List

from ..models import Finding, Target, TargetType
from .base import Engine


class DemoEngine(Engine):
    name = "demo"
    category = "synthetic (selftest only)"
    supports = tuple(TargetType)
    binary = ""  # always "available"
    homepage = "https://github.com/ggeorgeazevedo/yubel"
    offline_ok = True
    offline_note = "synthetic: no process, no network"

    def handles(self, target: Target) -> bool:
        return True

    def run(self, target: Target):
        from ..models import EngineRun
        import time
        rec = EngineRun(engine=self.name, target=target.label, command="(synthetic)")
        rec.started_at = time.time()
        findings = self._samples(target)
        rec.status = "ok"
        rec.findings = len(findings)
        rec.finished_at = time.time()
        return findings, rec

    def _samples(self, target: Target) -> List[Finding]:
        return [
            Finding(title="SQL Injection", severity="high", engine=self.name,
                    target=target.label, description="Boolean-based blind SQLi in 'id'.",
                    location=f"{target.endpoint()}/items?id=1", cwe="89",
                    remediation="Use parameterized queries.",
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"]),
            Finding(title="Reflected Cross-Site Scripting", severity="medium",
                    engine=self.name, target=target.label, cwe="79",
                    location=f"{target.endpoint()}/search?q=<script>",
                    description="User input reflected without encoding."),
            Finding(title="Missing Strict-Transport-Security header", severity="low",
                    engine=self.name, target=target.label, cwe="319",
                    location=target.endpoint(),
                    description="HSTS not set; downgrade attacks possible."),
            Finding(title="Server version disclosed", severity="info",
                    engine=self.name, target=target.label,
                    location=target.endpoint(), description="Server header leaks version."),
        ]
