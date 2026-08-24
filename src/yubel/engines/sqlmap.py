"""sqlmap adapter — targeted SQL injection confirmation.

Off by default in broad scans (it is intrusive/slow); enable per-target when a
crawler/other engine flags an injectable parameter, or point it at a URL.
"""
from __future__ import annotations

from typing import List

from ..models import Finding, Target, TargetType
from .base import Engine


class SqlmapEngine(Engine):
    name = "sqlmap"
    category = "SQL injection (confirm/exploit)"
    supports = (TargetType.WEB, TargetType.API)
    binary = "sqlmap"
    header_flag = "-H"
    default_timeout = 1200
    homepage = "https://sqlmap.org/"
    #: Same reasoning as dalfox: no verified switch, so it is skipped rather
    #: than run under a promise nobody checked. sqlmap is opt-in anyway, so
    #: this combination is rare — but it used not to receive the offline
    #: option at all, which is worse than being skipped: it ran, and nothing
    #: said so.
    offline_ok = False
    offline_note = "no update-check switch could be verified"
    #: opt-in only — intrusive
    opt_in = True

    def build_command(self, target: Target, workdir: str) -> List[str]:
        cmd = [self.binary, "-u", target.endpoint(),
               "--batch", "--disable-coloring", "--flush-session",
               "--level", str(self.options.get("level", 1)),
               "--risk", str(self.options.get("risk", 1)),
               "--output-dir", workdir]
        cmd += self.auth_args(target)
        if self.options.get("data"):
            cmd += ["--data", self.options["data"]]
        return cmd

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        findings: List[Finding] = []
        # sqlmap writes a target log; the simplest robust signal is stdout.
        text = stdout or ""
        if "is vulnerable" in text or "injectable" in text.lower() or \
                "sqlmap identified the following injection point" in text.lower():
            findings.append(Finding(
                title="SQL Injection confirmed",
                severity="high",
                engine=self.name,
                target=target.label,
                description="sqlmap confirmed an injectable parameter.",
                location=target.endpoint(),
                evidence=_extract_evidence(text),
                cwe="89",
                confidence="high",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            ))
        return findings

    def _ok_returncodes(self):
        return (0, 1)


def _extract_evidence(text: str) -> str:
    keys = ("Parameter", "Type:", "Payload:")
    lines = [ln for ln in text.splitlines() if any(k in ln for k in keys)]
    return "\n".join(lines[:8])
