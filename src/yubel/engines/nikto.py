"""Nikto adapter — classic web server misconfiguration / dangerous file scan."""
from __future__ import annotations

import json
import os
from typing import List

from ..models import Finding, Target, TargetType
from .base import Engine


class NiktoEngine(Engine):
    name = "nikto"
    category = "web server misconfig"
    supports = (TargetType.WEB, TargetType.HOST, TargetType.CONTAINER)
    binary = "nikto"
    default_timeout = 900
    homepage = "https://github.com/sullo/nikto"

    def build_command(self, target: Target, workdir: str) -> List[str]:
        out = os.path.join(workdir, "nikto.json")
        cmd = [self.binary, "-h", target.endpoint(),
               "-Format", "json", "-output", out, "-nointeractive", "-ask", "no"]
        # cap Nikto's runtime so it can't stall a scan for many minutes.
        maxtime = self.options.get("maxtime", 600)   # seconds
        if maxtime:
            cmd += ["-maxtime", f"{int(maxtime)}s"]
        tuning = self.options.get("tuning")
        if tuning:
            cmd += ["-Tuning", str(tuning)]
        return cmd

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        raw = self._read(os.path.join(workdir, "nikto.json"))
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if isinstance(data, list):
            data = data[0] if data else {}
        findings: List[Finding] = []
        for v in data.get("vulnerabilities", []):
            findings.append(Finding(
                title=v.get("msg", "Nikto finding")[:120],
                severity="low",
                engine=self.name,
                target=target.label,
                description=v.get("msg", ""),
                location=(v.get("url") or target.endpoint()),
                references=[f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={v['references']}"]
                    if v.get("references") else [],
                raw={"id": v.get("id"), "method": v.get("method"), "osvdb": v.get("OSVDB")},
                confidence="low",
            ))
        return findings

    def _ok_returncodes(self):
        return (0, 1)
