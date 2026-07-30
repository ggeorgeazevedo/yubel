"""Discovery engines: katana (crawler) and httpx (probing).

These do not emit vulnerabilities themselves; they enrich a target's attack
surface (endpoints / live services) and record them as INFO findings that are
useful context and can seed other engines. Kept lightweight and non-intrusive.
"""
from __future__ import annotations

import json
import os
from typing import List

from ..models import Finding, Target, TargetType
from .base import Engine


class KatanaEngine(Engine):
    name = "katana"
    category = "crawler / attack-surface discovery"
    supports = (TargetType.WEB, TargetType.API, TargetType.CLOUD)
    binary = "katana"
    default_timeout = 600
    homepage = "https://github.com/projectdiscovery/katana"

    def build_command(self, target: Target, workdir: str) -> List[str]:
        out = os.path.join(workdir, "katana.jsonl")
        cmd = [self.binary, "-u", target.endpoint(), "-jsonl", "-o", out,
               "-silent", "-d", str(self.options.get("depth", 2))]
        # -jc: parse endpoints out of in-page JavaScript (essential for SPAs like
        #      Angular/React, where routes and API paths live in the JS bundle);
        # -kf: pull known files (robots.txt / sitemap.xml) for extra surface.
        if self.options.get("js_crawl", True):
            cmd += ["-jc"]
        if self.options.get("known_files", True):
            cmd += ["-kf", "all"]
        if self.options.get("headless"):
            cmd += ["-headless", "-no-sandbox"]
        return cmd

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        text = self._read(os.path.join(workdir, "katana.jsonl")) or stdout
        urls, seen = [], set()
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if o.get("error"):          # failed request, not a real endpoint
                    continue
                # katana ≥ v1 nests the URL under "request"; older builds and the
                # plain (-o) output put it at the top level — support both.
                req = o.get("request") or {}
                ep = req.get("endpoint") or o.get("endpoint") or ""
            elif line.startswith("http"):
                ep = line
            else:
                continue
            if ep and ep not in seen:
                seen.add(ep)
                urls.append(ep)
        if not urls:
            return []
        # write surface to workdir sibling for other tooling / debugging
        return [Finding(
            title=f"Attack surface: {len(urls)} endpoints discovered",
            severity="info",
            engine=self.name,
            target=target.label,
            description="Crawled endpoints (context for dynamic testing).",
            location=target.endpoint(),
            evidence="\n".join(urls[:50]),
            raw={"endpoints": urls[:500]},
            confidence="high",
        )]

    def _ok_returncodes(self):
        return (0, 1)


class HttpxEngine(Engine):
    name = "httpx"
    category = "service probing / fingerprint"
    supports = (TargetType.WEB, TargetType.API, TargetType.CLOUD,
                TargetType.HOST, TargetType.CONTAINER)
    binary = "httpx"
    default_timeout = 300
    homepage = "https://github.com/projectdiscovery/httpx"

    def build_command(self, target: Target, workdir: str) -> List[str]:
        out = os.path.join(workdir, "httpx.jsonl")
        return [self.binary, "-u", target.endpoint(), "-json", "-o", out,
                "-silent", "-title", "-tech-detect", "-status-code",
                "-server", "-tls-grab"]

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        text = self._read(os.path.join(workdir, "httpx.jsonl")) or stdout
        findings: List[Finding] = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            tech = ", ".join(o.get("tech", []) or [])
            findings.append(Finding(
                title=f"Live service: {o.get('status_code', '')} {o.get('title', '')}".strip(),
                severity="info",
                engine=self.name,
                target=target.label,
                description=f"Server={o.get('webserver', '')}; Tech={tech}",
                location=o.get("url", target.endpoint()),
                raw={"status": o.get("status_code"), "tech": o.get("tech")},
                confidence="high",
            ))
        return findings

    def _ok_returncodes(self):
        return (0, 1)
