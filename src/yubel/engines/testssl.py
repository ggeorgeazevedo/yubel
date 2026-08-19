"""testssl.sh adapter — dynamic TLS/SSL/mTLS/cipher assessment.

Relevant for every https target: web, api, cloud, ingress, service mesh edge.
"""
from __future__ import annotations

import json
import os
from typing import List
from urllib.parse import urlparse

from ..models import Finding, Target, TargetType
from .base import Engine


class TestSSLEngine(Engine):
    name = "testssl"
    category = "TLS / transport security"
    supports = (TargetType.WEB, TargetType.API, TargetType.GRAPHQL,
                TargetType.CLOUD, TargetType.HOST, TargetType.CONTAINER)
    binary = "testssl.sh"
    default_timeout = 600
    homepage = "https://testssl.sh/"

    def available(self) -> bool:
        import shutil
        return shutil.which("testssl.sh") is not None or shutil.which("testssl") is not None

    def _bin(self):
        import shutil
        return "testssl.sh" if shutil.which("testssl.sh") else "testssl"

    def _hostport(self, target: Target) -> str:
        ep = target.endpoint()
        if ep.startswith("http"):
            u = urlparse(ep)
            port = u.port or (443 if u.scheme == "https" else 80)
            return f"{u.hostname}:{port}"
        return ep

    def build_command(self, target: Target, workdir: str) -> List[str]:
        out = os.path.join(workdir, "testssl.json")
        return [self._bin(), "--jsonfile", out, "--quiet", "--warnings", "off",
                "--severity", self.options.get("severity", "LOW"),
                self._hostport(target)]

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        raw = self._read(os.path.join(workdir, "testssl.json"))
        if not raw:
            return []
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError:
            return []

        # Does the target actually speak TLS? When scanning a plain-HTTP port
        # (e.g. a dev server on :3000) testssl reports every protocol and cipher
        # list as "not offered" and "no forward secrecy" — those "absence of TLS"
        # rows are noise, not misconfigurations, and are suppressed below. A real
        # weakness (expired cert, BEAST, an offered-but-obsolete protocol, …) is
        # still reported.
        proto_ids = {"sslv2", "sslv3", "tls1", "tls1_1", "tls1_2", "tls1_3"}
        tls_offered = any(
            str(r.get("id", "")).lower() in proto_ids
            and "offered" in str(r.get("finding", "")).lower()
            and "not offered" not in str(r.get("finding", "")).lower()
            for r in rows
        )

        findings: List[Finding] = []
        for r in rows:
            sev = str(r.get("severity", "INFO")).upper()
            if sev in ("OK", "INFO", "DEBUG", "WARN"):
                continue
            # operational problems are NOT vulnerabilities — drop the noise
            # (e.g. scanning an HTTP-only host, connection refused, no TLS)
            rid = str(r.get("id", "")).lower()
            finding_txt = str(r.get("finding", "")).lower()
            if sev in ("SCANPROBLEM", "FATAL", "ERROR") or rid in (
                    "scanproblem", "engine_problem", "service", "pre_128cipher"):
                continue
            if any(p in finding_txt for p in (
                    "can't connect", "cannot connect", "connection refused",
                    "make sure a firewall", "not open", "service detected",
                    "doesn't seem to be a tls", "scan interrupted")):
                continue
            # drop the per-cipher enumeration (id like "cipher-tls1_2_x33"):
            # it's testssl listing every supported cipher, not a finding. The
            # real signal is captured by cipherlist_*, cipher_order, BEAST, etc.
            if rid.startswith("cipher-"):
                continue
            # when the host has no TLS at all, drop the "not offered" / "no FS"
            # rows — they only mean "this isn't an HTTPS endpoint", not a flaw
            if not tls_offered and (
                    ("not offered" in finding_txt
                     and (rid in proto_ids or rid.startswith("cipherlist")))
                    or (rid == "fs" and "forward secrecy" in finding_txt)):
                continue
            findings.append(Finding(
                title=f"TLS: {r.get('id', 'issue')}",
                severity=sev,
                engine=self.name,
                target=target.label,
                description=r.get("finding", ""),
                location=r.get("ip", self._hostport(target)),
                cve=r.get("cve") or None,
                cwe=r.get("cwe", "").replace("CWE-", "") or None,
                raw={"id": r.get("id")},
            ))
        return findings

    #: testssl.sh reserves 242-255 for hard errors and uses everything below
    #: for normal outcomes (0 = all ok, plus the severity level of the worst
    #: finding). Source: `declare -r ERR_*` at testssl.sh:75-88 — ERR_CHILD is
    #: the lowest at 242. The previous `range(0, 250)` swallowed ERR_CONNECT
    #: (246), ERR_DNSLOOKUP (247) and ERR_RESOURCE (244): a testssl that never
    #: reached the target, or could not read its own data files, reported
    #: `ok (0 findings)` — a clean bill of health for a scan that never ran.
    _ERR_FLOOR = 242

    def _ok_returncodes(self):
        return tuple(range(0, self._ERR_FLOOR))
