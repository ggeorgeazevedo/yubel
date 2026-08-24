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
    offline_ok = True
    #: ZAP's own help: "-silent  Ensures ZAP does not make any unsolicited
    #: requests, including 'check for updates'". It reaches the daemon
    #: through the wrapper's -z passthrough.
    #:
    #: It is not free. The wrappers read their own arguments and skip
    #: `-addonupdate -addoninstall pscanrulesBeta` when -silent is present,
    #: so an offline ZAP run has fewer passive rules than an online one and
    #: can therefore report fewer findings. That is the honest trade and it
    #: is written in the docs: air-gapped means air-gapped, including the
    #: part where you do not download rules mid-scan.
    offline_args = ("-z", "-silent")
    offline_note = ("-z -silent stops all unsolicited requests; note it also "
                    "skips the beta passive rules the wrapper would install")

    #: Every web entrypoint, for the availability probe. Which one actually
    #: runs is decided by `mode`, not by this order.
    WEB_SCRIPTS = ("zap-baseline.py", "zap-full-scan.py")
    API_SCRIPTS = ("zap-api-scan.py",)

    #: `mode` -> scripts in the order we would like to use them.
    #:
    #: `baseline` is the default, and it is the passive spider: it crawls and
    #: reports what it observes. `full` is `zap-full-scan.py`, which actively
    #: attacks the target.
    #:
    #: This used to key off `mode == "baseline"` with everything else falling
    #: through to the full scan — so the *default* was the active scan, while
    #: `docs/engines.md` and SECURITY.md's "safe defaults" both said passive.
    #: Pointing Yubel at production on defaults attacked it. A DAST tool that
    #: attacks by default has to say so; this one said the opposite, so the
    #: code moved rather than the promise.
    MODES = {
        "baseline": ("zap-baseline.py", "zap-full-scan.py"),
        "full": ("zap-full-scan.py",),
    }
    DEFAULT_MODE = "baseline"

    @classmethod
    def option_errors(cls, options: dict) -> List[str]:
        mode = options.get("mode")
        if mode is None:
            return []
        if str(mode).strip().lower() in cls.MODES:
            return []
        return [f"options.zap.mode: unknown value {mode!r} "
                f"(expected {' or '.join(sorted(cls.MODES))}); "
                f"an unrecognised mode would silently run the "
                f"{cls.DEFAULT_MODE} scan"]

    def _script(self, target: Target) -> str:
        candidates = self.API_SCRIPTS if target.type in (
            TargetType.API, TargetType.GRAPHQL) else self._web_scripts()
        for c in candidates:
            if shutil.which(c):
                return c
        return ""

    def _web_scripts(self):
        """Scripts to try for a web target, most-preferred first.

        `full` deliberately does NOT fall back to the baseline script: asking
        for an active scan and silently getting a passive one is the failure
        this project keeps removing. With no full-scan script installed the
        run is recorded as skipped, which is the honest answer.
        """
        mode = str(self.options.get("mode", self.DEFAULT_MODE)).strip().lower()
        return self.MODES.get(mode, self.MODES[self.DEFAULT_MODE])

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
        return cmd + self.offline_flags()

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
                # `alert.get("instances", [{}])` returns [] when the key is
                # present and empty, so the default never fires; and `.get(k, d)`
                # keeps an empty `uri` for the same reason. Neither path ended
                # at the target, so a ZAP finding could carry no address.
                instances = alert.get("instances") or [{}]
                loc = (instances[0].get("uri") or site.get("@name")
                       or target.endpoint())
                findings.append(Finding(
                    title=alert.get("alert", alert.get("name", "ZAP alert")),
                    severity=alert.get("riskcode", alert.get("riskdesc", "0")),
                    engine=self.name,
                    target=target.label,
                    description=_strip_html(alert.get("desc", "")),
                    location=loc,
                    evidence=instances[0].get("evidence", ""),
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
