"""ProjectDiscovery Nuclei adapter.

Nuclei is the workhorse. By default Yubel runs it in TWO passes and merges the
results, because a single mode misses half the value:

  * full pass  — the complete template set (CVEs, exposures, misconfigurations,
    default credentials, tech detection). This is what catches real issues on a
    normal URL.
  * dast pass  — parameter fuzzing (`-dast`): injects into query/body params to
    find reflected/blind SQLi, XSS, SSTI, etc. Only useful when the URL actually
    has parameters.

Either pass can be turned off via options (`full: false` / `dast: false`); the
`--fast` CLI profile runs the dast pass only.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import List, Tuple

from ..models import EngineRun, Finding, Target, TargetType
from ..redact import redact_argv, redact_text, secrets_of
from .base import Engine


class NucleiEngine(Engine):
    name = "nuclei"
    category = "multi (full templates + dast fuzzing)"
    supports = (TargetType.WEB, TargetType.API, TargetType.CLOUD,
                TargetType.KUBERNETES, TargetType.CONTAINER, TargetType.HOST)
    binary = "nuclei"
    default_timeout = 900
    homepage = "https://github.com/projectdiscovery/nuclei"

    def run(self, target: Target) -> Tuple[List[Finding], EngineRun]:
        rec = EngineRun(engine=self.name, target=target.label)
        rec.started_at = time.time()
        if not self.handles(target):
            rec.status = "skipped"
            rec.message = f"does not handle target type {target.type}"
            rec.finished_at = time.time()
            return [], rec
        if not self.available():
            rec.status = "skipped"
            rec.message = self.unavailable_reason()
            rec.finished_at = time.time()
            return [], rec

        passes = []
        if self.options.get("full", True):
            passes.append(False)   # full template set
        if self.options.get("dast", True):
            passes.append(True)    # parameter fuzzing
        if not passes:
            passes = [False]

        findings: List[Finding] = []
        cmds: List[str] = []
        errors: List[str] = []
        any_ok = False
        for dast in passes:
            fs, cmd, err = self._pass(target, dast)
            findings.extend(fs)
            cmds.append(cmd)
            if err:
                errors.append(err)
            else:
                any_ok = True

        rec.command = "  ;  ".join(cmds)
        rec.findings = len(findings)
        rec.status = "ok" if any_ok else ("timeout" if any("timeout" in e for e in errors) else "error")
        if errors and not findings:
            rec.message = errors[-1]
        rec.finished_at = time.time()
        return findings, rec

    def _pass(self, target: Target, dast: bool) -> Tuple[List[Finding], str, str]:
        workdir = tempfile.mkdtemp(prefix="yubel-nuclei-")
        try:
            cmd = self.build_command(target, workdir, dast)
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout(),
                cwd=workdir, env={**os.environ, "NO_COLOR": "1"})
            fs = self.parse(target, workdir, proc.stdout, dast)
            return fs, redact_argv(cmd, secrets_of(target.auth)), ""
        except subprocess.TimeoutExpired:
            return [], "nuclei", f"timeout {self.timeout()}s"
        except FileNotFoundError as e:
            return [], "nuclei", str(e)
        except Exception as e:
            return [], "nuclei", f"{type(e).__name__}: {e}"
        finally:
            if not self.options.get("keep_workdir"):
                shutil.rmtree(workdir, ignore_errors=True)

    def build_command(self, target: Target, workdir: str, dast: bool = False) -> List[str]:
        out = os.path.join(workdir, f"nuclei-{'dast' if dast else 'full'}.jsonl")
        cmd = [self.binary]
        # Full-template pass scans the whole crawled surface; the (expensive)
        # dast fuzzing pass only targets URLs that actually carry parameters —
        # fuzzing a parameter-less URL wastes time and explodes the scan on large
        # crawls. With no discovery this collapses to the seed endpoint as before.
        urls = target.param_urls() if dast else target.scan_urls()
        if not urls:
            urls = [target.endpoint()]
        if len(urls) > 1:
            listfile = os.path.join(workdir, "urls.txt")
            try:
                with open(listfile, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(urls) + "\n")
                cmd += ["-l", listfile]
            except OSError:
                cmd += ["-u", urls[0]]
        else:
            cmd += ["-u", urls[0]]
        cmd += [
            "-jsonl", "-o", out,
            "-silent", "-no-color",
            "-irr",   # include request/response in output = the proof/evidence
            "-severity", self.options.get("severity", "low,medium,high,critical"),
        ]
        if dast:
            cmd += ["-dast"]
        if self.options.get("offline"):
            # air-gapped: no OAST/interactsh callbacks, no update checks
            cmd += ["-ni", "-duc"]
        if self.options.get("rate_limit"):
            cmd += ["-rl", str(self.options["rate_limit"])]
        for h in _auth_headers(target):
            cmd += ["-H", h]
        extra = self.options.get("extra_args")
        if extra:
            # accept either a list or a shell-style string (avoid list("...")
            # exploding a string into individual characters)
            if isinstance(extra, str):
                import shlex
                extra = shlex.split(extra)
            cmd += list(extra)
        return cmd

    def parse(self, target: Target, workdir: str, stdout: str,
              dast: bool = False) -> List[Finding]:
        out = os.path.join(workdir, f"nuclei-{'dast' if dast else 'full'}.jsonl")
        text = self._read(out) or stdout
        _sec = secrets_of(target.auth)
        findings: List[Finding] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = ev.get("info", {})
            matched = ev.get("matched-at", ev.get("host", ""))
            findings.append(Finding(
                title=info.get("name", ev.get("template-id", "Nuclei finding")),
                severity=info.get("severity", "info"),
                engine=self.name,
                target=target.label,
                description=info.get("description", ""),
                location=matched,
                evidence=(ev.get("extracted-results") or [""])[0]
                    if ev.get("extracted-results") else ev.get("matcher-name", ""),
                param=_param_of(ev, matched),
                payload=(ev.get("extracted-results") or [""])[0]
                    if ev.get("extracted-results") else "",
                # -irr echoes back the headers we injected: redact before
                # this reaches yubel.json and the HTML report
                request=_snippet(ev.get("request", ""), 4000, _sec),
                response=_snippet(ev.get("response", ""), 2000, _sec),
                cwe=_first(info.get("classification", {}).get("cwe-id")),
                cve=_first(info.get("classification", {}).get("cve-id")),
                references=info.get("reference") or [],
                remediation=info.get("remediation", ""),
                confidence="high" if (ev.get("request") and ev.get("response")) else "medium",
                raw={"template": ev.get("template-id"), "mode": "dast" if dast else "full"},
            ))
        return findings


def _first(v):
    if isinstance(v, list) and v:
        return v[0]
    return v or None


def _snippet(text: str, limit: int, secrets=()) -> str:
    """Trim raw HTTP request/response to a readable, bounded proof snippet."""
    text = redact_text(text or "", secrets).strip()
    if len(text) > limit:
        return text[:limit].rstrip() + "\n…(truncated)"
    return text


def _param_of(ev: dict, matched: str) -> str:
    """Best-effort vulnerable-parameter extraction: nuclei's fuzzing metadata
    first, then the query-string key of the matched URL."""
    meta = ev.get("meta") or {}
    for k in ("parameter", "param", "fuzzing_parameter"):
        if meta.get(k):
            return str(meta[k])
    if "?" in (matched or "") and "=" in matched:
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(matched).query)
        if qs:
            return next(iter(qs))
    return ""


def _auth_headers(target: Target) -> List[str]:
    a = target.auth
    hs = []
    if a.kind == "bearer" and a.token:
        hs.append(f"Authorization: Bearer {a.token}")
    if a.kind == "header":
        for k, v in a.headers.items():
            hs.append(f"{k}: {v}")
    if a.kind == "cookie" and a.token:
        hs.append(f"Cookie: {a.token}")
    return hs
