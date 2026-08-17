"""dalfox adapter — fast, parameter-aware XSS scanner.

dalfox 3.x rewrote the CLI (the URL is now `--url <URL>` instead of a positional
argument), so the adapter detects the major version and builds the right command
for both the 2.x and 3.x families.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import List, Tuple

from ..models import EngineRun, Finding, Target, TargetType
from ..redact import redact_argv, secrets_of
from .base import Engine


class DalfoxEngine(Engine):
    name = "dalfox"
    category = "XSS"
    supports = (TargetType.WEB, TargetType.API)
    binary = "dalfox"
    default_timeout = 900
    homepage = "https://github.com/hahwul/dalfox"

    _major = None  # cached detected major version

    def _major_version(self) -> int:
        if self._major is None:
            try:
                out = subprocess.run([self.binary, "--version"],
                                     capture_output=True, text=True, timeout=10)
                m = re.search(r"(\d+)\.\d+", (out.stdout + out.stderr))
                DalfoxEngine._major = int(m.group(1)) if m else 2
            except Exception:
                DalfoxEngine._major = 2
        return self._major

    def run(self, target: Target) -> Tuple[List[Finding], EngineRun]:
        """dalfox only tests URLs that carry parameters. When the discovery
        phase surfaced parameterized URLs we scan each of them (capped); with no
        discovery we fall back to the seed endpoint, exactly as before."""
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

        urls = target.param_urls(int(self.options.get("max_urls", 25))) \
            or [target.endpoint()]
        findings: List[Finding] = []
        cmds: List[str] = []
        errors: List[str] = []
        any_ok = False
        for url in urls:
            fs, cmd, err = self._scan_url(target, url)
            findings.extend(fs)
            cmds.append(cmd)
            if err:
                errors.append(err)
            else:
                any_ok = True
        rec.command = cmds[0] + (f"   (+{len(cmds) - 1} more URL(s))"
                                 if len(cmds) > 1 else "")
        rec.findings = len(findings)
        rec.status = "ok" if any_ok else (
            "timeout" if any("timeout" in e for e in errors) else "error")
        if errors and not findings:
            rec.message = errors[-1]
        rec.finished_at = time.time()
        return findings, rec

    def _scan_url(self, target: Target, url: str) -> Tuple[List[Finding], str, str]:
        workdir = tempfile.mkdtemp(prefix="yubel-dalfox-")
        try:
            cmd = self.build_command(target, workdir, url)
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout(),
                cwd=workdir, env={**os.environ, "NO_COLOR": "1"})
            fs = self.parse(target, workdir, proc.stdout)
            if proc.returncode not in self._ok_returncodes() and not fs:
                tail = (proc.stderr or proc.stdout or "").strip().splitlines()
                return [], redact_argv(cmd, secrets_of(target.auth)), (
                    tail[-1] if tail else f"exit={proc.returncode}")
            return fs, redact_argv(cmd, secrets_of(target.auth)), ""
        except subprocess.TimeoutExpired:
            return [], "dalfox", f"timeout {self.timeout()}s"
        except FileNotFoundError as e:
            return [], "dalfox", str(e)
        except Exception as e:
            return [], "dalfox", f"{type(e).__name__}: {e}"
        finally:
            if not self.options.get("keep_workdir"):
                shutil.rmtree(workdir, ignore_errors=True)

    def build_command(self, target: Target, workdir: str,
                      url: str = None) -> List[str]:
        url = url or target.endpoint()
        if self._major_version() >= 3:
            # dalfox 3.x: URL is a named argument, JSON goes to stdout
            cmd = [self.binary, "url", "--url", url, "--format", "json", "--silence"]
            if target.auth.kind == "bearer" and target.auth.token:
                cmd += ["--header", f"Authorization: Bearer {target.auth.token}"]
        else:
            # dalfox 2.x: positional URL
            cmd = [self.binary, "url", url, "--format", "json", "--silence"]
            if target.auth.kind == "bearer" and target.auth.token:
                cmd += ["-H", f"Authorization: Bearer {target.auth.token}"]
        return cmd

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        findings: List[Finding] = []
        text = (self._read(os.path.join(workdir, "dalfox.json")) or stdout or "").strip()
        objs = _extract_objs(text)
        for o in objs:
            if not isinstance(o, dict):
                continue
            findings.append(Finding(
                title=f"XSS ({o.get('type', 'reflected')})",
                severity=_sev(o.get("severity", "high")),
                engine=self.name,
                target=target.label,
                description=o.get("message") or o.get("message_str")
                    or "Cross-site scripting",
                location=(o.get("url") or o.get("data") or o.get("param")
                          or target.endpoint()),
                evidence=(o.get("evidence") or o.get("poc")
                          or o.get("payload") or ""),
                param=str(o.get("param") or ""),
                payload=str(o.get("payload") or o.get("data") or ""),
                request=str(o.get("poc") or ""),   # dalfox PoC is the reproducing URL
                cwe="79",
                confidence="high",
                references=["https://owasp.org/www-community/attacks/xss/"],
                raw={"param": o.get("param")},
            ))
        return findings

    def _ok_returncodes(self):
        return (0, 1)


def _extract_objs(text: str) -> List[dict]:
    """Return the list of finding objects across dalfox output formats:
    - v3: a single object `{"findings": [...], "meta": {...}}`
    - v2: a JSON array `[...]`, or JSONL (one object per line)."""
    text = (text or "").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            if isinstance(parsed.get("findings"), list):   # v3 wrapper
                return parsed["findings"]
            # a bare single-finding object (not the meta wrapper)
            if any(k in parsed for k in ("type", "payload", "param", "data")):
                return [parsed]
            return []
        if isinstance(parsed, list):                        # v2 array
            return parsed
    except json.JSONDecodeError:
        objs = []
        for line in text.splitlines():                      # v2 JSONL
            line = line.strip()
            if line.startswith("{"):
                try:
                    objs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return objs
    return []


def _sev(s: str) -> str:
    return str(s or "high").lower()
