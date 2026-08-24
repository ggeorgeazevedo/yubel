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
    header_flag = "-H"
    default_timeout = 900
    homepage = "https://github.com/projectdiscovery/nuclei"
    offline_ok = True
    #: placed by build_command_for, which also decides between -duc alone and
    #: -ni -duc depending on where the templates come from.
    offline_args = ("-ni", "-duc")
    offline_note = ("-ni disables OAST/interactsh callbacks, -duc the "
                    "template update check")

    def run(self, target: Target) -> Tuple[List[Finding], EngineRun]:
        rec = EngineRun(engine=self.name, target=target.label)
        rec.started_at = time.time()
        reason = self.skip_reason(target)
        if reason:
            rec.status = "skipped"
            rec.message = reason
            rec.finished_at = time.time()
            return [], rec
        rec.tool_version = self.tool_version()

        passes = self.passes()

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
            cmd = self.build_command_for(target, workdir, dast)
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout(),
                cwd=workdir, env={**os.environ, "NO_COLOR": "1"})
            fs = self.parse_for(target, workdir, proc.stdout, dast)
            shown = redact_argv(cmd, secrets_of(target.auth))
            if proc.returncode not in self._ok_returncodes() and not fs:
                # same rule as Engine.run(): a hard failure that produced
                # nothing is an error, not a clean scan. This class overrides
                # run() and the check was lost in the copy.
                tail = (proc.stderr or proc.stdout or "").strip().splitlines()
                return [], shown, (tail[-1] if tail else f"exit={proc.returncode}")
            return fs, shown, ""
        except subprocess.TimeoutExpired:
            return [], "nuclei", f"timeout {self.timeout()}s"
        except FileNotFoundError as e:
            return [], "nuclei", str(e)
        except Exception as e:
            return [], "nuclei", f"{type(e).__name__}: {e}"
        finally:
            if not self.options.get("keep_workdir"):
                shutil.rmtree(workdir, ignore_errors=True)

    def passes(self) -> List[bool]:
        """Which nuclei invocations this configuration asks for.

        `False` is the full-template pass, `True` the parameter-fuzzing (dast)
        pass. Disabling both would mean running nothing at all and reporting a
        clean scan, so that case falls back to the full pass.

        This is a method rather than inline logic because it is exactly what
        `--fast` and the `full`/`dast` options control, and a test that
        reimplements the rule locally only ever tests its own copy.
        """
        selected = []
        if self.options.get("full", True):
            selected.append(False)
        if self.options.get("dast", True):
            selected.append(True)
        return selected or [False]

    def handles(self, target: Target) -> bool:
        """Supporting the target type is not enough — there has to be a URL.

        A `kubernetes` target is exempt from the endpoint check in
        `Config.validate()` (kube-hunter reaches a cluster without one), and
        `handles()` used to look only at the type. So the Kubernetes Job this
        project ships ran `nuclei -u ''` on every scan and reported it as a
        normal, finding-free run. nuclei covers a cluster *via its ingress*,
        which means it needs the ingress URL.
        """
        return super().handles(target) and bool(target.endpoint())

    def build_command(self, target: Target, workdir: str) -> List[str]:
        """The base contract: the full-template pass."""
        return self.build_command_for(target, workdir, dast=False)

    def build_command_for(self, target: Target, workdir: str,
                          dast: bool = False) -> List[str]:
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
        elif os.environ.get("NUCLEI_TEMPLATES_DIR"):
            # The templates were provisioned ahead of time (the container image
            # bakes them into a read-only path). Letting nuclei run its update
            # check then means an unexpected outbound call at scan time and a
            # write into a directory that is deliberately not writable — on the
            # documented Kubernetes Job, with `readOnlyRootFilesystem: true`,
            # that write fails and the pass runs with whatever it can reach.
            cmd += ["-duc"]
        if self.options.get("rate_limit"):
            cmd += ["-rl", str(self.options["rate_limit"])]
        cmd += self.auth_args(target)
        extra = self.options.get("extra_args")
        if extra:
            # accept either a list or a shell-style string (avoid list("...")
            # exploding a string into individual characters)
            if isinstance(extra, str):
                import shlex
                extra = shlex.split(extra)
            cmd += list(extra)
        return cmd

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        """The base contract: the full-template pass."""
        return self.parse_for(target, workdir, stdout, dast=False)

    def parse_for(self, target: Target, workdir: str, stdout: str,
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
            # `.get(k, default)` returns "" when the key is present and
            # empty, so the host fallback never fired; and neither branch
            # ended at the target, so a finding could be born with no
            # address at all.
            matched = (ev.get("matched-at") or ev.get("host")
                       or target.endpoint())
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
