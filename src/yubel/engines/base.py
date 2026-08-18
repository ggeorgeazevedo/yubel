"""Base class every engine adapter inherits from.

An adapter is a thin, well-behaved wrapper around an external OSS tool. It:
  1. declares which TargetTypes it supports,
  2. reports whether the underlying binary is available,
  3. builds and runs a command in a temp workdir,
  4. parses the tool's native output into normalized Findings.

Adapters must never raise on a scanning error: they capture it in EngineRun.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from typing import List, Optional, Tuple

from ..models import EngineRun, Finding, Target, TargetType
from ..redact import redact_argv, secrets_of


class Engine:
    #: unique short id, e.g. "nuclei"
    name: str = "base"
    #: human category shown in reports
    category: str = "generic"
    #: TargetTypes this engine can handle
    supports: Tuple[TargetType, ...] = ()
    #: the binary we look for on PATH
    binary: str = ""
    #: default wall-clock timeout (seconds); overridable via config
    default_timeout: int = 900
    #: url the engine came from (for the manifest / credits)
    homepage: str = ""

    def __init__(self, options: Optional[dict] = None):
        self.options = options or {}

    # ---- capability / availability -------------------------------------
    def available(self) -> bool:
        """True if the engine can actually run in this environment."""
        if not self.binary:
            return True
        return shutil.which(self.binary) is not None

    def handles(self, target: Target) -> bool:
        return target.type in self.supports

    def unavailable_reason(self) -> str:
        """Human message when the engine can't run. Subclasses override for
        clarity (e.g. ZAP resolves scripts, not a single binary)."""
        return f"binary '{self.binary}' not found on PATH"

    # ---- command construction (implemented by subclasses) --------------
    # subclasses may take extra keyword args (e.g. nuclei's `dast`, dalfox's
    # `url`), so the base accepts *args/**kwargs to stay signature-compatible.
    def build_command(self, target: Target, workdir: str, *args, **kwargs) -> List[str]:
        raise NotImplementedError

    def parse(self, target: Target, workdir: str, stdout: str,
              *args, **kwargs) -> List[Finding]:
        raise NotImplementedError

    # ---- execution ------------------------------------------------------
    def timeout(self) -> int:
        return int(self.options.get("timeout", self.default_timeout))

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

        workdir = tempfile.mkdtemp(prefix=f"yubel-{self.name}-")
        try:
            cmd = self.build_command(target, workdir)
            # never let the operator's own credentials into yubel.json
            rec.command = redact_argv(cmd, secrets_of(target.auth))
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout(),
                cwd=workdir,
                env={**os.environ, "NO_COLOR": "1"},
            )
            findings = self.parse(target, workdir, proc.stdout)
            rec.findings = len(findings)
            if proc.returncode not in self._ok_returncodes() and not findings:
                # a hard failure that produced nothing is an error, not a clean
                # scan — never report a broken run as "ok" (false assurance).
                tail = (proc.stderr or proc.stdout or "").strip().splitlines()
                rec.status = "error"
                rec.message = tail[-1] if tail else f"exit={proc.returncode}"
            else:
                # scanners routinely exit non-zero when they *find* issues.
                rec.status = "ok"
            rec.finished_at = time.time()
            return findings, rec
        except subprocess.TimeoutExpired:
            rec.status = "timeout"
            rec.message = f"exceeded {self.timeout()}s"
            rec.finished_at = time.time()
            return [], rec
        except FileNotFoundError as e:
            rec.status = "skipped"
            rec.message = str(e)
            rec.finished_at = time.time()
            return [], rec
        except Exception as e:  # never let one engine kill the whole scan
            rec.status = "error"
            rec.message = f"{type(e).__name__}: {e}"
            rec.finished_at = time.time()
            return [], rec
        finally:
            if not self.options.get("keep_workdir"):
                shutil.rmtree(workdir, ignore_errors=True)

    def _ok_returncodes(self) -> Tuple[int, ...]:
        return (0,)

    # ---- helpers --------------------------------------------------------
    @staticmethod
    def _read(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                return fh.read()
        except (OSError, IOError):
            return ""
