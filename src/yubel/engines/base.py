"""Base class every engine adapter inherits from.

An adapter is a thin, well-behaved wrapper around an external OSS tool. It:
  1. declares which TargetTypes it supports,
  2. reports whether the underlying binary is available,
  3. builds and runs a command in a temp workdir,
  4. parses the tool's native output into normalized Findings.

Adapters must never raise on a scanning error: they capture it in EngineRun.
"""
from __future__ import annotations

import base64
import json
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

    #: The flag this engine's binary uses to add an HTTP request header, or
    #: None when it has no such flag (or none we have verified). Declaring it
    #: is what makes `auth_args()` work — and leaving it None is what makes the
    #: gap show up as "no" in `yubel engines`, instead of the scan silently
    #: running unauthenticated.
    header_flag: Optional[str] = None

    def auth_headers(self, target: Target) -> List[str]:
        """Every `Name: value` header implied by the target's credentials.

        One implementation for all engines. It used to live in nuclei.py and
        handle only what nuclei happened to need, so `--header` reached one of
        thirteen engines and `basic` reached one other — while the README sold
        authenticated crawling. Same failure shape as `--offline`: a control
        that is accepted, documented, and quietly ignored.
        """
        auth = target.auth
        headers: List[str] = []
        if auth.kind == "bearer" and auth.token:
            headers.append(f"Authorization: Bearer {auth.token}")
        elif auth.kind == "cookie" and auth.token:
            headers.append(f"Cookie: {auth.token}")
        elif auth.kind == "basic" and auth.username:
            raw = f"{auth.username}:{auth.password or ''}".encode()
            headers.append("Authorization: Basic "
                           + base64.b64encode(raw).decode())
        # extra headers ride along regardless of kind, so `--bearer X
        # --header "Y: Z"` sends both rather than one erasing the other
        headers += [f"{k}: {v}" for k, v in (auth.headers or {}).items()]
        return headers

    #: How this engine's binary wants a header *spelled* after `header_flag`.
    #: `"colon"` is `Name: value` and is what almost every tool takes.
    #: `"json"` is `{"Name": "value"}` — graphql-cop parses its `-H` with
    #: `json.loads()`, and on failure it prints a line and **keeps scanning**,
    #: so getting this wrong does not fail the run: it drops the credentials
    #: and reports an anonymous scan as a normal one. Declaring the flag is not
    #: enough; the spelling has to match too.
    header_style: str = "colon"

    def format_header(self, header: str) -> str:
        """Render one `Name: value` header the way this engine's binary wants."""
        if self.header_style != "json":
            return header
        name, _, value = header.partition(":")
        return json.dumps({name.strip(): value.strip()})

    def auth_args(self, target: Target) -> List[str]:
        """argv fragments carrying the credentials, or [] if unsupported."""
        if not self.header_flag:
            return []
        args: List[str] = []
        for header in self.auth_headers(target):
            args += [self.header_flag, self.format_header(header)]
        return args

    def supports_auth(self) -> bool:
        """Whether credentials reach this engine at all (for `yubel engines`)."""
        return bool(self.header_flag)

    # ---- command construction (implemented by subclasses) --------------
    # This is the contract every engine must honour, and `run()` below calls
    # exactly this: two positional arguments, no more. A subclass may *widen*
    # it with extra optional parameters — nuclei takes `dast`, dalfox takes
    # `url`, and both drive those from their own `run()` — but it has to stay
    # callable with just (target, workdir).
    #
    # The base used to declare *args/**kwargs to "stay compatible". That is
    # backwards: it advertised a wider contract than any of the twelve engines
    # implements, so a caller trusting the base signature could pass arguments
    # that every implementation rejects at runtime.
    def build_command(self, target: Target, workdir: str) -> List[str]:
        raise NotImplementedError

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
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
