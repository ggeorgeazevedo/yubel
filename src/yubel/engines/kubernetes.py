"""Kubernetes / container dynamic testing: kube-hunter.

kube-hunter actively probes a cluster from three vantage points:
  - remote : point at the API server / node IP from outside
  - internal: run inside the cluster network (a CronJob / debug pod)
  - pod    : run as a pod to emulate a compromised workload (--pod)

This is genuine dynamic testing (it talks to the live control plane and
kubelets), which is why it belongs in a DAST orchestrator rather than a static
manifest linter. Pair it with Nuclei against the ingress for exposed apps.
"""
from __future__ import annotations

import json
import os
import shutil
from typing import List

from ..models import K8S_MODES, Finding, Target, TargetType
from .base import Engine


class KubeHunterEngine(Engine):
    name = "kube-hunter"
    category = "kubernetes cluster pentest"
    supports = (TargetType.KUBERNETES,)
    binary = "kube-hunter"
    default_timeout = 900
    homepage = "https://github.com/aquasecurity/kube-hunter"
    offline_ok = True
    #: The report goes to stdout by default; the `http` dispatcher is opt-in
    #: through KUBEHUNTER_HTTP_DISPATCH_URL and this adapter never sets it.
    #: One caveat that is not ours to fix in code: the `aquasec/kube-hunter`
    #: image tagged `:aqua` bundles a closed-source plugin that uploads
    #: results. Our image builds from the open-source Dockerfile.
    offline_note = ("dispatches to stdout; the uploading plugin exists only "
                    "in the vendor's :aqua image")
    #: Aqua Security archived the repository. The tool still works and is
    #: still the only open-source engine that dynamically pentests a cluster
    #: from inside, so removing it would cost coverage and gain nothing. What
    #: was wrong was the silence: the engine table listed it exactly like the
    #: maintained ones. Saying so is the fix; replacing it is a decision with
    #: no candidate behind it yet.
    unmaintained = "archived upstream by Aqua Security; no new checks or CVEs"
    #: kube-hunter has no --version flag; asking would print usage.
    version_args = ()

    def available(self) -> bool:
        return shutil.which("kube-hunter") is not None

    def build_command(self, target: Target, workdir: str) -> List[str]:
        out = os.path.join(workdir, "kh.json")
        cmd = [self.binary, "--report", "json", "--log", "none"]
        mode = target.k8s_mode or "remote"
        # No `else: pass`. An unrecognised mode used to fall past all three
        # branches and leave kube-hunter with no vantage flag: it exits 0,
        # finds nothing, and the run is recorded as ok — a clean bill of
        # health for a scan that never happened. `Config.validate()` catches
        # this before anything runs; this catches a Config built in code.
        if mode == "remote":
            host = target.host or target.url or ""
            if not host:
                raise ValueError(
                    "k8s_mode 'remote' needs a host or url; --remote '' scans "
                    "nothing and would still exit 0")
            cmd += ["--remote", host]
        elif mode == "internal":
            cmd += ["--interface"]
        elif mode == "pod":
            cmd += ["--pod"]
        else:
            raise ValueError(
                f"unknown k8s_mode {mode!r} (expected one of "
                f"{', '.join(K8S_MODES)})")
        if self.options.get("active"):
            cmd += ["--active"]  # opt-in: performs exploitation attempts
        # kube-hunter prints JSON to stdout; we also redirect for safety
        self._out = out
        return cmd

    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        text = (stdout or "").strip()
        start = text.find("{")
        if start == -1:
            return []
        try:
            data = json.loads(text[start:])
        except json.JSONDecodeError:
            return []
        findings: List[Finding] = []
        for v in data.get("vulnerabilities", []):
            findings.append(Finding(
                title=v.get("vulnerability", "Kubernetes weakness"),
                severity=_sev(v.get("severity", "medium")),
                engine=self.name,
                target=target.label,
                description=v.get("description", ""),
                # a cluster target legitimately has no URL, so the last
                # resort is the label, which `Target.label` guarantees is
                # never empty
                location=(v.get("location") or target.endpoint()
                          or target.label),
                evidence=v.get("evidence", ""),
                references=[v.get("avd_reference")] if v.get("avd_reference") else [],
                raw={"category": v.get("category"), "hunter": v.get("hunter"),
                     "vid": v.get("vid")},
                confidence="high",
            ))
        return findings

    def _ok_returncodes(self):
        return (0, 1)


def _sev(s: str) -> str:
    return {"high": "high", "medium": "medium", "low": "low"}.get(str(s).lower(), "medium")
