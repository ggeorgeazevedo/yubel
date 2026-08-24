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

from ..models import Finding, Target, TargetType
from .base import Engine


class KubeHunterEngine(Engine):
    name = "kube-hunter"
    category = "kubernetes cluster pentest"
    supports = (TargetType.KUBERNETES,)
    binary = "kube-hunter"
    default_timeout = 900
    homepage = "https://github.com/aquasecurity/kube-hunter"

    def available(self) -> bool:
        return shutil.which("kube-hunter") is not None

    def build_command(self, target: Target, workdir: str) -> List[str]:
        out = os.path.join(workdir, "kh.json")
        cmd = [self.binary, "--report", "json", "--log", "none"]
        mode = target.k8s_mode or "remote"
        if mode == "remote":
            host = target.host or target.url or ""
            cmd += ["--remote", host]
        elif mode == "internal":
            cmd += ["--interface"]
        elif mode == "pod":
            cmd += ["--pod"]
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
