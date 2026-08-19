"""YAML/dict configuration loading and validation.

A config describes *what* to scan (targets) and *how* (engine selection,
options, thresholds, output). Everything can also be expressed on the CLI for
one-off scans; the CLI simply builds an equivalent Config.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import Auth, Target, TargetType
from .severity import Severity

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover
    yaml = None


@dataclass
class OutputConfig:
    dir: str = "yubel-report"
    formats: List[str] = field(default_factory=lambda: ["json", "html", "markdown"])
    sarif: bool = True


@dataclass
class Config:
    targets: List[Target] = field(default_factory=list)
    engines: List[str] = field(default_factory=list)          # allow-list
    disable: List[str] = field(default_factory=list)          # deny-list
    options: Dict[str, dict] = field(default_factory=dict)    # per-engine opts
    parallelism: int = 4
    fail_on: Optional[Severity] = None                        # CI gate threshold
    fail_on_new: bool = False                                 # gate only on new
    include_opt_in: bool = False
    offline: bool = False                                     # air-gapped hardening
    baseline: Optional[str] = None                            # prior yubel.json
    chains: bool = True                                       # attack-chain synth
    cluster_threshold: int = 8                                # noise clustering
    crawl: bool = True                                        # feed crawler URLs to scanners
    crawl_max_urls: int = 150                                 # cap URLs fed downstream
    output: OutputConfig = field(default_factory=OutputConfig)

    @staticmethod
    def load(path: str) -> "Config":
        if yaml is None:
            raise RuntimeError("PyYAML is required to read config files "
                               "(pip install pyyaml)")
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return Config.from_dict(data)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Config":
        targets = [_target(t) for t in data.get("targets", [])]
        out = data.get("output", {}) or {}
        fail_on = data.get("fail_on")
        return Config(
            targets=targets,
            engines=data.get("engines", []) or [],
            disable=data.get("disable", []) or [],
            options=data.get("options", {}) or {},
            parallelism=int(data.get("parallelism", 4)),
            fail_on=Severity.from_any(fail_on) if fail_on else None,
            fail_on_new=bool(data.get("fail_on_new", False)),
            include_opt_in=bool(data.get("include_opt_in", False)),
            offline=bool(data.get("offline", False)),
            baseline=_expand(data.get("baseline")),
            chains=bool(data.get("chains", True)),
            cluster_threshold=int(data.get("cluster_threshold", 8)),
            crawl=bool(data.get("crawl", True)),
            crawl_max_urls=int(data.get("crawl_max_urls", 150)),
            output=OutputConfig(
                dir=out.get("dir", "yubel-report"),
                formats=out.get("formats", ["json", "html", "markdown"]),
                sarif=out.get("sarif", True),
            ),
        )

    def validate(self) -> List[str]:
        errors = []
        if not self.targets:
            errors.append("no targets defined")
        for t in self.targets:
            if not t.endpoint() and t.type != TargetType.KUBERNETES:
                errors.append(f"target {t.label} has no url/host")
            if t.type in (TargetType.API,) and not (t.openapi or t.url):
                errors.append(f"api target {t.label} needs 'openapi' or 'url'")
        errors += self._unknown_engine_errors()
        return errors

    def _unknown_engine_errors(self) -> List[str]:
        """Reject engine names that do not exist, with a suggestion.

        A typo used to be silent and total: `-e nucli` passed validation,
        matched no engine, ran nothing, wrote empty reports and exited 0. With
        `--fail-on` the pipeline went green having scanned nothing at all.
        Same for `disable:` and for the keys of `options:`.
        """
        from difflib import get_close_matches
        from .engines import registry

        known = set(registry())
        errors = []
        for field_name, names in (("engines", self.engines),
                                  ("disable", self.disable),
                                  ("options", list(self.options))):
            for name in names or []:
                if name in known:
                    continue
                near = get_close_matches(name, known, n=1)
                hint = f" (did you mean '{near[0]}'?)" if near else ""
                errors.append(
                    f"{field_name}: unknown engine '{name}'{hint}")
        return errors


def _target(d: Dict[str, Any]) -> Target:
    if isinstance(d, str):
        # shorthand: bare URL -> web target
        return Target(type=TargetType.WEB, url=d)
    auth = d.get("auth")
    if isinstance(auth, dict):
        auth = Auth(**{k: _expand_deep(v) for k, v in auth.items()})
    return Target(
        type=TargetType(d.get("type", "web")),
        url=_expand(d.get("url")),
        host=_expand(d.get("host")),
        port=d.get("port"),
        openapi=_expand(d.get("openapi")),
        kubeconfig=_expand(d.get("kubeconfig")),
        k8s_mode=d.get("k8s_mode", "remote"),
        scope=d.get("scope", []) or [],
        exclude=d.get("exclude", []) or [],
        auth=auth or Auth(),
        tags=d.get("tags", []) or [],
        name=d.get("name"),
    )


def _expand(v):
    """Allow ${ENV_VAR} in string fields so secrets stay out of the YAML."""
    if isinstance(v, str):
        return os.path.expandvars(v)
    return v


def _expand_deep(v):
    """Env-expand strings, list items and dict values (for auth blocks)."""
    if isinstance(v, str):
        return os.path.expandvars(v)
    if isinstance(v, list):
        return [_expand_deep(x) for x in v]
    if isinstance(v, dict):
        return {k: _expand_deep(x) for k, x in v.items()}
    return v
