"""YAML/dict configuration loading and validation.

A config describes *what* to scan (targets) and *how* (engine selection,
options, thresholds, output). Everything can also be expressed on the CLI for
one-off scans; the CLI simply builds an equivalent Config.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import K8S_MODES, Auth, Target, TargetType
from .netguard import host_of, internal_reason
from .severity import Severity


def _compiles(pattern: str) -> bool:
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True

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
    allow_internal: bool = False                              # scan RFC1918/loopback/IMDS
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
            allow_internal=bool(data.get("allow_internal", False)),
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
        errors += self._uncovered_target_errors()
        errors += self._bad_option_value_errors()
        errors += self._internal_target_errors()
        errors += self._k8s_mode_errors()
        errors += self._scope_errors()
        return errors

    def _scope_errors(self) -> List[str]:
        """`scope` and `exclude` are regexes, and a regex can be wrong.

        These two were read from the YAML and consulted by nothing for the
        whole life of the project, so nothing ever checked them either. Now
        that they bound a scan, a broken one has to fail here rather than
        raise `re.error` from a worker thread halfway through a run — and a
        scope that excludes the operator's own target is a mistake worth
        naming, since it silently means "discover nothing".
        """
        errors = []
        for t in self.targets:
            for field_name in ("scope", "exclude"):
                for pattern in getattr(t, field_name) or []:
                    try:
                        re.compile(pattern)
                    except re.error as exc:
                        errors.append(f"target {t.label}: {field_name} pattern "
                                      f"{pattern!r} is not a valid regex ({exc})")
            host = host_of(t.endpoint())
            if not host:
                continue
            good = [p for p in (t.scope or []) if _compiles(p)]
            if good and not any(re.search(p, host) for p in good):
                errors.append(
                    f"target {t.label}: no scope pattern matches its own host "
                    f"{host}, so the crawler would discard everything it finds")
            for pattern in (t.exclude or []):
                if _compiles(pattern) and re.search(pattern, t.endpoint()):
                    errors.append(
                        f"target {t.label}: exclude pattern {pattern!r} matches "
                        f"the target's own endpoint")
        return errors

    def _internal_target_errors(self) -> List[str]:
        """Refuse to aim the scanners at the infrastructure running them.

        See `netguard.py` for what is refused and why a name is never
        resolved. Every URL a target can carry is checked, not just the
        endpoint: `openapi` and `options.schemathesis.base_url` are fetched
        too, and either can name an address the endpoint does not.

        One route stays open by construction: `options.nuclei.extra_args` is
        concatenated into the argv, so `-u <anything>` there is not reachable
        from here. That is what an escape hatch is; it is documented as one.
        """
        if self.allow_internal:
            return []
        suffix = ("; pass --allow-internal (or allow_internal: true) if this "
                  "is an authorized internal assessment")
        errors = []
        for t in self.targets:
            places = [("target", t.endpoint()), ("openapi spec", t.openapi)]
            for what, value in places:
                reason = internal_reason(value or "")
                if reason:
                    errors.append(f"{what} of {t.label} refused: {reason}{suffix}")
        base_url = (self.options.get("schemathesis") or {}).get("base_url")
        reason = internal_reason(base_url or "") if isinstance(base_url, str) else None
        if reason:
            errors.append(f"options.schemathesis.base_url refused: {reason}{suffix}")
        return errors

    def _k8s_mode_errors(self) -> List[str]:
        """`--k8s-mode` has `choices`; the YAML path had nothing.

        An unknown mode is not a typo that fails loudly — it falls past every
        branch in `KubeHunterEngine.build_command`, and the engine runs with
        no vantage flag, exits 0 and reports nothing. A green scan that never
        scanned is the worst output this tool can produce.
        """
        errors = []
        for t in self.targets:
            if t.type != TargetType.KUBERNETES:
                continue
            if t.k8s_mode not in K8S_MODES:
                errors.append(
                    f"target {t.label}: unknown k8s_mode {t.k8s_mode!r} "
                    f"(expected one of {', '.join(K8S_MODES)})")
            elif t.k8s_mode == "remote" and not (t.host or t.url):
                errors.append(
                    f"target {t.label}: k8s_mode 'remote' needs a host or url "
                    f"to point kube-hunter at (use 'internal' or 'pod' to scan "
                    f"from inside the cluster)")
        return errors

    def _bad_option_value_errors(self) -> List[str]:
        """Reject option values an engine does not understand.

        Unknown option *keys* are already rejected. A known key holding an
        unknown value is the same bug one level down — `zap: {mode: passive}`
        was accepted and quietly ran the default scan instead.
        """
        from .engines import registry

        known = registry()
        errors = []
        for name, options in (self.options or {}).items():
            engine_cls = known.get(name)
            if engine_cls is None or not isinstance(options, dict):
                continue
            errors += engine_cls.option_errors(options)
        return errors

    def _uncovered_target_errors(self) -> List[str]:
        """Reject a target type that no engine can scan.

        `--type grpc` is accepted by the CLI (the choices come from the enum),
        matches no engine, and produces an empty report with exit 0 — a clean
        bill of health for a scan that never ran. This is generic on purpose:
        any target left uncovered by the enabled/disabled sets is caught, not
        just grpc.
        """
        from .engines import select_for

        errors = []
        for target in self.targets:
            engines = select_for(target, self.engines, self.disable,
                                 self.options, include_opt_in=self.include_opt_in)
            if not engines:
                errors.append(
                    f"target {target.label} ({target.type.value}): no engine "
                    f"supports this target type with the current "
                    f"engines/disable settings")
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
