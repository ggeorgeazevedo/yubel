"""The engine registry: the single place engines are registered and resolved.

To add an engine to Yubel you write an adapter (subclass of Engine) and add
it to ALL_ENGINES here. Everything else — availability probing, target routing,
CLI listing, Docker bundling docs — flows from this list.
"""
from __future__ import annotations

from typing import Dict, List, Type

from ..models import Target
from .base import Engine
from .nuclei import NucleiEngine
from .zap import ZapEngine
from .nikto import NiktoEngine
from .wapiti import WapitiEngine
from .testssl import TestSSLEngine
from .sqlmap import SqlmapEngine
from .dalfox import DalfoxEngine
from .discovery import KatanaEngine, HttpxEngine
from .api_specs import SchemathesisEngine
from .graphql import GraphwoofEngine, GraphqlCopEngine
from .kubernetes import KubeHunterEngine
from .demo import DemoEngine

#: Order matters only for display; execution order is handled by the orchestrator.
ALL_ENGINES: List[Type[Engine]] = [
    # discovery / context
    HttpxEngine, KatanaEngine,
    # core web DAST
    ZapEngine, NucleiEngine, WapitiEngine, NiktoEngine,
    # specialized web
    DalfoxEngine, SqlmapEngine, TestSSLEngine,
    # api
    SchemathesisEngine,
    # graphql
    GraphwoofEngine, GraphqlCopEngine,
    # kubernetes / container
    KubeHunterEngine,
    # selftest
    DemoEngine,
]

#: engines that are intrusive and must be explicitly enabled
OPT_IN = {"sqlmap"}


def registry() -> Dict[str, Type[Engine]]:
    return {e.name: e for e in ALL_ENGINES}


def instantiate(name: str, options: dict | None = None) -> Engine:
    cls = registry().get(name)
    if not cls:
        raise KeyError(f"unknown engine '{name}'")
    return cls(options or {})


def select_for(target: Target, enabled: List[str] | None,
               disabled: List[str] | None, options: Dict[str, dict],
               include_opt_in: bool = False) -> List[Engine]:
    """Return the engine instances that should run against a target.

    - `enabled` (allow-list) wins if provided; otherwise all engines that
      handle the target type are candidates.
    - `disabled` (deny-list) is always subtracted.
    - opt-in engines (e.g. sqlmap) are excluded unless include_opt_in or the
      engine is explicitly named in `enabled`.
    """
    enabled = enabled or []
    disabled = set(disabled or [])
    chosen: List[Engine] = []
    for cls in ALL_ENGINES:
        if cls is DemoEngine:
            continue
        name = cls.name
        if name in disabled:
            continue
        if enabled and name not in enabled:
            continue
        if name in OPT_IN and not include_opt_in and name not in enabled:
            continue
        eng = cls(options.get(name, {}))
        if eng.handles(target):
            chosen.append(eng)
    return chosen
