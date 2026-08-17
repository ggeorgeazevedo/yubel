"""Every engine must be callable through the base class contract.

`Engine.run()` calls `self.build_command(target, workdir)` and
`self.parse(target, workdir, stdout)` — two and three positional arguments.
An engine that narrows that (fewer parameters, or a required extra one) blows
up at runtime, and only for the target types that reach it, which is the worst
way to find out.

The base used to hide this by declaring `*args, **kwargs`: it advertised a
contract wider than any implementation honoured, so nothing checked either
direction. These tests check both.
"""
import inspect

import pytest

from yubel.engines import ALL_ENGINES
from yubel.engines.base import Engine

ENGINES = sorted((cls() for cls in ALL_ENGINES), key=lambda e: e.name)
IDS = [e.name for e in ENGINES]


def _accepts(func, positional):
    """Can `func` be called with `positional` positional arguments?"""
    try:
        inspect.signature(func).bind(*(object(),) * positional)
    except TypeError:
        return False
    return True


@pytest.mark.parametrize("engine", ENGINES, ids=IDS)
def test_build_command_takes_target_and_workdir(engine):
    assert _accepts(engine.build_command, 2), (
        f"{type(engine).__name__}.build_command must be callable as "
        f"build_command(target, workdir); got "
        f"{inspect.signature(engine.build_command)}")


@pytest.mark.parametrize("engine", ENGINES, ids=IDS)
def test_parse_takes_target_workdir_and_stdout(engine):
    assert _accepts(engine.parse, 3), (
        f"{type(engine).__name__}.parse must be callable as "
        f"parse(target, workdir, stdout); got "
        f"{inspect.signature(engine.parse)}")


def test_base_does_not_advertise_more_than_it_requires():
    """The base signature is the contract; it must not be a catch-all.

    `*args, **kwargs` on an abstract method means callers can pass anything
    and every implementation will reject it — the mismatch CodeQL flags as
    py/inheritance/incorrect-overridden-signature.
    """
    for name in ("build_command", "parse"):
        params = inspect.signature(getattr(Engine, name)).parameters.values()
        kinds = {p.kind for p in params}
        assert inspect.Parameter.VAR_POSITIONAL not in kinds, (
            f"Engine.{name} still declares *args")
        assert inspect.Parameter.VAR_KEYWORD not in kinds, (
            f"Engine.{name} still declares **kwargs")


def test_widening_with_optional_parameters_is_allowed():
    """nuclei and dalfox legitimately take an extra argument from their own
    `run()`. That is fine precisely because it is optional — the base contract
    still holds."""
    from yubel.engines.dalfox import DalfoxEngine
    from yubel.engines.nuclei import NucleiEngine

    assert _accepts(NucleiEngine().build_command, 3)   # ... + dast
    assert _accepts(NucleiEngine().build_command, 2)   # ... and without it
    assert _accepts(DalfoxEngine().build_command, 3)   # ... + url
    assert _accepts(DalfoxEngine().build_command, 2)
