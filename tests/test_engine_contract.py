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


def test_extra_parameters_live_on_their_own_method():
    """nuclei needs a `dast` flag and dalfox a `url`, both driven from their
    own `run()`. Those go on a separate method rather than widening the
    contract name: a call passing a third argument to `build_command` is what
    made the base signature disagree with its use in the first place."""
    from yubel.engines.dalfox import DalfoxEngine
    from yubel.engines.nuclei import NucleiEngine

    for engine, extra in ((NucleiEngine(), "build_command_for"),
                          (DalfoxEngine(), "build_command_for")):
        assert _accepts(getattr(engine, extra), 3)
        # and the contract name stays exactly two positional arguments
        assert _accepts(engine.build_command, 2)
        assert not _accepts(engine.build_command, 3)
