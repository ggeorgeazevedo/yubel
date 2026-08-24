"""`--offline` reached ten engines and was read by one.

`_apply_offline` set `options[engine]["offline"] = True` for a hand-written
list of ten names, and exactly one adapter — nuclei — ever looked at it. The
other nine egressed exactly as before: ZAP checked the add-on marketplace,
nikto did reverse DNS, wapiti would post a crash report off-site. Three more
engines (sqlmap, graphw00f, graphql-cop) were not even on the list, so nothing
had considered them at all. The report said nothing about any of it, so the
operator got the word "offline" and none of the property.

The rule now: an engine either declares how it honours offline, or it does not
run under it. Each `offline_args` below was verified against the tool's own
documentation or source before being written down — a flag believed from
memory is exactly the failure this replaces.
"""
import pytest

from yubel.config import Config
from yubel.cli import _apply_offline
from yubel.engines import registry
from yubel.engines.base import Engine
from yubel.models import Target, TargetType

ENGINES = sorted(registry().items())
IDS = [name for name, _ in ENGINES]

#: The engines that declare flags, parametrized separately rather than
#: skipped inside the test. A skipped test reports as "not a failure", which
#: is the same shape of quiet as the bug this file is about.
WITH_FLAGS = [(name, cls) for name, cls in ENGINES if cls.offline_args]
FLAG_IDS = [name for name, _ in WITH_FLAGS]


def test_some_engine_declares_offline_flags():
    """Guards the filter above: an empty list would make the two tests
    below pass by having nothing to check."""
    assert len(WITH_FLAGS) >= 5, FLAG_IDS


def _build(engine):
    """The built command, with ZAP's script resolution stubbed.

    ZAP is the one adapter that resolves a *script* on PATH rather than a
    single binary, and raises when it finds none. That is correct behaviour
    and not what this test is about.
    """
    if hasattr(engine, "_script"):
        engine._script = lambda target: "zap-baseline.py"
    return engine.build_command(_target(), "/tmp")


def _target():
    return Target(type=TargetType.WEB, url="https://example.com", name="site")


# --------------------------------------------------------------------------
# Every engine has to have an answer
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name,cls", ENGINES, ids=IDS)
def test_every_engine_declares_an_offline_stance(name, cls):
    """`offline_ok` defaults to False, so a new engine is skipped until
    someone looks into it. What must never be silent is the reason."""
    assert cls.offline_note, f"{name} has no offline_note"
    assert cls.offline_note != Engine.offline_note or not cls.offline_ok, (
        f"{name} claims offline_ok with the base's placeholder note — say "
        f"which switch makes it safe")


@pytest.mark.parametrize("name,cls", WITH_FLAGS, ids=FLAG_IDS)
def test_a_declared_offline_flag_actually_reaches_the_command(name, cls):
    """A flag declared and not passed is the original bug in miniature.

    The base deliberately does not append `offline_args` for the engine:
    testssl.sh takes its host as a trailing positional, so "append at the
    end" is wrong for at least one engine and therefore wrong as a rule.
    Each engine places its own flags; this is what proves it did.
    """
    engine = cls({"offline": True})
    command = _build(engine)
    for flag in cls.offline_args:
        assert flag in command, (
            f"{name} declares {flag!r} in offline_args and never puts it in "
            f"the command")


@pytest.mark.parametrize("name,cls", WITH_FLAGS, ids=FLAG_IDS)
def test_the_flags_stay_out_when_the_run_is_not_offline(name, cls):
    command = _build(cls({}))
    # `-duc` is also passed by nuclei when the templates are pre-provisioned,
    # which is a different rule with its own test; only assert on flags that
    # belong exclusively to offline mode.
    exclusive = [f for f in cls.offline_args if f not in ("-duc",)]
    for flag in exclusive:
        assert flag not in command, f"{name} passes {flag!r} in an online run"


# --------------------------------------------------------------------------
# The option reaches every engine, not a list someone maintains
# --------------------------------------------------------------------------

def test_offline_reaches_every_registered_engine():
    """The hand-written list named ten of thirteen. sqlmap, graphw00f and
    graphql-cop never received the option, so nothing had ever decided
    whether they were safe — they simply ran."""
    cfg = Config()
    _apply_offline(cfg)
    missing = [name for name in registry()
               if not cfg.options.get(name, {}).get("offline")]
    assert not missing, f"engines --offline never reaches: {missing}"


# --------------------------------------------------------------------------
# What an engine that cannot honour it does
# --------------------------------------------------------------------------

def test_an_engine_that_cannot_honour_offline_is_skipped():
    cls = registry()["dalfox"]
    engine = cls({"offline": True})
    engine.available = lambda: True
    reason = engine.skip_reason(_target())
    assert reason and reason.startswith("--offline:")


def test_the_skip_says_why_and_that_reason_survives_into_the_run():
    """"skipped" with no reason reads as housekeeping. The operator has to be
    able to tell that an engine was dropped from *this* scan, and why."""
    cls = registry()["dalfox"]
    engine = cls({"offline": True})
    engine.available = lambda: True
    _findings, record = engine.run(_target())
    assert record.status == "skipped"
    assert "update-check" in record.message


def test_an_engine_that_can_honour_it_is_not_skipped():
    cls = registry()["nikto"]
    engine = cls({"offline": True})
    engine.available = lambda: True
    assert engine.skip_reason(_target()) is None


# --------------------------------------------------------------------------
# One skip path, not three copies of one
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["nuclei", "dalfox"])
def test_the_engines_with_their_own_run_use_the_shared_skip_check(name):
    """nuclei and dalfox reimplement `run()`, and each had its own copy of
    the handles/available preamble. A fourth reason then had to be added in
    three places or silently miss two engines."""
    import inspect

    source = inspect.getsource(registry()[name].run)
    assert "skip_reason" in source, (
        f"{name}.run has its own copy of the skip logic again")


# --------------------------------------------------------------------------
# The reports have to show it
# --------------------------------------------------------------------------

def _result_with_a_skip():
    from yubel.models import EngineRun, ScanResult

    result = ScanResult(version="test")
    result.runs.append(EngineRun(
        engine="dalfox", target="site", status="skipped",
        message="--offline: no update-check switch could be verified for v2"))
    result.finished_at = 1.0
    return result


def test_the_html_report_shows_the_reason(tmp_path):
    from yubel.reporters.html_reporter import write_html

    path = tmp_path / "yubel.html"
    write_html(_result_with_a_skip(), str(path))
    text = path.read_text(encoding="utf-8")
    assert "no update-check switch" in text
    assert "did not execute" in text


def test_the_markdown_report_shows_the_reason(tmp_path):
    from yubel.reporters.markdown_reporter import write_markdown as write_md

    path = tmp_path / "yubel.md"
    write_md(_result_with_a_skip(), str(path))
    assert "no update-check switch" in path.read_text(encoding="utf-8")
