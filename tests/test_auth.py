"""Credentials must reach every engine that can carry them.

`--header` used to be honoured by exactly one of thirteen engines, `basic` by
one other, and `cookie` by one — while the README sold authenticated crawling.
An engine that silently scans anonymously finds a fraction of what it should
and reports the result as a clean run, which is the same failure shape as a
control that is accepted, documented and ignored.
"""
import base64

import pytest

from yubel.engines import ALL_ENGINES
from yubel.models import Auth, Target, TargetType

WITH_AUTH = [cls for cls in ALL_ENGINES if cls().supports_auth()]
AUTH_IDS = [cls.name for cls in WITH_AUTH]


def _target(auth):
    return Target(type=TargetType.WEB, url="https://app.example.com", auth=auth)


# --------------------------------------------------------------------------
# One implementation, shared by every engine
# --------------------------------------------------------------------------

@pytest.mark.parametrize("auth,expected", [
    (Auth(kind="bearer", token="T"), ["Authorization: Bearer T"]),
    (Auth(kind="cookie", token="sid=abc"), ["Cookie: sid=abc"]),
    (Auth(kind="header", headers={"X-Api-Key": "k"}), ["X-Api-Key: k"]),
    (Auth(), []),
    (Auth(kind="bearer"), []),                      # kind set, no token
])
def test_auth_headers_by_kind(auth, expected):
    engine = WITH_AUTH[0]()
    assert engine.auth_headers(_target(auth)) == expected


def test_basic_auth_is_encoded():
    engine = WITH_AUTH[0]()
    sent = engine.auth_headers(_target(Auth(kind="basic", username="u",
                                            password="p")))
    assert sent == ["Authorization: Basic " + base64.b64encode(b"u:p").decode()]


def test_extra_headers_ride_along_with_any_kind():
    """`--bearer X --header "Y: Z"` must send both, not one or the other."""
    engine = WITH_AUTH[0]()
    sent = engine.auth_headers(_target(Auth(kind="bearer", token="T",
                                            headers={"X-Tenant": "acme"})))
    assert "Authorization: Bearer T" in sent
    assert "X-Tenant: acme" in sent


@pytest.mark.parametrize("engine_cls", WITH_AUTH, ids=AUTH_IDS)
@pytest.mark.parametrize("auth,accepted", [
    (Auth(kind="bearer", token="TOK"), ["TOK"]),
    (Auth(kind="cookie", token="sid=TOK"), ["sid=TOK"]),
    # colon spelling, or graphql-cop's JSON one — the assertion is that the
    # credential arrives, not that it arrives in one particular encoding
    (Auth(kind="header", headers={"X-Api-Key": "TOK"}),
     ["X-Api-Key: TOK", '"X-Api-Key": "TOK"']),
    # basic may travel as the encoded header or as the tool's own flags —
    # wapiti drives the session natively, which is better than our header
    (Auth(kind="basic", username="u", password="TOK"),
     [base64.b64encode(b"u:TOK").decode(), "--auth-password TOK"]),
])
def test_every_auth_capable_engine_passes_every_kind(engine_cls, auth, accepted,
                                                     tmp_path):
    """The regression that matters: each kind reaches each engine's argv.

    Before, each adapter re-implemented `if auth.kind == "bearer"` and stopped
    there, so three of the four kinds were dropped by five of the six engines
    that take credentials at all. The assertion is that the credential arrives,
    not that it arrives in one particular encoding.
    """
    engine = engine_cls()
    argv = " ".join(engine.build_command(_target(auth), str(tmp_path)))
    assert any(needle in argv for needle in accepted), (
        f"{engine_cls.__name__} dropped {auth.kind} credentials")


# --------------------------------------------------------------------------
# The engines that cannot carry credentials say so
# --------------------------------------------------------------------------

def test_engines_without_a_header_flag_emit_no_auth_args():
    """Silence is the bug; `supports_auth() == False` is the honest answer."""
    for cls in ALL_ENGINES:
        engine = cls()
        if engine.supports_auth():
            continue
        assert engine.auth_args(_target(Auth(kind="bearer", token="T"))) == []


def test_the_auth_gap_is_reported_not_hidden(capsys):
    """`yubel engines` must name the engines that scan anonymously."""
    from yubel.cli import main

    main(["engines"])
    out = capsys.readouterr().out
    assert "AUTH" in out
    assert "credentials are NOT passed" in out
    for name in ("zap", "nikto", "testssl"):
        assert name in out


def test_no_adapter_hand_rolls_an_authorization_header():
    """Adapters must go through `auth_args()`/`auth_headers()`.

    Each hand-rolled `if auth.kind == "bearer"` was a place where the other
    three kinds got dropped. wapiti is the documented exception: it drives
    basic auth natively, which is better than sending the header ourselves.
    """
    import inspect
    import re

    offenders = []
    for cls in ALL_ENGINES:
        source = inspect.getsource(inspect.getmodule(cls))
        for match in re.finditer(r'Authorization:\s*(Bearer|Basic)', source):
            line = source[:match.start()].count("\n") + 1
            offenders.append(f"{cls.__module__}:{line}")
    assert not offenders, (
        "adapters building an Authorization header by hand: "
        + ", ".join(sorted(set(offenders))))


# --------------------------------------------------------------------------
# Declaring the flag is not enough — the spelling has to match
# --------------------------------------------------------------------------

def test_graphql_cop_receives_json_headers_not_colon_headers():
    """graphql-cop parses `-H` with `json.loads()`.

    Fase 2 gave it `header_flag = "-H"` and stopped there, so it received
    `Authorization: Bearer T`. graphql-cop's handler is a bare `except:` that
    prints one line and **keeps scanning** — the run does not fail, it just
    drops the credentials and reports an anonymous scan as a normal one. Same
    silent-false-negative shape the whole `test_silent_failures` suite exists
    for, introduced by the fix for it.
    """
    import json as _json

    from yubel.engines.graphql import GraphqlCopEngine

    args = GraphqlCopEngine().auth_args(
        _target(Auth(kind="bearer", token="TOK", headers={"X-Tenant": "acme"})))
    values = [a for a in args if a != "-H"]
    assert values, "graphql-cop got no credentials at all"
    for value in values:
        # must parse as a JSON object, which the colon form never does
        assert isinstance(_json.loads(value), dict), value
    assert {"Authorization": "Bearer TOK"} in [_json.loads(v) for v in values]


@pytest.mark.parametrize("engine_cls", WITH_AUTH, ids=AUTH_IDS)
def test_header_style_is_declared_deliberately(engine_cls):
    """Every auth-capable engine states which spelling its binary takes.

    Verified against each tool's own `--help` when this was written:
    nuclei, wapiti, sqlmap, dalfox and schemathesis document
    `-H 'Name: value'`; graphql-cop documents `-H '{"Name": "value"}'`.
    """
    engine = engine_cls()
    assert engine.header_style in ("colon", "json")
    if engine_cls.name == "graphql-cop":
        assert engine.header_style == "json"
    else:
        assert engine.header_style == "colon", (
            f"{engine_cls.name} claims a non-colon header style — if that is "
            f"right, verify it against the tool's --help and note it here")


# --------------------------------------------------------------------------
# `yubel engines --check` — the step whose absence shipped a broken image
# --------------------------------------------------------------------------

def _force_availability(monkeypatch, predicate):
    """Six adapters override `available()`, so patching the base is not enough."""
    for cls in ALL_ENGINES:
        monkeypatch.setattr(cls, "available",
                            lambda self, _p=predicate: _p(self.name),
                            raising=False)


def test_engines_check_fails_when_an_engine_is_missing(monkeypatch, capsys):
    """The published image advertised 13 engines and shipped 11.

    Nothing ever asked it. `--check` is what the container build now runs, so a
    missing engine fails the build instead of reaching users as a scan that
    reports clean without that engine having run.
    """
    from yubel.cli import main

    _force_availability(monkeypatch, lambda name: name != "zap")
    assert main(["engines", "--check"]) == 1
    assert "zap" in capsys.readouterr().err


def test_engines_check_passes_when_everything_is_present(monkeypatch, capsys):
    from yubel.cli import main

    _force_availability(monkeypatch, lambda name: True)
    assert main(["engines", "--check"]) == 0
    assert "every non-opt-in engine is present" in capsys.readouterr().out


def test_engines_check_tolerates_a_missing_opt_in_engine(monkeypatch):
    """sqlmap is intrusive; an image is allowed to ship without it."""
    from yubel.cli import main
    from yubel.engines import OPT_IN

    _force_availability(monkeypatch, lambda name: name not in OPT_IN)
    assert main(["engines", "--check"]) == 0


def test_plain_engines_still_exits_zero_with_engines_missing(monkeypatch):
    """Listing is not gating — only `--check` fails."""
    from yubel.cli import main

    _force_availability(monkeypatch, lambda name: False)
    assert main(["engines"]) == 0
