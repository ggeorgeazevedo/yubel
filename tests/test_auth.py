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
    (Auth(kind="header", headers={"X-Api-Key": "TOK"}), ["X-Api-Key: TOK"]),
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
