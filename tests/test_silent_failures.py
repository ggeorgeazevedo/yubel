"""Five paths where the tool used to say "no findings" without having looked.

Every test here fails on the code as it stood at v0.7.2. They are grouped
because they share a shape rather than a module: each one produced a clean
report, exit code 0, and no warning, for a scan that did not actually happen —
the failure mode that matters most in a security tool, because the operator
acts on the all-clear.
"""
import pytest

from yubel.config import Config
from yubel.engines import ALL_ENGINES
from yubel.engines.nuclei import NucleiEngine
from yubel.engines.testssl import TestSSLEngine as _TestSSL
from yubel.models import Auth, Finding, ScanResult, Target, TargetType, canon_cwe
from yubel.severity import Severity


def _web(url="https://app.example.com", **kw):
    return Target(type=TargetType.WEB, url=url, **kw)


def _finding(engine, cwe, title="Reflected XSS", location="https://x/a?q=1"):
    return Finding(title=title, severity=Severity.HIGH, engine=engine,
                   target="t", location=location, cwe=cwe)


# --------------------------------------------------------------------------
# 1. CWE spelling split one issue into two
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("cwe-79", "79"),      # nuclei's classification carries the prefix
    ("CWE-79", "79"),      # testssl used to strip this by hand
    ("79", "79"),          # zap, dalfox
    (79, "79"),            # anything int-ish
    ("079", "79"),
    (" 89 ", "89"),
    ("CWE-1004, CWE-79", "1004"),   # a list: first id wins
    ("-1", None),          # zap's "no CWE mapped" sentinel
    ("0", None),
    ("", None),
    ("n/a", None),
    (None, None),
])
def test_cwe_is_canonicalised(raw, expected):
    assert canon_cwe(raw) == expected
    assert _finding("x", raw).cwe == expected


def test_same_issue_from_two_engines_deduplicates():
    """The headline feature: corroboration across engines.

    nuclei spells it `cwe-79` and ZAP spells it `79`. Both reached
    `Finding.fingerprint` verbatim, so the same XSS produced two findings, the
    `verified` tier ("corroborated by 2+ engines") never fired, and the risk
    score never got its corroboration bump.
    """
    result = ScanResult()
    result.add([_finding("nuclei", "cwe-79"), _finding("zap", "79")])
    result = result.dedupe()

    assert len(result.findings) == 1
    assert result.findings[0].corroboration == 2


def test_attack_chain_rules_see_nuclei_findings():
    """`chains._has(..., cwe=79)` compares against an int-ish CWE.

    With `cwe-79` it never matched, so the rules were blind to the engine that
    produces the most findings, and only fired through the keyword fallback.
    """
    from yubel.analysis.chains import _has

    assert _has([_finding("nuclei", "cwe-79")], cwe=79)


def test_systemic_correlation_does_not_split_one_class_in_two():
    """`correlate._class_key` built "cwe-cwe-79" for nuclei findings."""
    from yubel.analysis.correlate import _class_key

    assert _class_key(_finding("nuclei", "cwe-79")) == _class_key(_finding("zap", "79"))


@pytest.mark.parametrize("engine_cls", ALL_ENGINES,
                         ids=[c.name for c in ALL_ENGINES])
def test_no_engine_hardcodes_a_non_canonical_cwe(engine_cls):
    """Adapters that hardcode a CWE (dalfox=79, sqlmap=89, ...) must use the
    canonical spelling, so a future adapter cannot reintroduce the split."""
    import inspect
    import re

    source = inspect.getsource(engine_cls)
    for literal in re.findall(r'cwe\s*=\s*["\']([^"\']+)["\']', source):
        assert canon_cwe(literal) == literal, (
            f"{engine_cls.__name__} hardcodes cwe={literal!r}; "
            f"canonical form is {canon_cwe(literal)!r}")


# --------------------------------------------------------------------------
# 2. --bearer and --header erased each other
# --------------------------------------------------------------------------

def test_bearer_and_header_compose():
    """They were two sequential assignments to the same variable, so passing
    both silently dropped the token and the whole scan ran anonymous."""
    from yubel.cli import _build_auth

    auth = _build_auth("TOKEN-PROD", ["X-Tenant: acme"])
    assert auth.token == "TOKEN-PROD"
    assert auth.headers == {"X-Tenant": "acme"}
    assert auth.kind == "bearer"


@pytest.mark.parametrize("bearer,headers,kind,token,hdrs", [
    ("T", None, "bearer", "T", {}),
    (None, ["A: 1"], "header", None, {"A": "1"}),
    ("T", ["A: 1", "B: 2"], "bearer", "T", {"A": "1", "B": "2"}),
    (None, None, "none", None, {}),
    (None, ["malformed"], "none", None, {}),      # no colon: ignored
    (None, ["  A  :  1  "], "header", None, {"A": "1"}),
    (None, ["A: v:with:colons"], "header", None, {"A": "v:with:colons"}),
])
def test_build_auth_table(bearer, headers, kind, token, hdrs):
    from yubel.cli import _build_auth

    auth = _build_auth(bearer, headers)
    assert (auth.kind, auth.token, auth.headers) == (kind, token, hdrs)


def test_nuclei_sends_both_the_token_and_the_extra_headers():
    """Keying header emission off `auth.kind` dropped one of the two."""
    from yubel.engines.nuclei import _auth_headers

    sent = _auth_headers(_web(auth=Auth(kind="bearer", token="T",
                                        headers={"X-Tenant": "acme"})))
    assert "Authorization: Bearer T" in sent
    assert "X-Tenant: acme" in sent


# --------------------------------------------------------------------------
# 3. A typo in --engine scanned nothing and exited 0
# --------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs,needle", [
    ({"engines": ["nucli"]}, "nuclei"),
    ({"disable": ["zapp"]}, "zap"),
    ({"options": {"sevirity": {}}}, "unknown engine"),
])
def test_unknown_engine_name_is_rejected(kwargs, needle):
    errors = Config(targets=[_web()], **kwargs).validate()
    assert errors, "a misspelled engine name passed validation"
    assert needle in " ".join(errors)


def test_correct_engine_names_still_validate():
    assert Config(targets=[_web()], engines=["nuclei"], disable=["zap"],
                  options={"nikto": {"maxtime": 300}}).validate() == []


# --------------------------------------------------------------------------
# 4. nuclei reported "ok" for a run that failed
# --------------------------------------------------------------------------

def test_nuclei_reports_an_error_when_it_fails_producing_nothing(monkeypatch):
    """`Engine.run()` has this rule, with the comment "never report a broken
    run as 'ok' (false assurance)". NucleiEngine overrides run() and the check
    was lost in the copy — dalfox, which also overrides, kept it.
    """
    import subprocess

    class Failed:
        returncode = 1
        stdout = ""
        stderr = "could not read templates directory"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Failed())
    monkeypatch.setattr(NucleiEngine, "available", lambda self: True)
    engine = NucleiEngine({"dast": False})
    findings, record = engine.run(_web())

    assert findings == []
    assert record.status == "error", "a failed nuclei run reported as clean"
    assert "templates" in record.message


def test_nuclei_still_reports_ok_when_it_finds_nothing_cleanly(monkeypatch):
    """Exit 0 with no findings is a legitimate clean scan, not an error."""
    import subprocess

    class Clean:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Clean())
    monkeypatch.setattr(NucleiEngine, "available", lambda self: True)
    _, record = NucleiEngine({"dast": False}).run(_web())
    assert record.status == "ok"


# --------------------------------------------------------------------------
# 5. testssl accepted its own error codes as success
# --------------------------------------------------------------------------

@pytest.mark.parametrize("code,name", [
    (0, "ALLOK"),
    (4, "CRITICAL severity level"),
    (241, "highest non-error code"),
])
def test_testssl_accepts_severity_exit_codes(code, name):
    assert code in _TestSSL()._ok_returncodes(), name


@pytest.mark.parametrize("code,name", [
    (242, "ERR_CHILD"),
    (244, "ERR_RESOURCE"),
    (245, "ERR_CLUELESS"),
    (246, "ERR_CONNECT"),
    (247, "ERR_DNSLOOKUP"),
    (250, "ERR_OSSLBIN"),
    (255, "ERR_BASH"),
])
def test_testssl_rejects_its_own_error_codes(code, name):
    """testssl.sh reserves 242-255 for hard errors (`declare -r ERR_*`,
    testssl.sh:75-88). The old `range(0, 250)` accepted ERR_CONNECT and
    ERR_RESOURCE, so a testssl that never reached the target reported
    `ok (0 findings)`."""
    assert code not in _TestSSL()._ok_returncodes(), name
