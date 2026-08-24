"""`scope` and `exclude` were read from the YAML and consulted by nothing.

For the whole life of the project `config.py` parsed both into `Target`,
`models.py` declared them, and no engine, no reporter and no analysis step
ever looked at either. `SECURITY.md` listed them under "Safe defaults" and
told operators to bound a scan with them. A scope field that exists and does
nothing is worse than one that does not exist, because the missing one raises
an error and the present one gives a false assurance.

They now bound the one thing that can grow without the operator's say-so: the
URLs the crawler discovers. Everything else in a scan is a target the operator
wrote down.
"""
import re

import pytest

from yubel.config import Config
from yubel.models import EngineRun, Finding, ScanResult, Target, TargetType
from yubel.orchestrator import Orchestrator
from yubel.severity import Severity


def _crawled(urls):
    result = ScanResult(version="test")
    result.runs.append(EngineRun(engine="katana", target="site", status="ok"))
    result.add([Finding(engine="katana", target="site", title="endpoints",
                        severity=Severity.INFO, raw={"endpoints": urls})])
    return result


def _seed(target, urls, **config_kwargs):
    result = _crawled(urls)
    Orchestrator(Config(targets=[target], **config_kwargs))._seed_from_discovery(result)
    return target.seed_urls, result


def _site(**kwargs):
    return Target(type=TargetType.WEB, url="https://shop.example.com",
                  name="site", **kwargs)


# --------------------------------------------------------------------------
# The default, with neither field set
# --------------------------------------------------------------------------

def test_by_default_the_crawler_cannot_leave_the_target_host():
    """katana follows off-site links and pulls routes out of JS bundles. With
    nothing bounding it, a link to a partner domain, a CDN or an analytics
    host put real attack traffic on infrastructure nobody authorised."""
    kept, _ = _seed(_site(), ["https://shop.example.com/a?x=1",
                              "https://cdn.othersite.net/app.js",
                              "https://partner.example.org/sso"])
    assert kept == ["https://shop.example.com/a?x=1"]


def test_leaving_the_host_is_recorded_with_the_way_to_allow_it():
    _, result = _seed(_site(), ["https://api.example.com/v1"])
    message = next(r for r in result.runs if r.engine == "katana").message
    # `re.search`, not `in`: a substring test against something URL-shaped is
    # the shape of a real sanitisation bug, and CodeQL flags it on sight —
    # correctly, in production code. Here it is an assertion, so spell it in a
    # way that does not train the eye to accept the bad shape.
    assert re.search(r"api\.example\.com", message)
    assert "scope" in message


# --------------------------------------------------------------------------
# scope
# --------------------------------------------------------------------------

def test_scope_admits_the_other_hosts_that_are_yours():
    kept, _ = _seed(_site(scope=[r"\.example\.com$"]),
                    ["https://shop.example.com/a",
                     "https://api.example.com/v1",
                     "https://evil.example.com.attacker.net/x"])
    assert kept == ["https://shop.example.com/a", "https://api.example.com/v1"]


def test_scope_matches_the_host_not_the_whole_url():
    """Anchoring on the host is what makes `\\.example\\.com$` mean anything.
    Against the full URL that pattern matches nothing at all, and an
    unanchored one would match any URL with the string in its path."""
    kept, _ = _seed(_site(scope=[r"^shop\.example\.com$"]),
                    ["https://shop.example.com/a",
                     "https://attacker.net/?next=https://shop.example.com"])
    assert kept == ["https://shop.example.com/a"]


# --------------------------------------------------------------------------
# exclude
# --------------------------------------------------------------------------

def test_exclude_matches_the_whole_url_so_paths_can_be_bounded():
    """The classic DAST need: keep the crawler from logging itself out, or
    off the endpoint that emails every user."""
    kept, _ = _seed(_site(exclude=[r"/logout", r"/admin/broadcast"]),
                    ["https://shop.example.com/cart?id=1",
                     "https://shop.example.com/logout",
                     "https://shop.example.com/admin/broadcast"])
    assert kept == ["https://shop.example.com/cart?id=1"]


def test_exclude_outranks_scope():
    """An explicit denial has to win, or `exclude` cannot carve a hole in the
    scope you just granted."""
    kept, _ = _seed(_site(scope=[r"\.example\.com$"], exclude=[r"/logout"]),
                    ["https://api.example.com/logout",
                     "https://api.example.com/v1"])
    assert kept == ["https://api.example.com/v1"]


def test_scope_cannot_re_admit_the_metadata_service():
    """Safety first, scoping second. `scope` says which hosts are yours; it
    must not be able to opt a scan back into the address that answers with
    the credentials of the machine running it."""
    kept, _ = _seed(_site(scope=[r".*"]),
                    ["http://169.254.169.254/latest/meta-data/",
                     "https://shop.example.com/a"])
    assert kept == ["https://shop.example.com/a"]


# --------------------------------------------------------------------------
# validate(): a regex can be wrong, and a scope can contradict itself
# --------------------------------------------------------------------------

def test_a_broken_regex_fails_before_the_scan_not_during_it():
    """Otherwise `re.error` surfaces from a worker thread halfway through."""
    errors = Config(targets=[_site(scope=["(unclosed"])]).validate()
    assert any("not a valid regex" in e for e in errors)


@pytest.mark.parametrize("field_name", ["scope", "exclude"])
def test_both_fields_are_checked(field_name):
    errors = Config(targets=[_site(**{field_name: ["*bad"]})]).validate()
    assert any(field_name in e for e in errors)


def test_a_scope_that_excludes_your_own_host_is_a_mistake():
    errors = Config(targets=[_site(scope=[r"^api\.example\.com$"])]).validate()
    assert any("its own host" in e for e in errors)


def test_an_exclude_matching_your_own_endpoint_is_a_mistake():
    errors = Config(targets=[_site(exclude=[r"shop\.example\.com"])]).validate()
    assert any("own endpoint" in e for e in errors)


def test_the_shipped_shapes_still_validate():
    """A target with neither field — the overwhelming majority — must not
    have acquired an error."""
    assert Config(targets=[_site()]).validate() == []
