"""Tests for the crawl → scanner wiring (discovery phase feeds parameter engines).

No network or external binaries: we exercise URL selection, command building and
the orchestrator's discovery→scan seeding directly.
"""
import pytest

from yubel.config import Config
from yubel.models import Finding, ScanResult, Target, TargetType
from yubel.orchestrator import Orchestrator, DISCOVERY_ENGINES
from yubel.engines.nuclei import NucleiEngine
from yubel.engines.dalfox import DalfoxEngine
from yubel.engines.discovery import KatanaEngine


def _web(url="http://t.example", seed=None):
    return Target(type=TargetType.WEB, url=url, seed_urls=seed or [])


# ---- Target URL helpers ------------------------------------------------------

def test_scan_urls_dedupes_endpoint_first_and_caps():
    t = _web(seed=["http://t.example/a", "http://t.example",  # dup of endpoint
                   "http://t.example/b"])
    urls = t.scan_urls()
    assert urls[0] == "http://t.example"          # seed endpoint first
    assert urls == ["http://t.example", "http://t.example/a", "http://t.example/b"]
    assert t.scan_urls(limit=2) == ["http://t.example", "http://t.example/a"]


def test_param_urls_only_returns_parameterized():
    t = _web(seed=["http://t.example/x?id=1", "http://t.example/static",
                   "http://t.example/y?q=2"])
    assert t.param_urls() == ["http://t.example/x?id=1", "http://t.example/y?q=2"]
    assert t.param_urls(limit=1) == ["http://t.example/x?id=1"]


# ---- nuclei uses -l over the crawled surface --------------------------------

def test_nuclei_uses_u_without_discovery():
    cmd = NucleiEngine().build_command_for(_web(), "/tmp", dast=False)
    assert "-u" in cmd and "-l" not in cmd


def test_nuclei_full_pass_lists_whole_surface(tmp_path):
    # the full-template pass scans every crawled URL (params or not)
    t = _web(seed=["http://t.example/p?a=1", "http://t.example/static"])
    cmd = NucleiEngine().build_command_for(t, str(tmp_path), dast=False)
    assert "-l" in cmd and "-u" not in cmd
    with open(cmd[cmd.index("-l") + 1]) as fh:
        body = fh.read()
    assert body.splitlines()[0] == "http://t.example"     # seed endpoint first
    assert "http://t.example/static" in body              # non-param URL included


def test_nuclei_dast_pass_only_fuzzes_param_urls(tmp_path):
    # the expensive dast fuzzing pass targets only parameterized URLs
    t = _web(seed=["http://t.example/p?a=1", "http://t.example/q?b=2",
                   "http://t.example/static"])
    cmd = NucleiEngine().build_command_for(t, str(tmp_path), dast=True)
    assert "-l" in cmd
    with open(cmd[cmd.index("-l") + 1]) as fh:
        body = fh.read()
    assert "http://t.example/p?a=1" in body and "http://t.example/q?b=2" in body
    assert "http://t.example/static" not in body          # param-less URL skipped


# ---- dalfox scans each discovered parameterized URL -------------------------

@pytest.mark.parametrize("major,subcommand", [(2, "url"), (3, "scan")])
def test_dalfox_command_targets_given_url(monkeypatch, major, subcommand):
    """The point of this test is the *URL*, so the version must not be ambient.

    It used to assert `"url" in cmd` with whatever dalfox happened to be on the
    machine's PATH. That passes in CI and in any container with no dalfox
    installed (the probe falls back to major 2) and fails on a laptop with the
    Homebrew build, which is 3.x — the subcommand there is `scan`. A test that
    reads the developer's environment is a test that reports on the developer's
    environment.
    """
    monkeypatch.setattr(DalfoxEngine, "_major_version", lambda self: major)
    cmd = DalfoxEngine().build_command_for(_web(), "/tmp", url="http://t.example/x?id=1")
    assert cmd[1] == subcommand
    assert cmd[2] == "http://t.example/x?id=1"


# ---- orchestrator discovery phase seeds the target --------------------------

def test_discovery_seeds_target_urls_capped():
    cfg = Config(targets=[_web("http://t")], crawl=True, crawl_max_urls=2)
    res = ScanResult()
    res.add([Finding("Attack surface", "info", "katana", "http://t",
                     raw={"endpoints": ["http://t/a?x=1", "http://t/b",
                                        "http://t/c?y=2"]})])
    Orchestrator(cfg)._seed_from_discovery(res)
    assert cfg.targets[0].seed_urls == ["http://t/a?x=1", "http://t/b"]  # capped to 2


@pytest.mark.parametrize("crawl,expected", [
    (False, []),
    (True, ["http://t/a?x=1"]),
])
def test_run_honours_the_crawl_guard(monkeypatch, crawl, expected):
    """Drive the real guard in Orchestrator.run(), both ways.

    The previous version wrote `if cfg.crawl: ...` in the test body and
    asserted on the result — simulating the branch instead of running it. With
    `crawl=False` the body never executed, so the assert held by construction
    and deleting the guard from run() would not have failed anything.
    """
    cfg = Config(targets=[_web("http://t")], crawl=crawl)
    orch = Orchestrator(cfg)

    discovered = Finding("Attack surface", "info", "katana", "http://t",
                         raw={"endpoints": ["http://t/a?x=1"]})

    def fake_batch(pairs, result, cancelled):
        # stand in for the discovery batch: katana "ran" and found an endpoint
        if any(e.name == "katana" for e, _ in pairs):
            result.add([discovered])

    monkeypatch.setattr(Orchestrator, "_run_batch", staticmethod(fake_batch))
    monkeypatch.setattr(
        Orchestrator, "_plan",
        lambda self: [(KatanaEngine(), cfg.targets[0])])

    orch.run()
    assert cfg.targets[0].seed_urls == expected


def test_discovery_engines_constant():
    assert "katana" in DISCOVERY_ENGINES and "httpx" in DISCOVERY_ENGINES


# ---- katana extracts JS endpoints (needed for SPAs) -------------------------

def test_katana_enables_js_and_known_files_by_default():
    cmd = KatanaEngine().build_command(_web(), "/tmp")
    assert "-jc" in cmd                         # parse endpoints from JS bundles
    assert "-kf" in cmd and "all" in cmd        # robots.txt / sitemap.xml
    assert "-headless" not in cmd               # off unless requested


def test_katana_headless_opt_in():
    cmd = KatanaEngine({"headless": True, "js_crawl": False,
                        "known_files": False}).build_command(_web(), "/tmp")
    assert "-headless" in cmd and "-no-sandbox" in cmd
    assert "-jc" not in cmd                      # respects opt-out


def test_katana_parse_reads_nested_endpoint_and_skips_errors(tmp_path):
    # katana v1.6 nests the URL under "request"; failed requests carry "error"
    lines = "\n".join([
        '{"timestamp":"t","request":{"method":"GET","endpoint":"http://x/a?id=1"}}',
        '{"timestamp":"t","request":{"endpoint":"http://x"},"error":"connection refused"}',
        '{"request":{"endpoint":"http://x/b"}}',
        '{"endpoint":"http://x/legacy"}',            # older top-level form still works
    ])
    findings = KatanaEngine().parse(_web("http://x"), str(tmp_path), lines)
    eps = findings[0].raw["endpoints"]
    assert "http://x/a?id=1" in eps and "http://x/b" in eps and "http://x/legacy" in eps
    assert "http://x" not in eps                     # errored line skipped
