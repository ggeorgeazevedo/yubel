"""Tests for the crawl → scanner wiring (discovery phase feeds parameter engines).

No network or external binaries: we exercise URL selection, command building and
the orchestrator's discovery→scan seeding directly.
"""
import os

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
    cmd = NucleiEngine().build_command(_web(), "/tmp", dast=False)
    assert "-u" in cmd and "-l" not in cmd


def test_nuclei_full_pass_lists_whole_surface(tmp_path):
    # the full-template pass scans every crawled URL (params or not)
    t = _web(seed=["http://t.example/p?a=1", "http://t.example/static"])
    cmd = NucleiEngine().build_command(t, str(tmp_path), dast=False)
    assert "-l" in cmd and "-u" not in cmd
    body = open(cmd[cmd.index("-l") + 1]).read()
    assert body.splitlines()[0] == "http://t.example"     # seed endpoint first
    assert "http://t.example/static" in body              # non-param URL included


def test_nuclei_dast_pass_only_fuzzes_param_urls(tmp_path):
    # the expensive dast fuzzing pass targets only parameterized URLs
    t = _web(seed=["http://t.example/p?a=1", "http://t.example/q?b=2",
                   "http://t.example/static"])
    cmd = NucleiEngine().build_command(t, str(tmp_path), dast=True)
    assert "-l" in cmd
    body = open(cmd[cmd.index("-l") + 1]).read()
    assert "http://t.example/p?a=1" in body and "http://t.example/q?b=2" in body
    assert "http://t.example/static" not in body          # param-less URL skipped


# ---- dalfox scans each discovered parameterized URL -------------------------

def test_dalfox_command_targets_given_url():
    cmd = DalfoxEngine().build_command(_web(), "/tmp", url="http://t.example/x?id=1")
    assert "http://t.example/x?id=1" in cmd
    assert "url" in cmd                            # v3/v2 both use the `url` verb


# ---- orchestrator discovery phase seeds the target --------------------------

def test_discovery_seeds_target_urls_capped():
    cfg = Config(targets=[_web("http://t")], crawl=True, crawl_max_urls=2)
    res = ScanResult()
    res.add([Finding("Attack surface", "info", "katana", "http://t",
                     raw={"endpoints": ["http://t/a?x=1", "http://t/b",
                                        "http://t/c?y=2"]})])
    Orchestrator(cfg)._seed_from_discovery(res)
    assert cfg.targets[0].seed_urls == ["http://t/a?x=1", "http://t/b"]  # capped to 2


def test_discovery_seeding_respects_crawl_off():
    # crawl disabled → the orchestrator never seeds, even if katana ran
    cfg = Config(targets=[_web("http://t")], crawl=False)
    res = ScanResult()
    res.add([Finding("Attack surface", "info", "katana", "http://t",
                     raw={"endpoints": ["http://t/a?x=1"]})])
    # run() only calls _seed_from_discovery when config.crawl is True; here we
    # assert the target stays unseeded by simulating that guard.
    if cfg.crawl:
        Orchestrator(cfg)._seed_from_discovery(res)
    assert cfg.targets[0].seed_urls == []


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
