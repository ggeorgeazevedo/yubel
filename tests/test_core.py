"""Unit tests for the Yubel core (no network, no external binaries)."""
import json
import os

from yubel.config import Config
from yubel.models import Finding, ScanResult, Target, TargetType
from yubel.orchestrator import Orchestrator, gate
from yubel.reporters import write_reports
from yubel.severity import Severity
from yubel.engines import select_for, registry


def test_severity_normalization():
    assert Severity.from_any("critical") == Severity.CRITICAL
    assert Severity.from_any("HIGH") == Severity.HIGH
    assert Severity.from_any(9.8) == Severity.CRITICAL   # CVSS
    assert Severity.from_any(3) == Severity.HIGH          # ZAP riskcode
    assert Severity.from_any(None) == Severity.INFO
    assert Severity.from_any("bogus") == Severity.INFO


def test_finding_fingerprint_stable():
    a = Finding("XSS", "high", "zap", "t", location="/x", cwe="79")
    b = Finding("xss", "medium", "nuclei", "t", location="/x", cwe="79")
    assert a.fingerprint == b.fingerprint  # same issue, different engines/case


def test_dedupe_merges_engines_and_keeps_worst():
    r = ScanResult()
    r.add([Finding("XSS", "medium", "nuclei", "t", location="/x", cwe="79"),
           Finding("XSS", "high", "zap", "t", location="/x", cwe="79")])
    d = r.dedupe()
    assert len(d.findings) == 1
    f = d.findings[0]
    assert f.severity == Severity.HIGH
    assert f.corroboration == 2
    assert "nuclei" in f.also_reported_by


def test_registry_has_expected_engines():
    reg = registry()
    for name in ["nuclei", "zap", "nikto", "wapiti", "testssl", "sqlmap",
                 "dalfox", "katana", "httpx", "schemathesis", "kube-hunter",
                 "graphw00f", "graphql-cop"]:
        assert name in reg, f"missing engine {name}"


def test_opt_in_excluded_by_default():
    t = Target(type=TargetType.WEB, url="http://x")
    names = [e.name for e in select_for(t, [], [], {}, include_opt_in=False)]
    assert "sqlmap" not in names
    names2 = [e.name for e in select_for(t, [], [], {}, include_opt_in=True)]
    assert "sqlmap" in names2


def test_target_routing_by_type():
    k8s = Target(type=TargetType.KUBERNETES, host="10.0.0.1")
    names = [e.name for e in select_for(k8s, [], [], {})]
    assert "kube-hunter" in names
    assert "wapiti" not in names  # wapiti doesn't handle kubernetes


def test_selftest_pipeline_and_reports(tmp_path):
    cfg = Config(targets=[Target(type=TargetType.WEB, url="http://demo")])
    res = Orchestrator(cfg, selftest=True).run().dedupe()
    assert res.counts()["Total"] == 4
    paths = write_reports(res, str(tmp_path), ["json", "html", "markdown"], sarif=True)
    assert len(paths) == 4
    # JSON is well-formed
    with open(os.path.join(tmp_path, "yubel.json")) as fh:
        data = json.load(fh)
    assert data["summary"]["Total"] == 4
    # SARIF is well-formed and has the required top-level keys
    with open(os.path.join(tmp_path, "yubel.sarif")) as fh:
        sarif = json.load(fh)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Yubel"
    # HTML is self-contained (no external scripts)
    with open(os.path.join(tmp_path, "yubel.html")) as fh:
        html = fh.read()
    assert "<script>" in html and "http-equiv" not in html
    assert "src=\"http" not in html


def test_gate_threshold():
    cfg = Config(targets=[Target(type=TargetType.WEB, url="http://demo")],
                 fail_on=Severity.HIGH)
    res = Orchestrator(cfg, selftest=True).run().dedupe()
    assert gate(res, cfg) == 2       # demo emits a HIGH finding
    cfg.fail_on = Severity.CRITICAL
    assert gate(res, cfg) == 0       # nothing critical


def test_config_from_dict_env_expansion(monkeypatch):
    monkeypatch.setenv("TESTTOKEN", "secret123")
    cfg = Config.from_dict({
        "targets": [{"type": "api", "url": "http://api", "openapi": "http://api/spec",
                     "auth": {"kind": "bearer", "token": "${TESTTOKEN}"}}],
        "fail_on": "medium",
    })
    assert cfg.targets[0].auth.token == "secret123"
    assert cfg.fail_on == Severity.MEDIUM
    assert not cfg.validate()


def test_config_validation_errors():
    cfg = Config()
    assert "no targets defined" in cfg.validate()
