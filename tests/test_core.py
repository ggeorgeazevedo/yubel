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
    # self-contained: the script is inline and nothing is fetched over the
    # network. `http-equiv` used to stand in for this, which meant adding a
    # CSP <meta> to the report would have failed the test that guards it.
    assert "<script>" in html
    assert "src=\"http" not in html
    assert "href=\"http" not in html.replace('href="https://owasp.org', "")
    assert "@import" not in html


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


def test_sarif_uris_are_checkout_relative(tmp_path):
    """GitHub code scanning rejects absolute URIs in artifactLocation.

    It resolves every URI against the checkout (scheme `file`), so an
    `https://` target — or a bare `host:port/...`, whose host the parser reads
    as a scheme — kills the whole upload with "SARIF URI scheme ... did not
    match the checkout URI scheme file".
    """
    from urllib.parse import urlparse
    from yubel.reporters.sarif_reporter import _artifact_uri

    for raw in ["https://demo.example.com/items?id=1", "example.com:8080/admin",
                "https://[2001:db8::1]:8443/x", "arn:aws:s3:::my-bucket/key",
                "k8s-control-plane", "/just/a/path", "", "   ", "/", "-", ":"]:
        uri = _artifact_uri(raw)
        assert uri, f"empty uri for {raw!r}"
        assert not urlparse(uri).scheme, f"{raw!r} -> {uri!r} still has a scheme"
        assert not uri.startswith("/"), f"{raw!r} -> {uri!r} is absolute"
        assert ".." not in uri.split("/"), f"{raw!r} -> {uri!r} escapes the tree"



def test_sarif_bare_path_anchors_under_the_target():
    """nikto reports `"url": "/"` for root-level findings, wapiti likewise for
    module-level ones. A bare path carries no host, so the target has to
    supply it — otherwise every such finding collapses onto one anchor.
    """
    from yubel.reporters.sarif_reporter import _artifact_uri

    t = "https://example.com"
    assert _artifact_uri("/", t) == "dast/example.com"
    assert _artifact_uri("/admin", t) == "dast/example.com/admin"
    assert _artifact_uri("", t) == "dast/example.com"
    # punctuation-only locations must not swallow the target either
    assert _artifact_uri("-", t) == "dast/example.com"
    # an explicit host in the location still wins over the target
    assert _artifact_uri("https://other.test/x", t) == "dast/other.test/x"
    # nothing usable anywhere is the only route to the placeholder
    assert _artifact_uri("/", "") == "dast/unknown"


def test_sarif_results_carry_url_and_fingerprint(tmp_path):
    cfg = Config(targets=[Target(type=TargetType.WEB, url="http://demo")])
    res = Orchestrator(cfg, selftest=True).run().dedupe()
    write_reports(res, str(tmp_path), ["json"], sarif=True)
    with open(os.path.join(tmp_path, "yubel.sarif")) as fh:
        sarif = json.load(fh)

    results = sarif["runs"][0]["results"]
    assert results, "selftest result produced no SARIF results"
    for r in results:
        # the pseudo-path is not human-readable, so the real URL has to survive
        assert r["properties"]["url"] in r["message"]["text"]
        # stable id, so code scanning tracks an alert across runs
        assert isinstance(r["partialFingerprints"]["yubel/v1"], str)
        assert r["partialFingerprints"]["yubel/v1"]
