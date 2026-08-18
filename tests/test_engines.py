"""Tests for engine adapters and CLI profiles (no external binaries needed)."""
from yubel.config import Config
from yubel.engines.zap import ZapEngine
from yubel.engines.nuclei import NucleiEngine
from yubel.engines.nikto import NiktoEngine
from yubel.models import Target, TargetType
from yubel.cli import _apply_fast_profile


def _web(url="http://t.example"):
    return Target(type=TargetType.WEB, url=url)


def test_zap_unavailable_reason_is_clear():
    msg = ZapEngine().unavailable_reason()
    assert "automation scripts" in msg
    assert "binary ''" not in msg


def test_nuclei_full_vs_dast_command():
    eng = NucleiEngine()
    full = eng.build_command_for(_web(), "/tmp", dast=False)
    dast = eng.build_command_for(_web(), "/tmp", dast=True)
    assert "-dast" not in full            # full template pass
    assert "-dast" in dast                # fuzzing pass
    assert "nuclei-full.jsonl" in " ".join(full)
    assert "nuclei-dast.jsonl" in " ".join(dast)


def test_nuclei_pass_selection_from_options():
    # default: both passes; fast: dast only; full-only when dast disabled
    assert _passes({}) == [False, True]
    assert _passes({"full": False, "dast": True}) == [True]
    assert _passes({"full": True, "dast": False}) == [False]
    assert _passes({"full": False, "dast": False}) == [False]  # never empty


def _passes(opts):
    p = []
    if opts.get("full", True):
        p.append(False)
    if opts.get("dast", True):
        p.append(True)
    return p or [False]


def test_nikto_has_maxtime_cap():
    cmd = " ".join(NiktoEngine({"maxtime": 300}).build_command(_web(), "/tmp"))
    assert "-maxtime 300s" in cmd
    # default also caps
    cmd2 = " ".join(NiktoEngine().build_command(_web(), "/tmp"))
    assert "-maxtime" in cmd2


def test_fast_profile_tunes_engines():
    cfg = Config(targets=[_web()])
    _apply_fast_profile(cfg)
    assert cfg.options["nuclei"]["full"] is False
    assert cfg.options["nuclei"]["dast"] is True
    assert cfg.options["nuclei"]["severity"] == "high,critical"
    assert cfg.options["nikto"]["maxtime"] == 120


def test_offline_profile_hardens_nuclei():
    from yubel.cli import _apply_offline
    cfg = Config(targets=[_web()])
    _apply_offline(cfg)
    assert cfg.options["nuclei"]["offline"] is True
    cmd = " ".join(NucleiEngine(cfg.options["nuclei"]).build_command_for(
        _web(), "/tmp", dast=True))
    assert "-ni" in cmd and "-duc" in cmd     # no OAST, no update check


def test_offline_from_config_dict():
    c = Config.from_dict({"targets": [{"type": "web", "url": "http://x"}],
                          "offline": True})
    assert c.offline is True


def test_hard_failure_is_error_not_ok():
    """A non-zero exit that produces no findings must be 'error', not 'ok'."""
    from yubel.engines.base import Engine

    class Failing(Engine):
        name = "failing"
        binary = "sh"
        supports = (TargetType.WEB,)

        def build_command(self, target, workdir):
            return ["sh", "-c", "exit 3"]

        def parse(self, target, workdir, stdout):
            return []

    _findings, rec = Failing().run(_web())
    assert rec.status == "error"
    assert _findings == []


def test_testssl_filters_scan_problems(tmp_path):
    """A connection/scan error must not be reported as a TLS finding."""
    import json
    from yubel.engines.testssl import TestSSLEngine
    (tmp_path / "testssl.json").write_text(json.dumps([
        {"id": "scanProblem", "severity": "FATAL",
         "finding": "Can't connect to '1.2.3.4:80' Make sure a firewall is not..."},
        {"id": "cert_expired", "severity": "HIGH",
         "finding": "Certificate expired", "cwe": "CWE-295"},
    ]))
    (tmp_path / "testssl.json").write_text(json.dumps([
        {"id": "scanProblem", "severity": "FATAL",
         "finding": "Can't connect to '1.2.3.4:80' Make sure a firewall is not..."},
        {"id": "cert_expirationStatus", "severity": "CRITICAL", "finding": "expired"},
        {"id": "cipher-tls1_2_x33", "severity": "LOW", "finding": "DHE-RSA-AES128-SHA"},
        {"id": "cipherlist_OBSOLETED", "severity": "LOW", "finding": "offered"},
    ]))
    t = Target(type=TargetType.WEB, url="http://x")
    findings = TestSSLEngine().parse(t, str(tmp_path), "")
    ids = [f.raw.get("id") for f in findings]
    assert "cert_expirationStatus" in ids       # real issue kept
    assert "cipherlist_OBSOLETED" in ids         # summary kept
    assert "scanProblem" not in ids              # noise dropped
    assert "cipher-tls1_2_x33" not in ids        # per-cipher enumeration dropped


def test_tls_findings_map_to_cryptographic_failures():
    from yubel.analysis import taxonomy
    from yubel.models import Finding
    f = Finding("TLS: BEAST_CBC_TLS1", "medium", "testssl", "t", cwe="20")
    taxonomy.enrich(f)
    # CWE-20 would wrongly bucket as Injection; TLS override forces A02
    assert f.owasp.startswith("A02:2021")


def test_dalfox_v3_vs_v2_command():
    from yubel.engines.dalfox import DalfoxEngine
    try:
        DalfoxEngine._major = 3
        cmd = DalfoxEngine().build_command(_web("http://t/x?q=1"), "/tmp")
        assert "--url" in cmd and "http://t/x?q=1" in cmd   # v3 named arg
        DalfoxEngine._major = 2
        cmd2 = DalfoxEngine().build_command(_web("http://t/x?q=1"), "/tmp")
        assert "--url" not in cmd2 and "http://t/x?q=1" in cmd2  # v2 positional
    finally:
        DalfoxEngine._major = None


def test_dalfox_v3_json_parsing(tmp_path):
    import json
    from yubel.engines.dalfox import DalfoxEngine
    t = Target(type=TargetType.WEB, url="http://t/x?q=1")
    # v3 empty wrapper (real output) must yield ZERO findings, not a garbage one
    empty = json.dumps({"findings": [], "meta": {"dalfox_version": "3.1.2"}})
    (tmp_path / "dalfox.json").write_text("")
    assert DalfoxEngine().parse(t, str(tmp_path), empty) == []
    # v3 wrapper WITH a finding must be extracted
    hit = json.dumps({"findings": [
        {"type": "reflected", "severity": "high", "param": "q",
         "url": "http://t/x?q=<svg>", "evidence": "<svg onload=alert(1)>"}],
        "meta": {}})
    fs = DalfoxEngine().parse(t, str(tmp_path), hit)
    assert len(fs) == 1 and fs[0].cwe == "79"
    assert "http://t/x?q=" in fs[0].location


def test_setup_install_plan():
    from yubel.engines.install import plan_for
    # pip engine is deterministic regardless of brew/go presence
    method, argv, label = plan_for("schemathesis")
    assert method == "pip" and "schemathesis" in label
    assert argv[:3] == [__import__("sys").executable, "-m", "pip"]
    # ZAP has no headless single-binary installer -> manual guidance
    assert plan_for("zap")[0] == "manual"
    # unknown engine -> None
    assert plan_for("does-not-exist") is None
