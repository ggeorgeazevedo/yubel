"""Tests for engine adapters and CLI profiles (no external binaries needed)."""
import pytest

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
    """Exercise NucleiEngine.passes() itself.

    This used to call a `_passes()` helper defined in this file that
    reimplemented the rule — so it tested its own copy, and deleting the real
    logic from nuclei.py left it green.
    """
    assert NucleiEngine({}).passes() == [False, True]
    assert NucleiEngine({"full": False, "dast": True}).passes() == [True]
    assert NucleiEngine({"full": True, "dast": False}).passes() == [False]
    # disabling both would scan nothing and report clean: fall back to full
    assert NucleiEngine({"full": False, "dast": False}).passes() == [False]


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


# --------------------------------------------------------------------------
# dalfox 2.x (Go) and 3.x (Rust) are different programs behind one name
# --------------------------------------------------------------------------

@pytest.mark.parametrize("major,subcommand", [(2, "url"), (3, "scan")])
def test_dalfox_uses_the_right_subcommand_for_the_installed_major(
        monkeypatch, major, subcommand, tmp_path):
    """v3.0 is a Rust rewrite that consolidated the subcommands under `scan`.

    The previous v3 branch sent `url --url <URL> --header ...`; v3 has no
    `--url` flag and spells the header flag `--headers`/`-H`, so its parser
    rejected the invocation. The URL is positional in both lines and `-H` works
    in both, so the only real difference is the subcommand.
    """
    from yubel.engines.dalfox import DalfoxEngine
    from yubel.models import Auth, Target, TargetType

    engine = DalfoxEngine()
    monkeypatch.setattr(DalfoxEngine, "_major_version", lambda self: major)
    target = Target(type=TargetType.WEB, url="https://app.example.com/?q=1",
                    auth=Auth(kind="bearer", token="TOK"))
    cmd = engine.build_command(target, str(tmp_path))

    assert cmd[1] == subcommand
    assert cmd[2] == "https://app.example.com/?q=1"   # positional, not --url
    assert "--url" not in cmd
    assert "--header" not in cmd                      # v3 rejects the singular
    assert "-H" in cmd and "Authorization: Bearer TOK" in cmd
