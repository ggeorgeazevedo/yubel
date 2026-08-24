"""`--k8s-mode` had `choices`; the YAML path had nothing.

A misspelled mode was not a loud error. It fell past all three branches in
`KubeHunterEngine.build_command`, the engine ran with no vantage flag at all,
exited 0, and the run was recorded as ok with zero findings. A clean bill of
health for a scan that never happened is the worst output a security tool can
produce — worse than a crash, because a crash gets investigated.

The values now live in one tuple, `models.K8S_MODES`, which argparse, the
validator and the engine all read. They used to be three independent literals
and two comments, which is how they drifted apart in the first place.
"""
import pytest

from yubel.config import Config
from yubel.engines.kubernetes import KubeHunterEngine
from yubel.models import K8S_MODES, Target, TargetType


def _cluster(**kwargs):
    return Config(targets=[Target(type=TargetType.KUBERNETES, name="c", **kwargs)])


@pytest.mark.parametrize("mode", K8S_MODES)
def test_every_documented_mode_validates(mode):
    host = "10.0.0.10" if mode == "remote" else None
    cfg = _cluster(k8s_mode=mode, host=host)
    cfg.allow_internal = True          # 10.0.0.10 is RFC1918 on purpose here
    assert cfg.validate() == []


def test_an_unknown_mode_from_yaml_is_refused():
    errors = Config.from_dict({
        "targets": [{"type": "kubernetes", "name": "c", "host": "k8s.example.com",
                     "k8s_mode": "pods"}],   # plural: the typo that started this
    }).validate()
    assert any("k8s_mode" in e and "pods" in e for e in errors)


def test_the_error_lists_the_modes_that_do_work():
    errors = _cluster(k8s_mode="Pod", host="k8s.example.com").validate()
    assert any(all(mode in e for mode in K8S_MODES) for e in errors)


def test_remote_without_a_host_is_refused():
    """`--remote ''` is accepted by kube-hunter and scans nothing."""
    errors = _cluster(k8s_mode="remote").validate()
    assert any("remote" in e and "host" in e for e in errors)


def test_the_engine_refuses_too_when_validate_was_bypassed():
    """`Config` can be built in code, and `validate()` is the caller's to
    invoke. The engine is the last line, and it must fail loudly rather than
    build a command with no vantage flag."""
    target = Target(type=TargetType.KUBERNETES, name="c", k8s_mode="pods")
    with pytest.raises(ValueError, match="unknown k8s_mode"):
        KubeHunterEngine({}).build_command(target, "/tmp")


def test_the_engine_refuses_remote_with_no_host():
    target = Target(type=TargetType.KUBERNETES, name="c", k8s_mode="remote")
    with pytest.raises(ValueError, match="scans nothing"):
        KubeHunterEngine({}).build_command(target, "/tmp")


def test_a_bad_mode_becomes_a_failed_run_not_a_silent_ok():
    """The whole point. `Engine.run()` turns the ValueError into an errored
    run; what must never happen again is `status == "ok"` with no findings."""
    target = Target(type=TargetType.KUBERNETES, name="c", k8s_mode="pods")
    engine = KubeHunterEngine({})
    engine.available = lambda: True          # pretend the binary is installed
    _findings, record = engine.run(target)
    assert record.status == "error"
    assert "k8s_mode" in record.message


def test_the_modes_are_declared_in_exactly_one_place():
    """argparse, the validator and the engine must not hold separate lists."""
    from yubel import cli, models
    import inspect

    source = inspect.getsource(cli.main)
    assert "K8S_MODES" in source, "the CLI hard-codes its own choices again"
    assert models.K8S_MODES == ("remote", "internal", "pod")
