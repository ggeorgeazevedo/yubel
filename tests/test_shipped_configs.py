"""The configs and manifests this project ships are part of the product.

`deploy/k8s/configmap.yaml` routed nuclei to a `kubernetes` target with no URL,
so the Kubernetes Job the README advertises ran `nuclei -u ''` on every scan
and reported it as a normal, finding-free run. `Config.validate()` was happy:
kubernetes targets are exempt from the endpoint check because kube-hunter
reaches a cluster without one, and `handles()` looked only at the target type.

Nothing tested the files themselves. These do.
"""
import yaml

import pytest

from yubel.config import Config
from yubel.engines import select_for
from yubel.engines.base import Engine

from test_workflows import ROOT

#: Engines that reach their target over a URL. kube-hunter and graphw00f are
#: the exceptions — a cluster and a fingerprint probe respectively.
_NEEDS_A_URL = ("nuclei", "zap", "nikto", "wapiti", "dalfox", "sqlmap",
                "testssl", "katana", "httpx", "schemathesis", "graphql-cop")


def _configs():
    """Every config this repository ships, as (label, dict)."""
    out = [("examples/yubel.yaml",
            yaml.safe_load((ROOT / "examples" / "yubel.yaml").read_text()))]

    cm = yaml.safe_load((ROOT / "deploy" / "k8s" / "configmap.yaml").read_text())
    out.append(("deploy/k8s/configmap.yaml",
                yaml.safe_load(cm["data"]["yubel.yaml"])))

    values = yaml.safe_load(
        (ROOT / "deploy" / "helm" / "yubel" / "values.yaml").read_text())
    out.append(("deploy/helm/yubel/values.yaml", values["config"]))
    return out


SHIPPED = _configs()
IDS = [label for label, _ in SHIPPED]


@pytest.mark.parametrize("label,data", SHIPPED, ids=IDS)
def test_every_shipped_config_validates(label, data):
    errors = Config.from_dict(data).validate()
    assert errors == [], f"{label}: {errors}"


@pytest.mark.parametrize("label,data", SHIPPED, ids=IDS)
def test_no_shipped_config_sends_a_url_engine_at_an_empty_target(label, data):
    """The bug this file exists for: an engine invoked with no address.

    Running with an empty endpoint is not an error the operator ever sees — the
    engine exits cleanly, contributes nothing, and the run table says `ok`.
    """
    config = Config.from_dict(data)
    offenders = []
    for target in config.targets:
        if target.endpoint():
            continue
        for engine in select_for(target, config.engines, config.disable,
                                 config.options,
                                 include_opt_in=config.include_opt_in):
            if engine.name in _NEEDS_A_URL:
                offenders.append(f"{engine.name} -> {target.label}")
    assert not offenders, (
        f"{label}: engine(s) routed at a target with no endpoint: "
        + ", ".join(offenders))


@pytest.mark.parametrize("label,data", SHIPPED, ids=IDS)
def test_no_shipped_config_asks_for_an_active_scan_by_accident(label, data):
    """An active ZAP scan has to be a deliberate line in a config, not a default."""
    mode = (data.get("options", {}) or {}).get("zap", {}).get("mode")
    assert mode in (None, "baseline", "full"), f"{label}: zap mode {mode!r}"


def test_the_starter_config_and_the_example_agree():
    """`yubel init` writes one of these; `examples/` shows the other."""
    from yubel import templates

    assert yaml.safe_load(templates.STARTER_CONFIG) == yaml.safe_load(
        (ROOT / "examples" / "yubel.yaml").read_text())


# --------------------------------------------------------------------------
# Read-only root filesystems need every written path mounted
# --------------------------------------------------------------------------

def _mount_paths(text: str):
    return set(__import__("re").findall(r"mountPath:\s*([^\s,}]+)", text))


def test_the_raw_manifest_and_the_chart_mount_the_same_paths():
    """The chart drifted: `deploy/k8s/job.yaml` gained `/home/yubel` for the
    nuclei fix and the Helm template did not, so a `helm install` still hit the
    failure the raw manifest had just been fixed for — with the README
    advertising both as equivalent."""
    raw = _mount_paths((ROOT / "deploy" / "k8s" / "job.yaml").read_text())
    chart = _mount_paths(
        (ROOT / "deploy" / "helm" / "yubel" / "templates" / "job.yaml").read_text())
    assert raw == chart, f"raw manifest {sorted(raw)} vs chart {sorted(chart)}"


def _sets_read_only_root(path: str) -> bool:
    """The chart puts `securityContext` in values.yaml, not in the template.

    Grepping only the template made this look like it had no read-only root,
    which turned the assertion below into a skip — a check that quietly stops
    checking is the failure mode this whole suite exists to remove.
    """
    if "readOnlyRootFilesystem: true" in (ROOT / path).read_text():
        return True
    if "helm" not in path:
        return False
    values = yaml.safe_load(
        (ROOT / "deploy" / "helm" / "yubel" / "values.yaml").read_text())
    return bool((values.get("securityContext") or {})
                .get("readOnlyRootFilesystem"))


@pytest.mark.parametrize("path", [
    "deploy/k8s/job.yaml",
    "deploy/helm/yubel/templates/job.yaml",
])
def test_a_read_only_root_mounts_home_and_tmp(path):
    assert _sets_read_only_root(path), (
        f"{path} no longer sets readOnlyRootFilesystem — if that is "
        f"deliberate, this test needs rewriting rather than skipping")
    mounts = _mount_paths((ROOT / path).read_text())
    for needed in ("/tmp", "/home/yubel"):
        assert needed in mounts, f"{path} has no writable {needed}"


# --------------------------------------------------------------------------
# Option values, not just option keys
# --------------------------------------------------------------------------

def test_an_unknown_option_value_is_a_config_error():
    """`zap: {mode: passive}` used to be accepted and silently run the default.

    Unknown option *keys* were already rejected; a known key holding a value no
    adapter understands is the same failure one level down.
    """
    errors = Config(targets=[], options={"zap": {"mode": "passive"}}).validate()
    assert any("options.zap.mode" in e for e in errors), errors


def test_the_documented_option_values_are_accepted():
    from yubel.engines.zap import ZapEngine

    for mode in ZapEngine.MODES:
        assert ZapEngine.option_errors({"mode": mode}) == []
    assert ZapEngine.option_errors({}) == []


def test_the_base_class_accepts_anything_it_has_not_enumerated():
    assert Engine.option_errors({"whatever": 1}) == []
