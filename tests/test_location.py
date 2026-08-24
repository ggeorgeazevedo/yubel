"""A finding with no location reports *nowhere*, and takes another with it.

Nine adapters guarded `Finding.location` with `dict.get(key, default)`. That
default applies only when the key is **absent** — a scanner emitting the key
with an empty string defeats it, and the finding is born with `location == ""`.

That is not cosmetic. `Finding.fingerprint` falls back to
`(self.location or self.target)`, so every empty-location finding from one
engine on one target collapses into a single fingerprint bucket keyed on
title + cwe, and `ScanResult.dedupe()` merges genuinely distinct findings into
one. The report then shows no address for what survives.

`dalfox.py` was the only adapter that had it right, with an `or`-chain. These
tests hold every adapter to that shape by feeding each one the three values a
real scanner can emit for its address key: absent, empty string, and null.
"""
import json
import os

import pytest

from yubel.models import Target, TargetType

TARGET = Target(type=TargetType.WEB, url="https://app.example.com")

#: adapter -> (filename it reads, how to wrap one record, the address key)
#: Each entry is the smallest document that adapter's `parse()` accepts.
CASES = {
    "nikto": (
        "nikto.json",
        lambda addr: {"vulnerabilities": [
            {"id": "1", "msg": "finding", **({} if addr is _ABSENT
                                             else {"url": addr})}]},
        "url"),
}

#: kube-hunter parses stdout, and a cluster target legitimately has no URL —
#: so its last resort is the label rather than the endpoint.
CLUSTER = Target(type=TargetType.KUBERNETES, name="prod-cluster", k8s_mode="pod")


class _Absent:
    def __repr__(self):
        return "<absent>"


_ABSENT = _Absent()
VALUES = [_ABSENT, "", None]
IDS = ["key absent", "key empty", "key null"]


def _write(tmp_path, name, payload):
    path = os.path.join(str(tmp_path), name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    return str(tmp_path)


@pytest.mark.parametrize("addr", VALUES, ids=IDS)
@pytest.mark.parametrize("engine_name", sorted(CASES), ids=sorted(CASES))
def test_a_finding_always_carries_an_address(engine_name, addr, tmp_path):
    from yubel.engines import instantiate

    filename, build, _ = CASES[engine_name]
    workdir = _write(tmp_path, filename, build(addr))
    findings = instantiate(engine_name).parse(TARGET, workdir, "")

    assert findings, f"{engine_name} parsed nothing — fixture is wrong"
    for finding in findings:
        assert finding.location, (
            f"{engine_name} produced a finding with no location when its "
            f"address key was {addr!r}")


@pytest.mark.parametrize("addr", VALUES, ids=IDS)
def test_kube_hunter_falls_back_to_the_cluster_label(addr, tmp_path):
    """`endpoint()` is empty for a pod-mode cluster, so `or target.endpoint()`
    alone would still leave the finding with no address."""
    from yubel.engines.kubernetes import KubeHunterEngine

    record = {"vulnerability": "issue", "severity": "medium"}
    if addr is not _ABSENT:
        record["location"] = addr
    findings = KubeHunterEngine().parse(
        CLUSTER, str(tmp_path), json.dumps({"vulnerabilities": [record]}))

    assert findings and findings[0].location == CLUSTER.label


@pytest.mark.parametrize("addr", VALUES, ids=IDS)
def test_nuclei_falls_back_through_host_to_the_target(addr, tmp_path):
    """nuclei had no terminal fallback at all: `matched-at` then `host` then
    the empty string, so a record missing both produced no address."""
    from yubel.engines.nuclei import NucleiEngine

    record = {"info": {"name": "issue", "severity": "high"},
              "template-id": "x"}
    if addr is not _ABSENT:
        record["matched-at"] = addr
    path = os.path.join(str(tmp_path), "nuclei-full.jsonl")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")

    findings = NucleiEngine().parse(TARGET, str(tmp_path), "")
    assert findings and findings[0].location == TARGET.endpoint()


@pytest.mark.parametrize("instances,expected", [
    ([], "target"),                       # key present but an empty list
    ([{"uri": ""}], "target"),            # key present but an empty string
    ([{"uri": None}], "target"),          # key present but null
    ([{"uri": "https://app.example.com/x"}], "https://app.example.com/x"),
], ids=["empty list", "empty uri", "null uri", "real uri"])
def test_zap_never_loses_the_address(instances, expected, tmp_path):
    """Two bugs on two lines: `alert.get("instances", [{}])` returns `[]` when
    the key exists and is empty, so the default never fired."""
    from yubel.engines.zap import ZapEngine

    report = {"site": [{"@name": "", "alerts": [
        {"alert": "issue", "riskcode": "2", "instances": instances}]}]}
    path = os.path.join(str(tmp_path), "zap.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle)

    findings = ZapEngine().parse(TARGET, str(tmp_path), "")
    assert findings
    want = TARGET.endpoint() if expected == "target" else expected
    assert findings[0].location == want


def test_two_findings_with_no_address_do_not_merge_into_one():
    """The consequence, stated as a test.

    `fingerprint` uses `(location or target)`. With both locations empty, two
    distinct findings on one target hash identically and `dedupe()` keeps one —
    silent finding loss, which is the whole reason this file exists.
    """
    from yubel.models import Finding, ScanResult

    a = Finding(title="Reflected XSS", severity="high", engine="e",
                target="t", location="https://app.example.com/a", cwe="79")
    b = Finding(title="Reflected XSS", severity="high", engine="e",
                target="t", location="https://app.example.com/b", cwe="79")
    assert a.fingerprint != b.fingerprint

    result = ScanResult()
    result.add([a, b])
    assert len(result.dedupe().findings) == 2


def test_no_adapter_still_guards_a_location_with_a_bare_default():
    """`.get(k, default)` is the wrong shape here; `.get(k) or default` is right.

    A grep, so a new adapter cannot reintroduce the pattern in a key this
    file's fixtures do not happen to cover.
    """
    import inspect
    import re

    from yubel.engines import ALL_ENGINES

    offenders = []
    for cls in ALL_ENGINES:
        source = inspect.getsource(inspect.getmodule(cls))
        for match in re.finditer(r"location=\s*\w+\.get\(\s*[\"'][^\"']+[\"']\s*,",
                                 source):
            line = source[:match.start()].count("\n") + 1
            offenders.append(f"{cls.__module__}:{line}")
    assert not offenders, (
        "location guarded by a bare `.get(key, default)` — an empty value "
        "defeats it; use `(x.get(key) or default)`: "
        + ", ".join(sorted(set(offenders))))
