"""`docs/engines.md` is generated, so it cannot drift and cannot be incomplete.

Eleven of the twenty-four `options` keys in use were documented nowhere a user
would read — including `timeout`, which applies to every engine and is the
first knob anyone reaches for, and `keep_workdir`, which is the only way to
inspect a failed engine's raw output.

The fix is not "write the table"; a hand-written table goes stale on the next
engine. These tests make the code the source of truth: the doc is generated
from the registry, and an engine that reads an undocumented option fails CI.
"""
import importlib.util
import inspect
import re
import subprocess
import sys
from pathlib import Path

import pytest

from yubel.engines import ALL_ENGINES

ROOT = Path(__file__).resolve().parent.parent
GENERATOR = ROOT / "scripts" / "gen_engines.py"
DOC = ROOT / "docs" / "engines.md"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_engines", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_committed_doc_matches_the_code():
    """Run the generator and compare, so a stale doc is a red build."""
    result = subprocess.run([sys.executable, str(GENERATOR), "--check"],
                            capture_output=True, text=True, cwd=str(ROOT))
    assert result.returncode == 0, (
        result.stdout + result.stderr
        + "\n\nRun: python3 scripts/gen_engines.py")


@pytest.mark.parametrize("engine_cls", ALL_ENGINES,
                         ids=[c.name for c in ALL_ENGINES])
def test_every_option_an_engine_reads_is_documented(engine_cls):
    """Adding `self.options.get("new_knob")` without a description fails here.

    This is the check that keeps the doc honest over time — the table itself
    is generated, so the only way it can go wrong is a missing description.
    """
    if engine_cls.name == "demo":
        pytest.skip("demo engine is not user-facing")

    generator = _generator()
    shared = set(generator.DESCRIPTIONS["*"])
    documented = set(generator.DESCRIPTIONS.get(engine_cls.name, {})) | shared

    read = set(re.findall(r'self\.options\.get\(\s*["\']([^"\']+)["\']',
                          inspect.getsource(engine_cls)))
    missing = sorted(read - documented)
    assert not missing, (
        f"{engine_cls.name} reads undocumented options {missing}; "
        f"add them to DESCRIPTIONS in scripts/gen_engines.py")


def test_the_doc_names_the_engines_that_cannot_carry_credentials():
    """The auth gap has to be stated, not left as an absence."""
    text = DOC.read_text(encoding="utf-8")
    assert "**Auth = no**" in text
    assert "scans anonymously" in text
    for name in ("zap", "nikto", "testssl", "katana"):
        assert f"`{name}`" in text


def test_the_doc_records_that_grpc_has_no_engine():
    text = DOC.read_text(encoding="utf-8")
    grpc_row = [line for line in text.splitlines() if line.startswith("| `grpc`")]
    assert grpc_row, "grpc row missing from the routing table"
    assert "**none**" in grpc_row[0]
