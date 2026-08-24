"""A report has to say which scanner versions produced it.

"The same scan yields the same result, every time" is on the front page. For a
scanner the tool version *is* the finding set, and two of the engines —
`wapiti` and `sqlmap` — come from apt with no version fixed, so an image built
three months apart runs a different scan. Pinning those versions in Debian
stable would trade that for a build that breaks the day a security update
lands. Recording costs nothing and answers the question that actually gets
asked of an old report: which versions produced this?

So every run records the version of the tool that produced it, the reports show
it, and `yubel engines` shows what is installed here.
"""
import pytest

from yubel.engines import registry
from yubel.engines.base import Engine, _VERSIONS
from yubel.models import EngineRun, ScanResult, Target, TargetType

ENGINES = sorted(registry().items())
IDS = [name for name, _ in ENGINES]


@pytest.fixture(autouse=True)
def _clear_cache():
    _VERSIONS.clear()
    yield
    _VERSIONS.clear()


class _Fake(Engine):
    name = "fake"
    binary = "fake-scanner"
    supports = (TargetType.WEB,)


def _run(monkeypatch, stdout="", stderr="", boom=None):
    import subprocess

    def fake_run(argv, **kwargs):
        if boom:
            raise boom
        return subprocess.CompletedProcess(argv, 0, stdout, stderr)

    monkeypatch.setattr(subprocess, "run", fake_run)


def test_the_version_is_read_from_the_tool(monkeypatch):
    _run(monkeypatch, stdout="fake-scanner v2.13.0\n")
    assert _Fake().tool_version() == "2.13.0"


def test_a_version_on_stderr_still_counts(monkeypatch):
    """Plenty of tools print it there, and half of those exit non-zero too."""
    _run(monkeypatch, stderr="fake-scanner 1.4\n")
    assert _Fake().tool_version() == "1.4"


def test_an_unknown_version_is_blank_not_a_guess(monkeypatch):
    _run(monkeypatch, stdout="no version here")
    assert _Fake().tool_version() == ""


def test_a_tool_that_blows_up_costs_a_blank_column_not_the_scan(monkeypatch):
    """A version probe must never be able to fail a scan. It is metadata."""
    _run(monkeypatch, boom=OSError("boom"))
    assert _Fake().tool_version() == ""


def test_the_probe_runs_once_per_engine(monkeypatch):
    """A scan runs each engine once per target; asking N times is N
    subprocesses for one answer."""
    calls = []
    import subprocess

    def counting(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "v9.9.9", "")

    monkeypatch.setattr(subprocess, "run", counting)
    assert _Fake().tool_version() == "9.9.9"
    assert _Fake().tool_version() == "9.9.9"
    assert len(calls) == 1


def test_an_engine_with_no_binary_asks_nothing(monkeypatch):
    """ZAP resolves a script rather than a single binary, and `demo` has no
    process at all. Neither should spawn a probe."""
    _run(monkeypatch, boom=AssertionError("should not have been called"))

    class NoBinary(Engine):
        name = "nobinary"

    assert NoBinary().tool_version() == ""


@pytest.mark.parametrize("name,cls", ENGINES, ids=IDS)
def test_an_engine_that_cannot_be_asked_says_so_explicitly(name, cls):
    """`version_args = ()` is a declaration that this tool has no version
    flag — kube-hunter prints usage if you ask. The point is that it is
    written down, not discovered by a support ticket."""
    assert isinstance(cls.version_args, tuple)


def test_the_run_record_carries_the_version(monkeypatch):
    """The record is what reaches `yubel.json`, so this is the whole chain."""
    import subprocess

    def fake_run(argv, **kwargs):
        if argv[1:] == ["--version"]:
            return subprocess.CompletedProcess(argv, 0, "fake 3.2.1", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    class Ok(_Fake):
        def build_command(self, target, workdir):
            return [self.binary, "-u", target.endpoint()]

        def parse(self, target, workdir, stdout):
            return []

    engine = Ok()
    engine.available = lambda: True
    _findings, record = engine.run(
        Target(type=TargetType.WEB, url="https://example.com", name="site"))
    assert record.tool_version == "3.2.1"


def test_a_skipped_run_does_not_probe(monkeypatch):
    """No point asking the version of a binary that is not installed."""
    _run(monkeypatch, boom=AssertionError("should not have been called"))
    engine = _Fake()
    engine.available = lambda: False
    _findings, record = engine.run(
        Target(type=TargetType.WEB, url="https://example.com", name="site"))
    assert record.status == "skipped"
    assert record.tool_version == ""


# --------------------------------------------------------------------------
# The reports
# --------------------------------------------------------------------------

def _result():
    result = ScanResult(version="test")
    result.runs.append(EngineRun(engine="nuclei", target="site", status="ok",
                                 tool_version="3.4.10", findings=2))
    result.finished_at = 1.0
    return result


def test_the_html_report_names_the_version(tmp_path):
    from yubel.reporters.html_reporter import write_html

    path = tmp_path / "yubel.html"
    write_html(_result(), str(path))
    assert "3.4.10" in path.read_text(encoding="utf-8")


def test_the_markdown_report_names_the_version(tmp_path):
    from yubel.reporters.markdown_reporter import write_markdown

    path = tmp_path / "yubel.md"
    write_markdown(_result(), str(path))
    assert "3.4.10" in path.read_text(encoding="utf-8")


def test_the_json_report_carries_it(tmp_path):
    """The machine-readable one matters most: this is what a later run gets
    diffed against."""
    import json

    from yubel.reporters.json_reporter import write_json

    path = tmp_path / "yubel.json"
    write_json(_result(), str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["engine_runs"][0]["tool_version"] == "3.4.10"


# --------------------------------------------------------------------------
# Unmaintained upstream
# --------------------------------------------------------------------------

def test_kube_hunter_is_marked_unmaintained():
    """Aqua archived it. The tool still works and is still the only
    open-source engine that pentests a cluster from the inside, so removing
    it would cost coverage and gain nothing. What was wrong was the silence:
    the table listed it exactly like the maintained ones."""
    assert registry()["kube-hunter"].unmaintained


def test_the_engines_doc_says_which_engines_are_unmaintained():
    from pathlib import Path

    doc = (Path(__file__).resolve().parent.parent / "docs" / "engines.md")
    text = doc.read_text(encoding="utf-8")
    assert "*(unmaintained)*" in text
    assert "archived upstream" in text
