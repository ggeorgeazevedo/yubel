"""The palette is a rule, not a preference, so it is asserted like one.

Yubel's identity used to live as literal hex strings in six hand-edited SVGs,
a diagram script, the HTML report and `action.yml`, and they had already
drifted apart. These tests make `scripts/brand.py` the single source and, more
importantly, they encode the one rule that actually matters in a security
report: **a colour must not have to be disambiguated between "brand" and
"finding"**. Crimson means Critical and gold-olive means Medium; if brand
crimson or brand gold appeared on a link, a chip or a border, the reader would
have to work out which meaning applied.
"""
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


def _brand():
    spec = importlib.util.spec_from_file_location("brand", SCRIPTS / "brand.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(script, *args):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args],
                          capture_output=True, text=True, cwd=str(ROOT))


# --------------------------------------------------------------------------
# Generated assets cannot drift from the code that generates them
# --------------------------------------------------------------------------

@pytest.mark.parametrize("script", ["gen_logo.py", "gen_diagram.py"])
def test_the_committed_assets_match_the_generator(script):
    result = _run(script, "--check")
    assert result.returncode == 0, (
        result.stdout + result.stderr + f"\n\nRun: python3 scripts/{script}")


def test_every_logo_file_referenced_by_the_readme_exists():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for ref in set(re.findall(r"docs/logo/[\w.-]+", readme)):
        assert (ROOT / ref).exists(), f"README points at a missing {ref}"


# --------------------------------------------------------------------------
# The report's frame stays out of the severity scale's way
# --------------------------------------------------------------------------

def _report_source() -> str:
    return (ROOT / "src" / "yubel" / "reporters" / "html_reporter.py").read_text(
        encoding="utf-8")


def _css_var(name: str, source: str):
    """Every value `--name` is given, across the light and dark blocks."""
    return re.findall(rf"--{name}\s*:\s*(#[0-9a-fA-F]{{3,8}})", source)


def test_the_report_accent_matches_brand_py():
    b = _brand()
    found = _css_var("accent", _report_source())
    assert found == [b.REPORT_ACCENT, b.REPORT_ACCENT_DARK], found


def test_the_report_accent_is_not_a_severity_colour():
    """A graphite link cannot be mistaken for a Critical or a Medium finding."""
    b = _brand()
    source = _report_source()
    severities = set(re.findall(r'"(?:Critical|High|Medium|Low|Info)":\s*'
                                r'"(#[0-9a-fA-F]{6})"', source))
    assert severities, "could not find the severity table — did _SEV move?"
    for accent in (b.REPORT_ACCENT, b.REPORT_ACCENT_DARK):
        assert accent.lower() not in {s.lower() for s in severities}


def test_brand_gold_and_crimson_appear_only_in_the_mark():
    """The one place a brand colour is allowed inside a report.

    They are declared as `--brand-*` custom properties and may be referenced
    only from the masthead `<svg>`. If a future edit paints a chip or a border
    with them, this fails — which is the entire point.
    """
    b = _brand()
    source = _report_source()

    declared = _css_var("brand-gold", source) + _css_var("brand-crimson", source)
    assert b.GOLD in declared and b.CRIMSON in declared, declared

    mark = re.search(r'<svg class="eye".*?</svg>', source, re.S)
    assert mark, "masthead mark not found"
    outside = source.replace(mark.group(0), "")
    outside = re.sub(r"--brand-[\w-]+\s*:\s*#[0-9a-fA-F]{3,8}", "", outside)
    stray = re.findall(r"var\(--brand-[\w-]+\)", outside)
    assert not stray, f"brand colour used outside the mark: {stray}"


# --------------------------------------------------------------------------
# The old palette is gone
# --------------------------------------------------------------------------

_OLD_PURPLES = ["#5b4aa6", "#8a72d8", "#3f3d8c", "#a7a3e6", "#1c1533",
                "#0d0a1a", "#120e24", "#2a2050", "#332a52"]


def test_no_file_still_paints_the_old_purple():
    """Catches a half-finished repaint — the failure mode of every rebrand."""
    targets = [ROOT / "src", ROOT / "scripts", ROOT / "docs" / "logo",
               ROOT / "action.yml", ROOT / "README.md"]
    offenders = []
    for base in targets:
        files = [base] if base.is_file() else [
            p for p in base.rglob("*")
            if p.is_file() and p.suffix in {".py", ".svg", ".yml", ".md"}]
        for path in files:
            text = path.read_text(encoding="utf-8", errors="ignore")
            for old in _OLD_PURPLES:
                if old in text.lower():
                    offenders.append(f"{path.relative_to(ROOT)}: {old}")
    assert not offenders, "old palette still present: " + ", ".join(offenders)


def test_the_action_badge_colour_comes_from_brand_py():
    b = _brand()
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    found = re.search(r'^\s*color:\s*"([\w-]+)"', action, re.M)
    assert found, "action.yml has no branding colour"
    assert found.group(1) == b.ACTION_COLOR
    # GitHub only renders a fixed set; anything else silently falls back.
    assert b.ACTION_COLOR in {"white", "yellow", "blue", "green", "orange",
                              "red", "purple", "gray-dark"}
