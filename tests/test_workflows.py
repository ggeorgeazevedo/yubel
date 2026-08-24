"""CI configuration is code that runs with credentials, so it gets tests too.

The release workflow held `contents: write` and `id-token: write` — the PyPI
Trusted Publisher — and referenced `pypa/gh-action-pypi-publish@release/v1`.
That is a *branch*: whatever is pushed to it executes in that job and can mint
the OIDC token and publish an arbitrary wheel as `yubel`, without one commit
landing in this repository. Every other action was on a mutable tag, which is
the same exposure with one more step.

Pinning is only durable if un-pinning fails the build, so that is what these
assert. Dependabot already tracks `github-actions` and updates a SHA pin in
place, keeping the version comment — so the ongoing cost is a review, not a
manual lookup.
"""
import re
from pathlib import Path

import pytest
import yaml   # a hard dependency of the package, so never conditionally skipped

ROOT = Path(__file__).resolve().parent.parent
#: `action.yml` is included deliberately: it is the file the Marketplace
#: runs inside a consumer's repository, and it was the one place still on a
#: mutable tag — the front door left unlocked while every window was barred.
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml")) + \
    [ROOT / "action.yml"]

#: `owner/repo/subpath@<40 hex>`, optionally followed by a version comment.
_PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)")


def test_there_are_workflows_to_check():
    """Guards the glob itself — an empty list would make everything below pass."""
    assert WORKFLOWS, "no workflows found; did .github/workflows move?"


@pytest.mark.parametrize("path", WORKFLOWS, ids=[p.name for p in WORKFLOWS])
def test_every_action_is_pinned_to_a_commit(path):
    offenders = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        found = _USES.match(line)
        if not found:
            continue
        ref = found.group(1)
        if ref.startswith("./") or ref.startswith("docker://"):
            continue                     # local action / image, not a git ref
        if not _PINNED.match(ref):
            offenders.append(f"{path.name}:{number} {ref}")
    assert not offenders, (
        "actions must be pinned to a full commit SHA with a `# vX.Y.Z` "
        "comment: " + ", ".join(offenders))


@pytest.mark.parametrize("path", WORKFLOWS, ids=[p.name for p in WORKFLOWS])
def test_every_pin_carries_a_version_comment(path):
    """A bare SHA is unreviewable; the comment is what makes a bump readable."""
    missing = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if _USES.match(line) and "@" in line and re.search(r"@[0-9a-f]{40}", line):
            if not re.search(r"#\s*v?\d", line):
                missing.append(f"{path.name}:{number}")
    assert not missing, "pinned action without a version comment: " + ", ".join(missing)


def test_the_release_build_job_cannot_reach_the_publishing_credentials():
    """The job that runs third-party build tooling must not inherit write scopes.

    `build` runs `pip install build` / `pip install twine`. The workflow-level
    grant exists for the two publishing jobs; inherited by `build`, it is
    enough to read $ACTIONS_ID_TOKEN_REQUEST_TOKEN directly and route around
    the `environment: pypi` gate that is supposed to be the only path to PyPI.
    """
    data = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml")
                          .read_text(encoding="utf-8"))
    job = data["jobs"]["build"]
    assert "permissions" in job, (
        "the release build job inherits the workflow's write permissions")
    assert job["permissions"].get("contents") == "read"
    assert "id-token" not in job["permissions"]


def test_release_build_tools_are_version_pinned():
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    for tool in ("build", "twine"):
        assert re.search(rf'pip install "{tool}==\d', text), (
            f"`pip install {tool}` is unpinned in the job that produces the "
            f"artifact published to PyPI")


# --------------------------------------------------------------------------
# The Dockerfile is shell, and shell has a parser
# --------------------------------------------------------------------------

DOCKERFILE = ROOT / "Dockerfile"

#: Build args, so a RUN body is a complete script when handed to `sh -n`.
_ARGS = {"TARGETARCH": "amd64", "NUCLEI_VERSION": "v0", "HTTPX_VERSION": "v0",
         "KATANA_VERSION": "v0", "DALFOX_VERSION": "v0", "ZAP_VERSION": "0.0.0",
         "NIKTO_VERSION": "0.0.0", "TESTSSL_VERSION": "v0",
         "GRAPHQL_COP_VERSION": "0.0"}


def _run_blocks():
    """Every RUN instruction, joined across its line continuations."""
    blocks, current = [], None
    for line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        if current is not None:
            current.append(line)
            if not line.rstrip().endswith("\\"):
                blocks.append(current)
                current = None
        elif re.match(r"^\s*RUN\s", line):
            current = [line]
            if not line.rstrip().endswith("\\"):
                blocks.append(current)
                current = None
    if current:
        blocks.append(current)
    return blocks


def test_the_dockerfile_has_run_instructions_to_check():
    assert len(_run_blocks()) > 5


def test_no_comment_hides_inside_a_run_continuation():
    """A `#` line inside a continued RUN is at the mercy of two parsers.

    Whether it is stripped by the Dockerfile frontend or passed through to the
    shell — where it comments out the rest of *that* line — depends on the
    builder. A comment that changes what runs depending on who builds is not a
    comment. Put it above the instruction.
    """
    offenders = [block[0].strip()[:60] for block in _run_blocks()
                 if any(line.lstrip().startswith("#") for line in block[1:])]
    assert not offenders, (
        "move these comments above their RUN: " + "; ".join(offenders))


def test_every_run_body_is_valid_shell():
    """`sh -n` parses without executing — catches the quoting mistakes that
    otherwise surface only after a ten-minute image build."""
    import subprocess
    import sys

    failures = []
    for block in _run_blocks():
        body = re.sub(r"^\s*RUN\s+", "", "\n".join(block), count=1)
        body = body.replace("\\\n", "\n")
        for name, value in _ARGS.items():
            body = body.replace("${%s}" % name, value)
        done = subprocess.run(["sh", "-n"], input=body,
                              capture_output=True, text=True)
        if done.returncode != 0:
            failures.append(f"{block[0].strip()[:50]}: {done.stderr.strip()}")
    assert not failures, "\n".join(failures)


# --------------------------------------------------------------------------
# One version, and a changelog that resolves
# --------------------------------------------------------------------------

VERSION = re.compile(r'(?:^version|__version__)\s*=\s*"([^"]+)"', re.M)


def _declared_versions():
    """Every place the project's own version is written down."""
    found = {}
    for path in ("pyproject.toml", "src/yubel/__init__.py"):
        match = VERSION.search((ROOT / path).read_text(encoding="utf-8"))
        assert match, f"no version found in {path}"
        found[path] = match.group(1)
    chart = yaml.safe_load(
        (ROOT / "deploy" / "helm" / "yubel" / "Chart.yaml").read_text(encoding="utf-8"))
    found["deploy/helm/yubel/Chart.yaml (appVersion)"] = str(chart["appVersion"])
    return found


def test_every_declared_version_agrees():
    """Nothing kept `pyproject.toml`, `__init__.py` and the chart in step.

    They happened to match; the chart did not, and sat four minor releases
    behind at 0.1.0 while claiming to track the app.
    """
    versions = _declared_versions()
    assert len(set(versions.values())) == 1, versions


def test_the_changelog_has_a_section_for_the_current_version():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    version = _declared_versions()["pyproject.toml"]
    assert re.search(rf"^## \[{re.escape(version)}\]", text, re.M), (
        f"CHANGELOG has no `## [{version}]` section — bump one and not the "
        f"other and the release notes describe the wrong code")


def test_every_changelog_section_resolves_to_a_link():
    """`[Unreleased]` had no definition at all, so it rendered as a dangling
    reference on GitHub — the one heading a reader clicks first."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = set(re.findall(r"^## \[([^\]]+)\]", text, re.M))
    links = set(re.findall(r"^\[([^\]]+)\]:", text, re.M))
    assert not headings - links, f"sections with no link: {sorted(headings - links)}"
    assert not links - headings, f"links with no section: {sorted(links - headings)}"


def test_no_release_section_repeats_a_heading():
    """Keep a Changelog expects one `### Fixed` per release. `[Unreleased]`
    had eight, so anything grouping by heading produced eight sections."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    blocks = re.split(r"^## \[", text, flags=re.M)[1:]
    offenders = []
    for block in blocks:
        name = block.split("]", 1)[0]
        headings = re.findall(r"^### (.+)$", block, re.M)
        for heading in set(headings):
            if headings.count(heading) > 1:
                offenders.append(f"[{name}] has {headings.count(heading)}x "
                                 f"'### {heading}'")
    assert not offenders, "; ".join(offenders)
