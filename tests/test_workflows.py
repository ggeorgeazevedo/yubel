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
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))

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
