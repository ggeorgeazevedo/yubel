"""Suite-wide guards that keep the tests from reading the machine they run on.

A test that consults the developer's PATH reports on the developer's PATH.
`test_dalfox_command_targets_given_url` asserted the `url` subcommand and
passed everywhere dalfox was absent — CI, containers — because the version
probe falls back to major 2 when the binary is missing. On a laptop with the
Homebrew build, which is the 3.x Rust line, the subcommand is `scan` and the
test failed. The result depended on what happened to be installed.

The fixture below pins the probe for every test, so a test that cares about the
version has to say which one it means.
"""
import pytest

from yubel.engines.dalfox import DalfoxEngine


@pytest.fixture(autouse=True)
def _pin_dalfox_major(monkeypatch):
    """Default every test to the 2.x line, and never shell out to find out.

    `DalfoxEngine._major` is a class attribute, so a real probe — or a test
    that sets it — would otherwise leak into every test that runs after it.
    """
    monkeypatch.setattr(DalfoxEngine, "_major", None, raising=False)
    monkeypatch.setattr(DalfoxEngine, "_major_version", lambda self: 2)
    yield
    DalfoxEngine._major = None
