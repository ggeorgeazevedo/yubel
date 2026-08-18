"""The operator's own credentials must not reach the reports.

Yubel injects whatever it is given into the engines (`-H "Authorization: …"`,
`--auth-password`, cookies), and those values come back in `EngineRun.command`
— serialised into `yubel.json` — and, because nuclei runs with `-irr`, in
`Finding.request`/`.response`, rendered verbatim in the HTML report.
"""
import json
import os
import shlex

from yubel.engines.nuclei import NucleiEngine
from yubel.engines.wapiti import WapitiEngine
from yubel.models import Auth, Target, TargetType
from yubel.redact import (MASK, redact_argv, redact_text, secrets_of)

TOKEN = "s3cr3t-production-token-value"
URL = "https://app.example.com"


def _target():
    return Target(type=TargetType.WEB, url=URL,
                  auth=Auth(kind="bearer", token=TOKEN))


def test_argv_masks_header_values_but_keeps_the_header_name():
    argv = ["nuclei", "-u", URL, "-H", f"Authorization: Bearer {TOKEN}", "-jsonl"]
    out = redact_argv(argv, [TOKEN])
    assert TOKEN not in out
    # Compare the whole parsed argv, element by element. This pins exactly what
    # changed and what did not — including that the URL survives as ONE
    # argument, which is the point of shlex.quote — and it avoids asserting a
    # substring against a URL, which is the shape of an incomplete host check.
    assert shlex.split(out) == [
        "nuclei", "-u", URL, "-H", f"Authorization: {MASK}", "-jsonl"]


def test_argv_masks_whole_value_flags():
    out = redact_argv(["wapiti", "--auth-user", "admin",
                       "--auth-password", "hunter2"], [])
    assert "hunter2" not in out
    assert "admin" in out          # a username is not a credential
    out = redact_argv(["tool", "--api-key=abcdef123456"], [])
    assert "abcdef123456" not in out


def test_query_string_credentials_are_masked():
    out = redact_argv(["httpx", "-u", "https://x/cb?access_token=zzzzzzzz&id=1"], [])
    assert "zzzzzzzz" not in out
    assert "id=1" in out           # ordinary parameters survive


def test_raw_http_keeps_every_line_it_does_not_mask():
    """Regression: an inline header pattern that crossed newlines swallowed
    every following header as part of the "value" and dropped them."""
    raw = (f"GET /admin HTTP/1.1\nHost: app.example.com\n"
           f"Authorization: Bearer {TOKEN}\nCookie: session=abcd1234efgh\n"
           f"User-Agent: Nuclei\nX-Trace: keep-me\n")
    out = redact_text(raw, [TOKEN])
    assert TOKEN not in out and "abcd1234efgh" not in out
    for kept in ("GET /admin HTTP/1.1", "Host: app.example.com",
                 "User-Agent: Nuclei", "X-Trace: keep-me"):
        assert kept in out, f"redaction dropped {kept!r}"
    assert out.count(MASK) == 2


def test_discovered_secrets_are_not_destroyed():
    """A DAST tool reports credentials it finds ON THE TARGET. Blanking those
    would destroy the finding — only our own injected values are masked."""
    body = "Exposed AWS key in response body: AKIAIOSFODNN7EXAMPLE"
    assert "AKIAIOSFODNN7EXAMPLE" in redact_text(body, [TOKEN])


def test_nuclei_proof_fields_are_redacted(tmp_path):
    target = _target()
    event = {
        "info": {"name": "Exposed admin panel"},
        "matched-at": "https://app.example.com/admin",
        "request": (f"GET /admin HTTP/1.1\nHost: app.example.com\n"
                    f"Authorization: Bearer {TOKEN}\nUser-Agent: Nuclei\n"),
        "response": "HTTP/1.1 200 OK\nSet-Cookie: sid=DEADBEEFCAFE\nServer: nginx\n",
    }
    with open(os.path.join(tmp_path, "nuclei-full.jsonl"), "w") as fh:
        fh.write(json.dumps(event) + "\n")

    finding = NucleiEngine().parse(target, str(tmp_path), "")[0]
    assert TOKEN not in finding.request
    assert "DEADBEEFCAFE" not in finding.response
    # the proof is still a proof
    assert "User-Agent: Nuclei" in finding.request
    assert "Server: nginx" in finding.response


def test_no_secret_survives_into_the_serialised_report(tmp_path):
    """The end-to-end property that matters: yubel.json is what CI uploads as
    an artifact and what teams commit as a --baseline."""
    target = _target()
    # each engine is called with its own signature: probing with a
    # try/except TypeError makes a statically invalid call, and CodeQL is
    # right to flag it (py/inheritance/incorrect-overriding-signature)
    for name, argv in (
        ("nuclei", NucleiEngine().build_command(target, str(tmp_path))),
        ("wapiti", WapitiEngine().build_command(target, str(tmp_path))),
    ):
        blob = json.dumps({"command": redact_argv(argv, secrets_of(target.auth))})
        assert TOKEN not in blob, f"{name} leaked the token"


def test_secrets_of_collects_every_credential_shape():
    assert secrets_of(Auth(kind="bearer", token=TOKEN)) == [TOKEN]
    assert "hunter2" in secrets_of(Auth(kind="basic", username="a", password="hunter2"))
    assert "v" in secrets_of(Auth(kind="header", headers={"X-Api-Key": "v"}))
    assert secrets_of(None) == []
