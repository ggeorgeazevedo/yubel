"""Keep the operator's own credentials out of the reports.

Yubel injects the credentials it is given into the engines it drives —
`-H "Authorization: Bearer …"`, `--auth-password`, `Cookie:` headers. Those
values come straight back in two places that get written to disk and then
shipped around:

* ``EngineRun.command`` — the exact argv, serialised into ``yubel.json``,
  which is the file CI uploads as an artifact and teams commit as a
  ``--baseline``;
* ``Finding.request`` / ``.response`` / ``.raw`` — nuclei runs with ``-irr``
  and echoes back the very headers we sent, and wapiti stores a full
  ``curl_command``. Both are rendered verbatim in the HTML report.

The redaction here is deliberately conservative: it masks the *value* and
keeps the header or flag name, so a report still shows that a request was
authenticated without showing what with.

Note the one thing this must NOT do: a DAST tool legitimately reports secrets
it *discovers on the target*, and blanking those would destroy the finding.
So only known-sensitive header names, known-sensitive argv flags, and the
literal credential values we were handed are masked — never evidence at large.
"""
from __future__ import annotations

import re
import shlex
from typing import Iterable, List, Sequence

MASK = "***"

#: Header names whose value is a credential. Matched case-insensitively at the
#: start of a line (raw HTTP) or of a standalone argv element (`-H` payloads).
_SECRET_HEADERS = (
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "apikey", "x-auth-token", "auth-token",
    "authentication", "x-amz-security-token", "x-csrf-token",
)

_HEADER_RE = re.compile(
    r"(?im)^([ \t]*(?:" + "|".join(_SECRET_HEADERS) + r")[ \t]*:[ \t]*)(.+)$")

#: Same, but inside a one-line command (a curl string, a shell log): there is
#: no line anchor, so stop at the quote that closes the header argument — and,
#: critically, at the end of the line. Letting this cross a newline would eat
#: every following header as part of the "value" and silently drop it.
_INLINE_HEADER_RE = re.compile(
    r"(?i)((?:" + "|".join(_SECRET_HEADERS) + r")[ \t]*:[ \t]*)([^'\"\r\n]+)")

#: Query-string parameters that carry credentials. Conservative on purpose —
#: a false positive here silently destroys a real finding's evidence.
_SECRET_PARAMS = (
    "access_token", "id_token", "refresh_token", "token", "api_key", "apikey",
    "client_secret", "secret", "password", "passwd", "pwd", "sig", "signature",
    "sessionid", "session_id",
)

_PARAM_RE = re.compile(
    r"(?i)([?&](?:" + "|".join(_SECRET_PARAMS) + r")=)[^&\s\"'<>]+")

#: argv flags whose value is entirely a secret.
_SECRET_VALUE_FLAGS = {
    "--auth-password", "--password", "--passwd", "--token", "--api-key",
    "--apikey", "--bearer", "--auth-token", "--cookie", "--cookies",
}

#: argv flags whose value is a header — mask the header value, keep its name,
#: because "this ran authenticated" is information worth keeping in a report.
_HEADER_FLAGS = {"-H", "--header", "--headers"}


def redact_headers(text: str) -> str:
    """Mask the value of any credential-bearing header in `text`."""
    if not text:
        return text
    text = _HEADER_RE.sub(lambda m: m.group(1) + MASK, text)
    return _INLINE_HEADER_RE.sub(lambda m: m.group(1) + MASK, text)


def redact_query(text: str) -> str:
    """Mask credential-looking query-string parameter values in `text`."""
    if not text:
        return text
    return _PARAM_RE.sub(lambda m: m.group(1) + MASK, text)


def scrub(text: str, secrets: Iterable[str]) -> str:
    """Mask every literal occurrence of `secrets`.

    This is the belt to the header matching's braces: whatever shape a value
    comes back in — echoed in a body, reflected in a URL, wrapped by a tool we
    do not model — if it is a credential we were handed, it does not survive.
    """
    if not text:
        return text
    for s in sorted({s for s in secrets if s and len(s) >= 4}, key=len,
                    reverse=True):
        text = text.replace(s, MASK)
    return text


def redact_text(text: str, secrets: Iterable[str] = ()) -> str:
    """Full redaction pass for free-form text (raw HTTP, curl lines, logs)."""
    return scrub(redact_query(redact_headers(text)), secrets)


def secrets_of(auth) -> List[str]:
    """Every literal credential value carried by an `Auth`."""
    if auth is None:
        return []
    out = [getattr(auth, "token", "") or "", getattr(auth, "password", "") or ""]
    out += [v for v in (getattr(auth, "headers", None) or {}).values() if v]
    return [s for s in out if s]


def redact_argv(argv: Sequence[str], secrets: Iterable[str] = ()) -> str:
    """Render argv as a shell-safe string with credential values masked.

    Quoting is `shlex.quote`, so the result is unambiguous about where each
    argument ends — the previous plain `" ".join(...)` made a header with
    spaces look like several arguments.
    """
    out: List[str] = []
    expect = None                      # what the *next* element means
    for arg in argv:
        arg = str(arg)
        if expect == "secret":
            out.append(MASK)
            expect = None
            continue
        if expect == "header":
            out.append(shlex.quote(redact_headers(arg)))
            expect = None
            continue

        flag, sep, inline = arg.partition("=")
        if sep and flag in _SECRET_VALUE_FLAGS:
            out.append(f"{flag}={MASK}")
            continue
        if sep and flag in _HEADER_FLAGS:
            out.append(shlex.quote(f"{flag}={redact_headers(inline)}"))
            continue

        if arg in _SECRET_VALUE_FLAGS:
            expect = "secret"
        elif arg in _HEADER_FLAGS:
            expect = "header"
        out.append(shlex.quote(redact_query(arg)))

    return scrub(" ".join(out), secrets)
