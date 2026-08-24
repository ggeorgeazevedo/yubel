#!/usr/bin/env python3
"""Generate docs/engines.md from the engine registry.

The reference has to come from the code, not from someone remembering to
update a table: eleven of the twenty-four `options` keys in use were
documented nowhere a user would read, including `timeout`, which applies to
every engine and is the first knob anyone reaches for.

DESCRIPTIONS below is the one part a human writes. `tests/test_engines_doc.py`
asserts that every option discovered in the code has an entry here and that
the committed doc matches this generator's output — so adding an undocumented
option, or letting the doc drift, fails CI.

    python3 scripts/gen_engines.py            # write docs/engines.md
    python3 scripts/gen_engines.py --check    # exit 1 if the file is stale
"""
from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from yubel.engines import ALL_ENGINES, OPT_IN                    # noqa: E402
from yubel.models import Target, TargetType                      # noqa: E402
from yubel.engines import select_for                             # noqa: E402
from yubel.config import Config                                  # noqa: E402

OUT = ROOT / "docs" / "engines.md"

#: option key -> (default, what it does). Shared keys live under "*".
DESCRIPTIONS = {
    "*": {
        "timeout": ("engine's `default_timeout`",
                    "Seconds before the engine is killed and its run recorded "
                    "as `timeout`. Applies to every engine."),
        "keep_workdir": ("false",
                         "Keep the engine's temporary directory instead of "
                         "deleting it. The only way to inspect a tool's raw "
                         "output when a run reports `error` — this is the "
                         "debug switch."),
    },
    "nuclei": {
        "full": ("true", "Run the full-template pass."),
        "dast": ("true", "Run the parameter-fuzzing (DAST) pass. Disabling "
                         "both falls back to the full pass."),
        "severity": ("low,medium,high,critical",
                     "Comma-separated nuclei severities to keep. Note that "
                     "`info` is **not** included by default — pass "
                     "`info,low,medium,high,critical` to keep it."),
        "offline": ("false", "Air-gapped mode: no OAST/interactsh, no "
                             "template update check."),
        "rate_limit": ("nuclei's default", "Requests per second cap (`-rl`)."),
        "extra_args": ("—", "Extra nuclei flags, as a list or a shell-style "
                            "string."),
    },
    "zap": {
        "mode": ("baseline", "`baseline` runs ZAP's passive spider and is the "
                             "default; `full` runs `zap-full-scan.py`, which "
                             "**actively attacks** the target. Any other value "
                             "is a config error rather than a silent fallback."),
        "api_format": ("openapi", "Spec format for `zap-api-scan.py`."),
        "ajax": ("false", "Enable the AJAX spider for JS-heavy apps."),
    },
    "wapiti": {
        "scope": ("folder", "`page`, `folder`, `domain` or `url`."),
        "depth": ("wapiti's default", "Crawl depth."),
    },
    "nikto": {
        "maxtime": ("600", "Wall-clock cap in seconds passed to nikto "
                           "itself. Always sent; set it to 0 to drop the "
                           "cap."),
        "tuning": ("—", "Nikto tuning string, e.g. `x6` to skip DoS checks."),
    },
    "testssl": {
        "severity": ("LOW", "Minimum severity testssl.sh reports."),
    },
    "dalfox": {
        "max_urls": ("25", "How many crawled URLs to test. dalfox is invoked "
                           "once per URL, so this bounds the run."),
    },
    "katana": {
        "depth": ("2", "Crawl depth."),
        "js_crawl": ("true", "Parse JavaScript for endpoints (`-jc`)."),
        "known_files": ("true", "Fetch robots.txt / sitemap.xml."),
        "headless": ("false", "Use a headless browser — needed for SPAs, "
                              "requires Chrome/Chromium."),
    },
    "schemathesis": {
        "examples": ("50", "How many test cases schemathesis generates per "
                           "operation (`--hypothesis-max-examples`). It is a "
                           "count, not a switch."),
        "base_url": ("target's url", "Override the base URL the spec is "
                                     "tested against."),
    },
    "sqlmap": {
        "level": ("1", "sqlmap test level 1-5. Higher is slower and more "
                       "intrusive."),
        "risk": ("1", "sqlmap risk 1-3. Higher may modify data."),
        "data": ("—", "POST body to test, as sqlmap's `--data`."),
    },
    "kube-hunter": {
        "active": ("false", "Enable active (intrusive) cluster checks."),
    },
}

#: Prose blocks live as whole strings rather than lists of fragments: a list of
#: adjacent string literals silently concatenates when a comma goes missing.
AUTH_NOTE = """\
**Auth = no** means credentials are not passed to that engine: it scans \
anonymously,
finds a fraction of what an authenticated run would, and reports that as a \
normal result.
The engine has no header flag we have verified. Run `yubel engines` to see \
the same column
for your installation."""

AUTH_SECTION = """\
`Auth.kind` is one of `bearer`, `cookie`, `header` or `basic`, and extra \
headers ride
along with any of them — `--bearer X --header "Y: Z"` sends both. Every \
engine with
**Auth = yes** above receives all four kinds through one shared implementation
(`Engine.auth_headers`), so a new adapter gets them by declaring \
`header_flag`.

`form` and `oauth2` appear in the `Auth` dataclass but no engine implements \
them.

Declaring the flag is not sufficient: the *spelling* has to match too. Most \
tools take
`-H 'Name: value'`; graphql-cop parses its `-H` with `json.loads()` and wants \
`-H '{"Name": "value"}'`. An adapter states which it is via `header_style`, \
because
graphql-cop reacts to a header it cannot parse by printing one line and \
carrying on —
so getting it wrong drops the credentials without failing the run."""

#: Defaults are read off `Config` rather than typed here: this table used to
#: claim `crawl_max_urls: 50` while the code said 150, which is the drift the
#: rest of this generator exists to prevent.
_D = Config()

TOP_LEVEL = f"""\
| Key | Default | What it does |
|---|---|---|
| `parallelism` | {_D.parallelism} | Max engines running at once. |
| `engines` | all | Allow-list of engine names. An unknown name is a config \
error, not a silent no-op. |
| `disable` | — | Deny-list of engine names. |
| `include_opt_in` | {str(_D.include_opt_in).lower()} | Allow intrusive \
engines (`sqlmap`). |
| `crawl` | {str(_D.crawl).lower()} | Feed crawler-discovered URLs to the \
parameter scanners. |
| `crawl_max_urls` | {_D.crawl_max_urls} | Cap on discovered URLs seeded per \
target. The cap is logged, never a silent truncation. |
| `chains` | {str(_D.chains).lower()} | Synthesize attack chains. |
| `cluster_threshold` | {_D.cluster_threshold} | Collapse this many similar \
info/low findings into one. |
| `baseline` | — | Prior `yubel.json` to diff against. |
| `fail_on` | — | Exit non-zero at or above this severity. |
| `fail_on_new` | {str(_D.fail_on_new).lower()} | With `baseline`, gate only \
on new/regressed. |
| `offline` | {str(_D.offline).lower()} | Air-gapped hardening. Today this \
reaches **nuclei only** (no OAST/interactsh, no template update check); the \
other engines ignore it. |
| `allow_internal` | {str(_D.allow_internal).lower()} | Permit link-local \
(169.254/16 — the cloud metadata service), loopback and RFC1918 targets. \
Refused by default, including URLs the crawler discovers at runtime. A \
hostname is never resolved, so a name pointing at an internal address still \
passes. |
| `output.dir` | {_D.output.dir} | Where reports are written. |
| `output.formats` | {", ".join(_D.output.formats)} | Reporters to run (`md` \
is an alias for `markdown`). |
| `output.sarif` | {str(_D.output.sarif).lower()} | Also emit `yubel.sarif`. |

Two per-target keys are parsed and then **ignored**: `scope` and `exclude` are \
read into
`Target.scope` / `Target.exclude`, and no engine consults them — so a config \
that sets
them is not scoped in any way. They are accepted rather than rejected only \
because
rejecting would break existing files; treat them as not implemented.
"""


def options_of(engine_cls) -> list:
    """Every `self.options.get("...")` key read by this engine."""
    source = inspect.getsource(engine_cls)
    keys = set(re.findall(r'self\.options\.get\(\s*["\']([^"\']+)["\']', source))
    return sorted(keys - set(DESCRIPTIONS["*"]))


def routing() -> list:
    rows = []
    for target_type in TargetType.__members__.values():
        target = Target(
            type=target_type,
            url=None if target_type is TargetType.KUBERNETES else "https://x",
            host="h" if target_type is TargetType.KUBERNETES else None)
        default = [e.name for e in select_for(target, [], [], {},
                                              include_opt_in=False)
                   if e.name != "demo"]
        with_opt = [e.name for e in select_for(target, [], [], {},
                                               include_opt_in=True)
                    if e.name not in default and e.name != "demo"]
        rows.append((target_type.value, default, with_opt))
    return rows


def render() -> str:
    lines = [
        "# Engines",
        "",
        "**Generated by `scripts/gen_engines.py` — do not edit by hand.**",
        "`tests/test_engines_doc.py` fails if this file drifts from the code,",
        "or if an engine reads an option that has no description here.",
        "",
        "## At a glance",
        "",
        "| Engine | Binary | Auth | Timeout | Targets | Category |",
        "|---|---|---|---|---|---|",
    ]
    for cls in ALL_ENGINES:
        if cls.name == "demo":
            continue
        engine = cls()
        auth = "yes" if engine.supports_auth() else "**no**"
        targets = ", ".join(t.value for t in cls.supports)
        opt = " *(opt-in)*" if cls.name in OPT_IN else ""
        lines.append(f"| `{cls.name}`{opt} | `{cls.binary}` | {auth} | "
                     f"{cls.default_timeout}s | {targets} | {cls.category} |")

    lines += [
        "",
        *AUTH_NOTE.splitlines(),
        "",
        "## Target routing",
        "",
        "| Target type | Engines | Opt-in |",
        "|---|---|---|",
    ]
    for name, default, with_opt in routing():
        engines = ", ".join(f"`{e}`" for e in default) or "**none**"
        extra = ", ".join(f"`{e}`" for e in with_opt) or "—"
        lines.append(f"| `{name}` | {engines} | {extra} |")

    lines += [
        "",
        "A target type with no engine is a config error, not an empty report.",
        "",
        "## Options every engine accepts",
        "",
        "| Key | Default | What it does |",
        "|---|---|---|",
    ]
    for key, (default, text) in sorted(DESCRIPTIONS["*"].items()):
        lines.append(f"| `{key}` | {default} | {text} |")

    lines += ["", "## Per-engine options", ""]
    for cls in ALL_ENGINES:
        if cls.name == "demo":
            continue
        keys = options_of(cls)
        if not keys:
            continue
        lines += [f"### `{cls.name}`", "",
                  "| Key | Default | What it does |", "|---|---|---|"]
        for key in keys:
            default, text = DESCRIPTIONS.get(cls.name, {}).get(
                key, ("?", "**undocumented**"))
            lines.append(f"| `{key}` | {default} | {text} |")
        lines.append("")

    lines += [
        "## Top-level config keys",
        "",
        TOP_LEVEL.rstrip(),
        "",
        "## Authentication",
        "",
        *AUTH_SECTION.splitlines(),
        "",
    ]
    # exactly one trailing newline: the section builders above each append a
    # blank separator, and the last one would otherwise leave a blank line at
    # EOF — which `git apply` reports as a whitespace error on every patch
    return "\n".join(lines).rstrip("\n") + "\n"


def main() -> int:
    generated = render()
    if "--check" in sys.argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != generated:
            print("docs/engines.md is stale — run scripts/gen_engines.py")
            return 1
        print("docs/engines.md is up to date")
        return 0
    OUT.write_text(generated, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
