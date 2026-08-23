# Changelog

All notable changes to Yubel are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versions follow
[SemVer](https://semver.org/).

## [Unreleased]

### Fixed — the published container image shipped 11 of the 13 engines it advertised
Running the image and asking it showed `zap: no` and `graphql-cop: no`. Nothing
in the build or the release pipeline had ever asked, so it went out that way.
Both causes are the failure shape this project keeps finding: a scan that
reports normally without having run.

- **ZAP was fetched from a URL that could only ever break.** The build asked
  GitHub for `releases/latest/download/ZAP_2.16.1_Linux.tar.gz` — a pinned
  *filename* under a floating `latest/` path — so it 404'd the day upstream cut
  2.17.0. Pinning half a URL is worse than pinning none of it, because it looks
  pinned. Two things then hid the failure: `curl -sSL` has no `-f`, so curl
  exits **0** on a 404 and writes the error page to the output file; and the
  whole `&&` chain ended in `|| true`, which swallows a failure of *any*
  command in it, not just the last. Both verified locally against a 404 before
  changing anything.
- **`pip install graphql-cop` installs a placeholder.** The PyPI project of
  that name is version 0.0.1 and its own summary reads "Reserved name
  placeholder. No functionality." It installs cleanly and provides no binary.
  The real tool is `github.com/dolevf/graphql-cop`, now cloned at a pinned tag.
  Its `requirements.txt` pins `requests==2.25.1`, which would drag schemathesis
  down with it, so its dependencies are installed unpinned instead.
- **Every version in the image is now an ARG** — Go tools, ZAP, nikto,
  testssl.sh, graphql-cop, and both base images — so a bump is a visible,
  reviewable change instead of whatever upstream published that morning. Every
  `RUN` starts with `set -eux` and every download uses `curl -f`.
- **The build now asks the image what it shipped.** New `yubel engines --check`
  exits non-zero if any non-opt-in engine is missing; the Dockerfile runs it as
  a build step, so this class of gap fails the build. Intrusive opt-in engines
  (`sqlmap`) are deliberately exempt.
- **The Docker workflow's smoke test never ran.** It was guarded by
  `if: github.event_name == 'pull_request'` in a workflow that does not trigger
  on `pull_request` — so the image was pushed to ghcr.io with nothing verifying
  it. The workflow now builds on PRs that touch the image (path-scoped, so
  Dependabot noise stays away), loads a single-arch image, and runs both
  `engines --check` and a full `selftest` against it before any push.
- **The image is now `linux/amd64` *and* `linux/arm64`.** It was amd64-only, so
  Apple Silicon needed `--platform linux/amd64` and ran under emulation. The Go
  stage builds on the host architecture and cross-compiles via `GOARCH`, so the
  second architecture costs minutes rather than most of an hour.

### Fixed — dalfox 3.x was invoked with flags it does not have
dalfox 3.0 is a complete rewrite **in Rust**, not a Go release: its tags carry
no `go.mod`, which is why pinning the image to `dalfox/v2@v3.2.1` failed the
build outright with *"does not contain package .../v2"*. The image is pinned to
`v2.13.0`, the last Go release — and exactly what the old `@latest` on the
`/v2` module path was already resolving to, so the shipped binary does not
change. Moving to v3 needs a Rust toolchain in the image and is deliberately a
separate change.

The adapter's own v3 branch was wrong too, and a test was locking it in: it
sent `dalfox url --url <URL> --header ...`, and v3 has no `--url` flag (the URL
is positional) and spells the header flag `--headers`/`-H`. Homebrew ships v3,
so anyone who installed dalfox that way had the engine failing on every run.
Both lines take a positional URL and `-H "Name: value"`, so the only real
difference left is the subcommand: `url` on 2.x, `scan` on 3.x.

### Fixed — a test was reporting on the developer's laptop, not on the code
`test_dalfox_command_targets_given_url` asserted the `url` subcommand against
whatever dalfox happened to be on PATH. It passed in CI and in any container
with no dalfox installed — the version probe falls back to major 2 when the
binary is missing — and failed on a machine with the Homebrew build, which is
the 3.x Rust line. A new `tests/conftest.py` pins the probe for the whole
suite, so a test that cares about the version has to say which one it means.
Verified by running the suite twice: once with every engine faked onto PATH
reporting 3.x, once with a bare PATH. Same result.

### Fixed — credentials silently dropped for graphql-cop
Introduced by the previous release's own auth work, and the same shape it was
written to eliminate. graphql-cop was given `header_flag = "-H"` and nothing
else, so it received `Authorization: Bearer …`. It parses `-H` with
`json.loads()` and wants `{"Authorization": "Bearer …"}`; its handler for a
value it cannot parse is a bare `except:` that prints one line and **keeps
scanning**. So the run did not fail — it dropped the credentials and reported
an anonymous scan as a normal one.

Adapters now declare `header_style` (`colon` or `json`) alongside `header_flag`,
and a test asserts the spelling for every auth-capable engine. The other five
were checked against their own `--help`: nuclei, wapiti, sqlmap, dalfox and
schemathesis all take `Name: value`.

### Changed
- `docs/engines.md` now derives the top-level config defaults from `Config`
  itself. The hand-written table claimed `crawl_max_urls: 50` while the code
  said 150 — the exact drift the generator exists to prevent — and described
  `offline` as covering every engine.
- **The brand is one file now, and it stays out of the severity scale's way.**
  Yubel's identity lived as literal hex strings in six hand-edited SVGs, a
  diagram script, the HTML report and `action.yml`, and they had already
  drifted — the report's accent was a different purple from the logo's. The
  palette moved to `scripts/brand.py`; the logo set, the architecture diagram
  and the sample report are generated from it, and `tests/test_brand.py` fails
  the build if a committed asset stops matching or if the old purple survives
  anywhere.

  The palette itself is black, crimson, gold and silver. The rule that comes
  with it is the part worth stating: **crimson already means Critical and
  gold-olive already means Medium in a Yubel report**, so brand crimson and
  brand gold appear in exactly one place inside a report — the mark in the
  masthead — and nowhere near a link, a chip or a border. The report's frame is
  a neutral graphite, and links are underlined, so the link affordance no
  longer depends on hue at all. No severity colour changed.
- **The wordmark is set in outlines.** It used to be an SVG `<text>` in a
  system font stack, so the logo rendered in a different typeface on nearly
  every machine that opened it. It now ships as Cinzel outlines
  (Natanael Gama, SIL Open Font License 1.1) in `scripts/brand_wordmarks.json`
  — nothing at build or render time needs a font installed.
- **The "how it works" diagram gained the phase it was missing.** The flow
  started at "run engines", so discovery — the step that decides how much
  attack surface is looked at at all — was invisible in the one picture people
  actually read.
- `docs/sample-report.html` was cut from v0.4.0 and had been stale for three
  releases: old palette, and none of the reporting added since — no proof
  block, no remediation, no confirmed/needs-review tier. It is regenerated by
  `scripts/gen_sample_report.py` from a fixed synthetic scenario, so it is
  reproducible and can be refreshed at every release.
- `action.yml` branding colour is now `red` (GitHub only renders a fixed set of
  words, so the palette collapses to one).

- `deploy/helm/omnidast` → `deploy/helm/yubel`, and `examples/omnidast.yaml` →
  `examples/yubel.yaml` (regenerated from `templates.STARTER_CONFIG`, so the
  example and the `yubel init` output cannot disagree). The old project name
  no longer appears in the tree.
- README: the `api` and `graphql` rows of the target table listed engines that
  do not run and omitted ones that do; `yubel setup`'s comment described the
  `--install` behaviour; a duplicate line claimed the Docker image twice. Added
  the Linux-without-Homebrew caveat, the sqlmap opt-in rule and the `grpc` gap.

### Fixed — documentation that overstated what the tool does
An audit of every doc against the source turned up statements that would
mislead a reader about **security coverage**, which is the only kind of doc bug
that can cost someone a finding.

- **`--offline` was sold as locking down every engine.** `_apply_offline` sets
  the flag for ten engines and exactly one of them — nuclei — reads it. A ZAP
  add-on update check or a nikto db fetch still egresses. The README, the
  article and the `action.yml` input description all now say what it actually
  covers: nuclei's OAST/interactsh callbacks and its template update check.
  The core's zero-outbound-calls guarantee is unaffected and unchanged.
- **The README said ZAP does "deep authenticated web crawls".** Yubel passes no
  credentials to ZAP — it has no `header_flag`, so `supports_auth()` is False
  and it always scans anonymously. Same for nikto, testssl, katana, httpx,
  graphw00f and kube-hunter. The line now says so and points at the AUTH
  column.
- **Both pipeline drawings omitted discovery**, and `crawl`, `crawl_max_urls`
  (default 150), `--no-crawl` and `--crawl-headless` were documented nowhere. A
  user capping or disabling the crawl had no documented knob, and the default
  cap that bounds attack surface was unstated.
- **"Adding an engine touches exactly two files"** now produces a red build —
  `tests/test_engines_doc.py` requires a `scripts/gen_engines.py` run — and it
  never mentioned `header_flag`, so a contributor following it shipped an
  engine that silently scans unauthenticated. README, ARCHITECTURE and
  CONTRIBUTING all corrected, and the CONTRIBUTING skeleton now declares
  `header_flag` with the reason attached.
- `ARCHITECTURE.md` named a JSON field that does not exist
  (`raw._also_reported_by`; it is the top-level `also_reported_by`), gave the
  wrong fingerprint formula, listed 6 of the 10 analysis stages — omitting
  cross-target correlation and the rationale trail, both of which the README
  sells as headline differentiators — and had no row for `redact.py`,
  `remediation.py`, `discovery.py`, `install.py` or `templates.py`.
- `reporting-roadmap.md` still listed the remediation KB and the
  confirmed/needs-review tier as unbuilt; both shipped in 0.7.0, and the proof
  block shipped for nuclei and dalfox.
- The `type` input in `action.yml` listed 5 of 8 target types, omitting
  `container` and `host`, which are routable.
- `docs/engines.md` now records that `scope` and `exclude` are parsed and then
  ignored by every engine — a config that sets them is not scoped in any way.
- The README release example tagged `v0.3.0`, four releases behind, and its
  engine list omitted `httpx` and `graphw00f`.


### Fixed
Five paths where the scan reported "no findings", exit 0 and no warning, for a
scan that had not actually happened. Each one is covered by a test in
`tests/test_silent_failures.py` that fails on 0.7.2.

- **The CWE id is now canonical.** nuclei emits `cwe-79`, ZAP and dalfox emit
  `79`, and testssl stripped the prefix by hand at its own call site. The field
  feeds `Finding.fingerprint`, the attack-chain rules and
  `correlate._class_key`, so the two spellings split one issue into two: the
  same XSS found by nuclei and by ZAP never corroborated (so the `verified`
  tier never fired for it), the chain rules were blind to nuclei, and the
  systemic correlation counted one class as two. `models.canon_cwe` normalises
  at construction, so no adapter can reintroduce the split.
- **`--bearer` together with `--header` no longer discards the token.** They
  were two sequential assignments to the same variable, so the scan ran
  unauthenticated and reported the handful of findings an anonymous crawl
  finds. They now compose, and nuclei sends both.
- **A misspelled engine name is rejected.** `-e nucli` passed validation,
  matched no engine, wrote empty reports and exited 0 — with `--fail-on`, a
  green pipeline that scanned nothing. `Config.validate()` now checks
  `engines`, `disable` and the keys of `options` against the registry, and
  suggests the closest match.
- **nuclei no longer reports `ok` for a run that failed.** `Engine.run()` has
  the rule ("never report a broken run as ok — false assurance"); nuclei
  overrides `run()` and the check was lost in the copy. dalfox, which also
  overrides, had kept it.
- **testssl no longer accepts its own error codes as success.** It reserves
  242-255 for hard errors (`declare -r ERR_*`, testssl.sh:75-88); the old
  `range(0, 250)` swallowed ERR_CONNECT (246), ERR_DNSLOOKUP (247) and
  ERR_RESOURCE (244), so a testssl that never reached the target reported
  `ok (0 findings)`.
- **Credentials now reach every engine that can carry them.** `--header` was
  honoured by one adapter of thirteen, `cookie` by one other and `basic` by a
  third: each adapter re-implemented `if auth.kind == "bearer"` and stopped
  there, so three of the four kinds were dropped by five of the six engines
  that take credentials at all. An engine that silently scans anonymously
  finds a fraction of what it should and reports it as a clean run.
  `Engine.auth_headers()` / `auth_args()` on the base now build all four kinds
  once, and an adapter opts in by declaring `header_flag` — nuclei, wapiti,
  sqlmap, dalfox, schemathesis and graphql-cop do. wapiti keeps driving basic
  auth natively, which is better than sending the header ourselves.
- **A target type no engine covers is rejected.** `--type grpc` was accepted by
  the CLI (the choices come from the enum), matched no engine, and wrote an
  empty report with exit 0. `Config.validate()` now rejects any target nothing
  can scan — which also catches the same hole reached through configuration,
  e.g. every engine disabled.

### Added
- **`docs/engines.md`**, generated from the registry by `scripts/gen_engines.py`.
  Eleven of the twenty-four `options` keys in use were documented nowhere a
  user would read — including `timeout`, which applies to every engine, and
  `keep_workdir`, the only way to inspect a failed engine's raw output. The
  doc carries the engine table, target routing, per-engine options, top-level
  config keys and the authentication matrix. `tests/test_engines_doc.py` fails
  the build if the committed file drifts from the code, or if an engine reads
  an option that has no description.
- **`yubel engines` gained an `AUTH` column** and names, underneath the table,
  the engines that scan anonymously. The auth gap is now stated rather than
  left as an absence.
- `NucleiEngine.passes()` is a documented public method — it was inline logic
  inside `run()` that no test could reach.

### Fixed (tests)
Four tests passed without exercising the code they named. Each was verified by
sabotage — breaking the production path and confirming the test now fails.
- `test_crawl.py` asserted on a hand-rolled copy of the crawl guard; it now
  drives the real guard through `_run_batch`/`_plan`.
- `test_engines.py` re-implemented nuclei's pass selection instead of calling
  `NucleiEngine().passes()`.
- `test_analysis.py` lost its `or` to operator precedence: `a and "IDOR" in t or
  "object authorization" in t` made the second half independent of `is_chain`.
- `test_core.py` used `"http-equiv" not in html` to mean "self-contained
  report", which nothing in the report ever emits — so that half asserted
  nothing, and adding a CSP `<meta>` would have failed the test guarding
  self-containment. It now checks external `src`, `href` and `@import` directly.

## [0.7.2] — 2026-08-18

### Security
- **The operator's own credentials no longer reach the reports.** Yubel injects
  whatever auth it is given into the engines (`-H "Authorization: Bearer …"`,
  `--auth-password`, cookies) and two paths carried those values straight to
  disk: `EngineRun.command` — the exact argv, serialised into `yubel.json`,
  which is the file CI uploads as an artifact and teams commit as a
  `--baseline` — and `Finding.request`/`.response`, because nuclei runs with
  `-irr` and echoes back the headers we sent, rendered verbatim in the HTML
  report. A new `yubel.redact` module masks credential-bearing header values,
  whole-value secret flags, credential-looking query parameters, and every
  literal occurrence of the values it was handed, at the point where each
  record is built (`engines/base.py`, `nuclei.py`, `dalfox.py`, `wapiti.py`).
  Header and flag *names* survive, so a report still shows that a scan ran
  authenticated. Secrets **discovered on the target** are deliberately left
  intact — blanking those would destroy the finding.
- `EngineRun.command` is now quoted with `shlex.quote`, so an argument
  containing spaces no longer reads as several arguments.

- **The base engine signature is the contract.** `Engine.build_command` and
  `Engine.parse` declared `*args, **kwargs`, advertising a wider contract than
  any of the twelve engines implements. nuclei's `dast` flag and dalfox's `url`
  now live on their own `build_command_for` / `parse_for`, and
  `tests/test_engine_contract.py` checks both directions.

## [0.7.1] — 2026-08-17

CI/CD fixes. The GitHub Actions path was broken end to end: the scan produced
no reports at all, and on the rare path where it did, code scanning rejected
the SARIF. Nothing changes for local or container runs.

### Fixed
- **Reports were never written in CI.** The image runs as the non-root user
  `yubel` (uid 10001) while the runner workspace is owned by uid 1001 with mode
  755, so `write_reports()` raised `PermissionError` on `os.makedirs()` and
  every report — SARIF included — was lost. `dast.yml` now pre-creates a
  writable output directory and mounts it directly on `/out`.
- **SARIF upload rejected outright.** `artifactLocation.uri` carried the
  scanned URL, absolute. GitHub resolves every URI against the checkout (scheme
  `file`), so an `https://` target — or a bare `host:port/...`, whose host the
  parser reads as a scheme — killed the whole upload with *"SARIF URI scheme
  ... did not match the checkout URI scheme file"*. URIs are now
  checkout-relative pseudo-paths (`dast/<host>/<path>`), with the real URL
  preserved in `message.text` and `properties.url`.
- **Bare-path locations kept their host.** nikto reports `"url": "/"` for
  root-level findings and wapiti does the same for module-level ones. A path
  with no host was collapsing onto a single `dast/unknown` anchor; the
  finding's target now supplies the host.
- **A missing SARIF no longer fails the job.** `upload-sarif` hard-fails on a
  nonexistent path; `dast.yml` now checks first and warns instead.
- **Gate failures were indistinguishable from crashes.** `continue-on-error`
  masked real scanner errors. Exit code 2 is now treated as the severity gate
  (warning, reports still published); any other non-zero exit is a real
  failure and surfaces as such.

### Added
- **`partialFingerprints`** on every SARIF result, so code scanning tracks an
  alert across runs instead of closing and reopening it every scan.
- **`properties.url`** on every SARIF result, and the scanned URL now leads the
  result message — the location anchor is a pseudo-path, so this is where a
  reader actually sees what was scanned.

### Changed
- **Release and Docker workflows only fire on exact semver tags.** Their filter
  was `v*`, which also matches the floating `v0` tag the Marketplace action
  points at — moving `v0` would have cut a stray "v0" GitHub Release and tried
  to re-publish an already published version to PyPI.
- **`src/yubel.egg-info/` is no longer tracked.** It is build output, already
  covered by `.gitignore`, but had been committed before that rule existed — so
  every editable install dirtied the working tree.
- **The GitHub Action is now a composite action** (was a Docker container
  action). A container action runs as the image's `USER`, which cannot write
  into the runner workspace; doing the `docker run` from a composite step lets
  the action pre-create a writable output directory *and* keep the image
  non-root. Linux runner with Docker required — as before.
- **`engines` and `openapi` action inputs now reach the CLI.** They were
  declared and silently ignored. New inputs: `disable`, `baseline`,
  `fail-on-new`, `fast`, `offline`, `image`, `upload-sarif` (default `false`).
  New outputs: `report-dir`, `sarif`, `exit-code`.

## [0.7.0] — 2026-07-30

Reporting upgrade — **evidence of *where* the issue is, and *how* to fix it** —
benchmarked against Invicti (proof-based scanning), Checkmarx DAST and the OWASP
API Security Testing Framework, kept 100% deterministic.

### Added
- **Proof per finding.** Findings now carry structured evidence: the vulnerable
  **parameter**, the **payload** that triggered it, and the raw **request /
  response** that demonstrate it. nuclei runs with `-irr` (include request/
  response) and dalfox surfaces its PoC/param/payload. Reports render a "Proof"
  block (parameter · payload · evidence · collapsible request/response).
- **Deterministic remediation KB** (`analysis/remediation.py`). Every finding
  gets concrete, actionable fix guidance — keyed by CWE, then OWASP category,
  then a safe generic. Engine-supplied remediation always wins; no network, no
  model. It's the OWASP-ASTF "recommendation per finding" idea, done offline.
- **Confirmed vs Needs-review tier.** A deterministic `verified` flag — Yubel's
  auditable answer to proof-based scanning (no LLM, no destructive exploit): a
  finding is *confirmed* when corroborated by ≥2 engines, synthesized as a chain,
  backed by a payload with observable proof, or a direct transport observation;
  otherwise it's *flagged for review*. Surfaced as a badge in the report and in
  the executive summary.
- Reporters (HTML/Markdown/SARIF) render the proof block, remediation and the
  confirmed/needs-review state; SARIF `help` carries the remediation and results
  expose `verified`/`parameter`/`payload` for code scanning.

## [0.6.0] — 2026-07-30

Discovery now feeds the scanners — the crawler's output expands the attack
surface instead of being a dead-end context finding.

### Added
- **Crawler → scanner wiring.** The orchestrator now runs in two phases:
  discovery (katana / httpx) first, then the scanners. URLs katana discovers are
  fed to the parameter engines so they cover the whole crawled surface, not just
  the seed URL:
  - **nuclei** runs against the URL list (`-l`): the full-template pass covers
    the whole crawled surface, while the expensive `-dast` fuzzing pass targets
    only *parameterized* URLs (fuzzing a param-less URL wastes time and would
    balloon the scan on a large crawl).
  - **dalfox** scans each discovered *parameterized* URL (`?k=v`), capped
    (`options.dalfox.max_urls`, default 25), reusing its per-URL command.
- **katana extracts endpoints from JavaScript** (`-jc`) and pulls known files
  (`-kf all`, robots.txt / sitemap.xml) by default — essential for SPAs
  (Angular/React) where routes and API paths live in the JS bundle. Toggle via
  `options.katana.js_crawl` / `known_files`.
- **Config + CLI controls.** `crawl` (default on) and `crawl_max_urls`
  (default 150) in config; `--no-crawl` to disable and `--crawl-headless` to run
  katana with a headless browser for JS/SPA apps (e.g. OWASP Juice Shop) on the
  CLI. URL caps are logged, never a silent truncation.

### Fixed
- **katana endpoints are parsed correctly.** katana ≥ v1 nests the URL under
  `request.endpoint` in its JSONL; the adapter read a top-level `endpoint` and
  silently found nothing. It now reads `request.endpoint` (with a top-level
  fallback) and skips failed-request lines (those carrying an `error`).

### Notes
- When crawling is off, or no discovery engine is installed/selected, behaviour
  is identical to before (each engine scans only the seed URL).

## [0.5.8] — 2026-07-29

### Fixed
- **testssl no longer reports false positives against non-HTTPS ports.** Scanning
  a plain-HTTP endpoint (e.g. a dev server on `:3000`) made testssl emit bogus
  "TLS 1.2 not offered", "TLS 1.3 not offered", "no Forward Secrecy" and
  "cipherlist not offered" findings — those just mean "this isn't an HTTPS
  endpoint", not a misconfiguration. When no SSL/TLS protocol is offered at all,
  these "absence of TLS" rows are now suppressed. Genuine weaknesses on real TLS
  endpoints (expired cert, BEAST, offered-but-obsolete protocols, missing FS on
  an actual HTTPS host) are still reported. Found via a live scan of a local
  OWASP Juice Shop instance.

## [0.5.7] — 2026-07-29

### Changed
- **Marketplace-ready Action name** — the composite Action's display `name` is
  now "Yubel DAST Orchestrator" (GitHub Marketplace requires a globally unique
  name; a bare "Yubel" collided with an existing account). This only affects the
  Marketplace listing title — usage is unchanged (`uses: ggeorgeazevedo/yubel@…`).

## [0.5.6] — 2026-07-29

### Fixed
- **Logo now renders on GitHub and PyPI** — the README referenced the logo by a
  relative path to an SVG, which neither GitHub (serves raw SVG as text) nor
  PyPI (no repo context) could display. It now points to an absolute raw URL of
  a PNG rendering. Added PNG versions of the logo, emblem and social banner
  under `docs/logo/`.
- **Docker image builds end-to-end** — the batteries-included image now builds
  and publishes to GHCR: nikto is fetched from upstream git (it was dropped from
  Debian bookworm) with its Perl deps; the Go toolchain stage uses Go 1.26 (a
  recent nuclei requires Go ≥ 1.25); and build tooling is added (then purged) so
  the `netifaces` C extension pulled in by kube-hunter compiles.

## [0.5.5] — 2026-07-29

First release published to PyPI.

### Added
- **PyPI distribution** — `pip install yubel` now works. Wheels and sdists are
  built and published automatically on tag via GitHub Actions using PyPI
  Trusted Publishing (OIDC, no stored token).

### Changed
- CI hardened: ruff rule set pinned to a stable, version-independent selection
  (pyflakes + core pycodestyle) so lint no longer breaks across ruff releases;
  Docker/scan workflows no longer run on pull_request; Dependabot calmed to a
  monthly, grouped cadence.

## [0.5.4] — 2026-07-28

### Fixed
- **dalfox 3.x JSON output parsed correctly** — dalfox 3 wraps results in
  `{"findings": [...], "meta": {...}}`; the adapter now reads the `findings`
  array (previously it treated the whole wrapper as one bogus finding) and
  extracts v3 field names.

## [0.5.3] — 2026-07-28

### Fixed
- **dalfox 3.x support** — dalfox 3 rewrote its CLI (`--url <URL>` instead of a
  positional argument); the adapter now detects the major version and builds the
  correct command for both 2.x and 3.x.

## [0.5.2] — 2026-07-28

### Fixed
- **testssl noise reduced** — the per-cipher enumeration rows (`cipher-tls1_…`,
  one finding per supported cipher) are no longer reported; the real signal
  (obsolete cipher lists, BEAST, LUCKY13, LOGJAM, cert issues, protocol
  deprecation) is kept. Cut a sample scan from 37 to 21 meaningful findings.
- **TLS findings always map to OWASP A02 (Cryptographic Failures)** — testssl
  tags some issues (e.g. BEAST) with a generic CWE that previously mis-bucketed
  them under Injection.

## [0.5.1] — 2026-07-28

### Fixed
- **testssl no longer reports connection/scan errors as findings** — scanning an
  HTTP-only host (or an unreachable one) produced a bogus `TLS: scanProblem`
  "finding"; these operational errors are now filtered out.
- **dalfox adapter hardened** — minimal, version-portable flags and JSON written
  to an output file (a stray flag was making dalfox exit with an error).

## [0.5.0] — 2026-07-28

### Added
- **`yubel setup`** — one command that detects missing scanning engines and
  installs them (brew → pip → go, chosen per machine). `yubel setup` shows the
  plan; `yubel setup --install` runs it. No more installing engines one by one.

## [0.4.0] — 2026-07-28

Correlation brain reinforced + air-gapped positioning + original branding.

### Added
- **Systemic correlation across targets** — when the same weakness class appears
  on 2+ targets, Yubel raises a single *systemic* finding ("fix centrally").
- **"Why we believe this" evidence trail** — every finding carries a
  deterministic, reproducible rationale (engines, corroboration, taxonomy, risk).
  Yubel's answer to LLM validators: auditable, not probabilistic.
- **Corroboration surfaced** — a green `✓ corroborated ×N` marker on findings
  seen by multiple engines, and corroborated/chain/systemic counts in the
  executive summary.
- **Air-gapped mode** — `--offline` / `offline: true` hardens engines against
  external calls (no OAST/interactsh, no update checks). The core already makes
  zero outbound calls. Now a first-class, documented feature.
- **Two new attack-chain rules** — IDOR/BOLA + data exposure → bulk record theft;
  default/weak credentials + exposed admin → full compromise (13 rules total).
- **Original branding** — winged three-eyed guardian emblem, horizontal logo and
  social/OG banner (all original art, `docs/logo/`).

### Changed
- Reports (HTML/Markdown) now show systemic issues, the evidence trail and
  corroboration prominently; footer states the deterministic/air-gapped stance.

## [0.3.0] — 2026-07-28

Usability & accuracy pass (from real-world testing) + community/CI scaffolding.

### Changed
- **Nuclei now runs two passes by default**: the full template set (CVEs,
  exposures, misconfig) **and** parameter fuzzing (`-dast`), merged. Previously
  only fuzzing ran, which found little on parameter-less URLs. Control via
  `options.nuclei.full` / `options.nuclei.dast`.
- **Nikto is capped** with `-maxtime` (default 600s) and a lower default
  timeout, so it can no longer stall a scan for many minutes.
- **Reports use the machine's local timezone** (with offset), instead of always
  UTC — whoever runs Yubel sees their own region's time.
- Console progress now prints a `▶ engine running…` line per active engine and a
  `will run / skipped` summary, and hides the noisy per-engine "binary not
  found" lines (still recorded in the report's engine table).

### Added
- **`--fast` profile**: nuclei fuzzing-only (high/critical), short Nikto cap and
  tighter timeouts — for quick smoke tests.
- **Graceful `Ctrl+C`**: clean "cancelled by user" message instead of a
  traceback; engines are shut down.
- CI/CD & community scaffolding: CodeQL, release (PyPI trusted publishing +
  GitHub Release), Docker (GHCR) and Dependabot workflows; refined badges.

### Fixed
- Clear message when ZAP automation scripts are missing (was `binary '' not
  found on PATH`).

## [0.2.0] — 2026-07-28

Renamed to **Yubel** and added the analysis layer.

### Added
- **Cross-engine consensus**: findings reported by ≥2 engines are marked
  corroborated and confidence-upgraded; duplicates merge with attribution.
- **Attack-chain synthesis**: composite findings for real exploitation paths
  (SSRF→IMDS, XSS+cookie→ATO, K8s API+kubelet→takeover, SQLi+verbose-errors,
  weak-TLS+creds, open-redirect+auth).
- **Baseline diff**: `--baseline` tags findings new/existing/regressed and
  tracks fixed issues; `--fail-on-new` gates CI on newly introduced risk only.
- **Taxonomy + scoring**: OWASP Top 10 (2021), OWASP API Top 10 (2023), CWE and
  MITRE ATT&CK mapping; 0–100 composite risk score; per-target A–F grade;
  OWASP coverage matrix.
- **Noise clustering**: repetitive info/low findings collapse into one.
- **Redesigned HTML report**: editorial security-assessment layout (masthead,
  executive summary + grade, attack-paths, coverage matrix, risk-scored findings).
- Richer Markdown and SARIF (security-severity from risk score, OWASP/MITRE tags).
- New CLI flags: `--baseline`, `--fail-on-new`, `--no-chains`, `--cluster`.

### Changed
- Project/package/CLI renamed `omnidast` → `yubel` (distribution `yubel`).
- `Finding` gained corroboration, status, OWASP/API/MITRE, risk_score and chain
  fields; `dedupe()` now records corroboration as first-class data.

## [0.1.0] — 2026-07-28

Initial public release.

### Added
- **Orchestrator core**: resilient, parallel (thread-pooled) execution of
  engines across targets; every run recorded (`ok|skipped|error|timeout`).
- **Normalized model**: shared 5-level `Severity` scale, `Finding` with stable
  fingerprint, cross-engine de-duplication that merges duplicates and keeps the
  worst severity.
- **13 engine adapters** (pragmatic core):
  - Web: ZAP, Nuclei, Wapiti, Nikto, dalfox, testssl.sh
  - Discovery: katana, httpx
  - API: ZAP api-scan, Nuclei, schemathesis
  - GraphQL: graphw00f, graphql-cop
  - Kubernetes/Container: kube-hunter
  - Intrusive/opt-in: sqlmap (off by default)
- **Target types**: web, api, graphql, cloud, container, host, kubernetes
  (remote/internal/pod).
- **Reporters**: JSON, self-contained HTML dashboard, Markdown, SARIF 2.1.0.
- **CLI**: `scan`, `engines`, `selftest`, `init`, `version`; CI fail-gate via
  `--fail-on`.
- **Config**: YAML with `${ENV}` expansion, per-engine options, allow/deny lists.
- **Deploy**: batteries-included Dockerfile, docker-compose, Kubernetes Job +
  ConfigMap, Helm chart (Job/CronJob), GitHub composite Action, CI workflow.
- **Docs**: README, ARCHITECTURE, CONTRIBUTING, SECURITY, and a surveyed
  **382-tool DAST landscape** (`docs/LANDSCAPE.md` + `data/dast-landscape.csv`).
- **Tests**: full pipeline coverage without network or external binaries.

[0.7.2]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.7.2
[0.7.1]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.7.1
[0.7.0]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.7.0
[0.6.0]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.6.0
[0.5.8]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.5.8
[0.5.7]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.5.7
[0.5.6]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.5.6
[0.5.5]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.5.5
[0.5.4]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.5.4
[0.5.3]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.5.3
[0.5.2]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.5.2
[0.5.1]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.5.1
[0.5.0]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.5.0
[0.4.0]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.4.0
[0.3.0]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.3.0
[0.2.0]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.2.0
[0.1.0]: https://github.com/ggeorgeazevedo/yubel/releases/tag/v0.1.0
