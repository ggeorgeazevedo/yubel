# Changelog

All notable changes to Yubel are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versions follow
[SemVer](https://semver.org/).

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
