# Yubel Architecture

Yubel is a thin, resilient orchestration layer over external scanning
engines. It owns four things and delegates everything else: **routing**,
**execution**, **normalization**, and **reporting**.

```
                         ┌─────────────────────────────┐
        yubel.yaml ──▶│           Config            │
        / CLI flags      │  targets + engine selection │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │        Orchestrator         │
                         │  phase 1: DISCOVERY         │
                         │    katana / httpx crawl     │
                         │    → seed_urls (≤150)       │
                         │  phase 2: plan (engine ×    │
                         │    target) + ThreadPool     │
                         └──────────────┬──────────────┘
             ┌──────────────────────────┼──────────────────────────┐
             ▼                          ▼                          ▼
     ┌──────────────┐           ┌──────────────┐           ┌──────────────┐
     │  Engine A    │           │  Engine B    │    ...     │  Engine N    │
     │ build_command│           │ build_command│           │ build_command│
     │   run(temp)  │           │   run(temp)  │           │   run(temp)  │
     │    parse()   │           │    parse()   │           │    parse()   │
     └──────┬───────┘           └──────┬───────┘           └──────┬───────┘
            └───────────── [Finding] normalized ──────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │   ScanResult.dedupe()       │
                         │  merge cross-engine dups,   │
                         │  keep worst severity        │
                         └──────────────┬──────────────┘
                                        ▼
                    JSON · HTML dashboard · Markdown · SARIF
                                        │
                                        ▼
                         fail_on gate → process exit code
```

## Modules

| Module | Responsibility |
|---|---|
| `severity.py` | The one normalized 5-level scale (`INFO…CRITICAL`) and coercion from every engine dialect (text, CVSS 0–10, ZAP riskcodes). |
| `models.py` | `Target`, `Auth`, `Finding`, `EngineRun`, `ScanResult`. Findings carry a stable `fingerprint` for de-duplication. |
| `config.py` | YAML/dict → `Config`, with `${ENV}` expansion and validation. Rejects unknown engine names, unknown `options` keys, and any target no engine covers — each of which used to produce an empty report and exit 0. |
| `redact.py` | Masks the operator's *own* credentials in commands, requests and raw evidence before anything is written to a report. Secrets **discovered on the target** are deliberately left intact — blanking those would destroy the finding. |
| `templates.py` | The starter config `yubel init` writes, and the source `examples/yubel.yaml` is generated from. |
| `engines/base.py` | The `Engine` contract: `available()`, `handles()`, `build_command()`, `parse()`, and a hardened `run()` that sandboxes each tool in a temp dir and never raises. |
| `engines/*.py` | One adapter per tool. Small, isolated, independently testable. An adapter declares `header_flag` to receive credentials; without it `supports_auth()` is False and it scans anonymously. |
| `engines/discovery.py` | katana / httpx — the crawl phase that seeds the scanners. |
| `engines/install.py` | `yubel setup` — probes for each binary and installs what it can via brew/pip/go. |
| `engines/registry.py` | The single list of engines + routing logic (`select_for`). |
| `orchestrator.py` | Fan-out execution, progress, and the CI `gate()`. |
| `analysis/taxonomy.py` | CWE→OWASP 2021 / OWASP API 2023 / MITRE mapping; composite risk score; per-target grade; OWASP coverage. |
| `analysis/correlate.py` | Cross-engine consensus (confidence uplift), noise clustering, cross-target systemic correlation, and the deterministic rationale trail. |
| `analysis/remediation.py` | Deterministic fix guidance per finding, keyed CWE → OWASP category → safe generic. No network, no model. |
| `analysis/chains.py` | Rule-based attack-chain synthesis (composite findings). |
| `analysis/baseline.py` | Diff vs a prior `yubel.json` (new/existing/regressed/fixed). |
| `analysis/__init__.py` | `analyze()` — runs the above in order over a deduped result. |
| `reporters/*` | JSON, HTML (self-contained, editorial), Markdown, SARIF 2.1.0. |

## Key design decisions

**Adapters are processes, not libraries.** Each engine is invoked as its native
CLI in an isolated temp working directory. This keeps Yubel dependency-light
(the core needs only PyYAML), sidesteps Python-version conflicts between tools,
and means the exact same adapters work whether a tool is installed locally or
baked into the Docker image.

**Failure is data, not an exception.** `Engine.run()` catches timeouts, missing
binaries and crashes, recording them as an `EngineRun` with a status
(`ok|skipped|error|timeout`). A broken engine degrades the scan; it never aborts
it. This is what makes "install only the engines you want" safe.

**Normalization happens at the edge.** Every adapter is solely responsible for
translating its tool's output into `Finding`s. The rest of the system never sees
engine-native formats, so adding an engine can't change core behavior.

**De-duplication with attribution.** Two engines reporting the same XSS on the
same URL collapse to one finding (by
`fingerprint = sha1("chain" if is_chain else "" | title | location or target | cwe)[:16]`
— a chain can therefore never collide with a plain finding, and a finding with
no location falls back to its target), keeping the highest severity and
recording every engine that saw it in the top-level `also_reported_by` field of
each finding in `yubel.json`. Corroboration raises confidence without inflating counts.

**Threads, not async.** Engines are subprocess-bound and long-running; a bounded
`ThreadPoolExecutor` is the simplest correct concurrency model and keeps the code
portable with zero event-loop machinery.

**Opt-in for intrusive tools.** sqlmap (and future exploiters) are excluded
unless explicitly enabled, so the default scan is safe to point at staging.

## Target routing

`TargetType` drives eligibility. An engine declares `supports = (TargetType.WEB,
TargetType.API, …)`; `select_for()` intersects that with the target, subtracts
the deny-list, and drops opt-in engines unless requested. This is the only place
that decides "what runs where", which keeps routing auditable.

## Extending

Adding an engine touches the adapter in `engines/`, one line in
`registry.ALL_ENGINES`, and a `python3 scripts/gen_engines.py` run to refresh
`docs/engines.md` — `tests/test_engines_doc.py` fails the build on a stale doc,
and on any `options` key the adapter reads that has no description in that
script's `DESCRIPTIONS`. Everything else downstream (availability, routing, CLI,
parallelism, dedupe, all four reporters, the fail-gate) is automatic — with one
exception worth stating: **credentials are not**. An adapter that does not
declare `header_flag` scans anonymously.

Adding a report format touches one file in `reporters/` plus one entry in
`reporters.WRITERS`.

Adding an **attack-chain rule** touches one function in `analysis/chains.py`
plus one line in its `RULES` list. Each rule is a pure predicate over a target's
findings returning an optional composite `Finding`, so rules are trivial to unit
test in isolation.

## The analysis layer

This is what separates Yubel from "run scanner, print output". After dedupe,
`analyze()` runs a fixed pipeline:

1. **taxonomy.enrich** — map each finding to OWASP 2021 / API 2023 / CWE / MITRE
   (CWE-driven, with a keyword fallback for CWE-less findings like TLS issues).
2. **correlate.consensus** — findings seen by ≥2 engines are marked corroborated
   and upgraded to high confidence. Agreement is treated as signal.
3. **correlate.cluster_noise** — large groups of same-class info/low findings
   collapse into one representative with an instance count (nothing MEDIUM+ is
   ever hidden).
4. **correlate.cross_target** — the same flaw class on N targets collapses into
   one systemic finding: N instances, one fix.
5. **chains.synthesize** — per-target rules combine findings into composite
   attack-path findings with escalated severity and explicit steps.
6. **remediation.remediate** — attaches deterministic fix guidance to every
   finding (engine-supplied remediation always wins).
7. **the confirmed / needs-review tier** — a finding is *confirmed* when
   corroborated by ≥2 engines, synthesized as a chain, backed by a payload with
   observable proof, or a direct transport observation; everything else is
   flagged for review. No LLM, no destructive exploit.
8. **taxonomy.score** — a 0–100 composite risk score per finding (severity base,
   adjusted by corroboration, confidence, and whether it is a chain), then a
   per-target aggregate with diminishing returns and an A–F grade.
9. **correlate.explain** — the auditable "why we believe this" trail.
10. **baseline.apply** (optional) — diff against a prior `yubel.json`, tagging
    new/existing/regressed and collecting fixed issues.

Every step is deterministic and side-effect-free beyond mutating the findings it
is handed, which keeps the whole layer unit-testable without network or engines.

## Testing

`tests/` runs without network or external binaries, driving the whole pipeline
through the synthetic `DemoEngine`:

| Suite | Concern |
|---|---|
| `test_core.py` | End-to-end pipeline, severity coercion, fingerprint stability, dedupe/merge, routing, opt-in exclusion, config env-expansion, report well-formedness, the CI gate. |
| `test_silent_failures.py` | The paths that used to report "no findings" for a scan that never happened. |
| `test_auth.py` | That every credential kind reaches every engine that can carry one, and that no adapter hand-rolls an `Authorization` header. |
| `test_redact.py` | That the operator's own credentials never reach a report — and that secrets found *on the target* still do. |
| `test_engine_contract.py` | The `Engine` contract, parametrized over every registered engine. |
| `test_engines_doc.py` | That `docs/engines.md` still matches the registry. |
| `test_brand.py` | That the palette has one source, and that no brand colour leaks into the report's severity scale. |
| `test_crawl.py`, `test_analysis.py`, `test_reporting.py`, `test_engines.py` | Discovery seeding, the analysis layer, the reporters, per-adapter behaviour. |

`yubel selftest` runs the same path as a smoke test in CI and on a fresh
checkout.
