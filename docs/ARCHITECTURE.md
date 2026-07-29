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
                         │  plan (engine × target)     │
                         │  ThreadPool(parallelism)    │
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
| `config.py` | YAML/dict → `Config`, with `${ENV}` expansion and validation. |
| `engines/base.py` | The `Engine` contract: `available()`, `handles()`, `build_command()`, `parse()`, and a hardened `run()` that sandboxes each tool in a temp dir and never raises. |
| `engines/*.py` | One adapter per tool. Small, isolated, independently testable. |
| `engines/registry.py` | The single list of engines + routing logic (`select_for`). |
| `orchestrator.py` | Fan-out execution, progress, and the CI `gate()`. |
| `analysis/taxonomy.py` | CWE→OWASP 2021 / OWASP API 2023 / MITRE mapping; composite risk score; per-target grade; OWASP coverage. |
| `analysis/correlate.py` | Cross-engine consensus (confidence uplift) and noise clustering. |
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
same URL collapse to one finding (by `fingerprint = sha1(title|location|cwe)`),
keeping the highest severity and recording every engine that saw it in
`raw._also_reported_by`. Corroboration raises confidence without inflating counts.

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

Adding an engine touches exactly two files: a new adapter in `engines/` and one
line in `registry.ALL_ENGINES`. Everything downstream (availability, routing,
CLI, parallelism, dedupe, all four reporters, the fail-gate) is automatic.

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
4. **chains.synthesize** — per-target rules combine findings into composite
   attack-path findings with escalated severity and explicit steps.
5. **taxonomy.score** — a 0–100 composite risk score per finding (severity base,
   adjusted by corroboration, confidence, and whether it is a chain), then a
   per-target aggregate with diminishing returns and an A–F grade.
6. **baseline.apply** (optional) — diff against a prior `yubel.json`, tagging
   new/existing/regressed and collecting fixed issues.

Every step is deterministic and side-effect-free beyond mutating the findings it
is handed, which keeps the whole layer unit-testable without network or engines.

## Testing

`tests/test_core.py` exercises the whole pipeline without network or external
binaries via the synthetic `DemoEngine`, plus severity coercion, fingerprint
stability, dedupe/merge, routing, opt-in exclusion, config env-expansion, report
well-formedness (valid JSON + SARIF, self-contained HTML) and the CI gate.
`yubel selftest` runs the same path as a smoke test in CI and on a fresh
checkout.
