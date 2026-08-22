# Contributing to Yubel

Thanks for helping build the best open-source DAST orchestrator. Contributions
of every size are welcome — a new engine adapter, a report format, a bug fix, or
a correction to the [landscape catalog](docs/LANDSCAPE.md).

## Dev setup

```bash
git clone https://github.com/ggeorgeazevedo/yubel && cd yubel
pip install -e ".[dev]"
pytest -q
yubel selftest
```

## Adding an engine (the common case)

An engine adapter is a small, self-contained wrapper around one OSS tool.

1. **Create** `src/yubel/engines/<tool>.py`:

   ```python
   from ..models import Finding, Target, TargetType
   from .base import Engine

   class MyToolEngine(Engine):
       name = "mytool"
       category = "what it does"
       supports = (TargetType.WEB, TargetType.API)
       binary = "mytool"                 # looked up on PATH
       homepage = "https://…"
       header_flag = "-H"                # the tool's add-a-header flag
       # Without header_flag, credentials NEVER reach this engine: it will
       # scan anonymously, find a fraction of what it should, and report
       # that as a normal result. `yubel engines` shows it as AUTH=no.

       def build_command(self, target, workdir):
           out = f"{workdir}/mytool.json"
           return [self.binary, "-u", target.endpoint(), "-o", out, "--json"]

       def parse(self, target, workdir, stdout):
           # read the tool's output and return normalized Findings
           return [Finding(title=..., severity="high", engine=self.name,
                           target=target.label, location=..., cwe="79")]
   ```

2. **Register** it in `engines/registry.py` → `ALL_ENGINES`. If it is intrusive
   (modifies data / exploits), add its name to `OPT_IN`.

3. **Test** it. Add a parse-only unit test with a captured sample of the tool's
   output — no network needed. See `tests/` for patterns.

4. **Regenerate the reference**: `python3 scripts/gen_engines.py`, and commit
   `docs/engines.md`. If your adapter reads a new `self.options.get("…")` key,
   add a description for it in that script's `DESCRIPTIONS` — CI fails on an
   undocumented option, and on a stale doc.

### Adapter rules

- **Never raise** out of `build_command`/`parse` for expected conditions; return
  `[]` and let the base class record the run. The base `run()` already sandboxes
  execution and captures timeouts/crashes.
- **Write outputs into `workdir`** (a temp dir cleaned up for you). Don't write
  to the CWD.
- **Map severity honestly** via the shared scale — don't invent your own.
- **Set `cwe`/`cve`/`references`** when the tool provides them; it powers SARIF
  rules and de-duplication.
- **Respect `self.options`** for tunables (timeouts, rate limits, depth).
- **Keep it dependency-light** — the core depends only on PyYAML. Engines are
  external processes, not Python imports.

## Adding a report format

Add `reporters/<fmt>_reporter.py` with a `write_<fmt>(result, path)` function and
register it in `reporters.WRITERS`.

## Landscape catalog

`docs/LANDSCAPE.md` is generated — edit `scripts/dast_data.py` and run
`python scripts/gen_landscape.py`. Include a source for any status/maintenance
claim; when sources disagree, note it in the Observações column.

## Style & checks

- `ruff check src` for linting.
- Keep functions small and readable; comments explain *why*, not *what*.
- CI runs `pytest` on Python 3.9/3.11/3.12 and builds the Docker image.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open public issues for
vulnerabilities in Yubel itself.

## Licensing

By contributing you agree your contribution is licensed under Apache-2.0. Don't
copy code from GPL/proprietary tools into this repo — Yubel *invokes* those
tools as separate processes precisely to keep license boundaries clean.
