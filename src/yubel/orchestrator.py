"""The orchestrator: fan out engines across targets, collect, normalize, gate.

Design goals:
  * resilient  - one engine failing never aborts the scan
  * parallel   - engines run concurrently (bounded by config.parallelism)
  * honest     - every engine execution is recorded (ok/skipped/error/timeout)
  * portable   - pure stdlib threads; no event loop or external queue needed
"""
from __future__ import annotations

import concurrent.futures as futures
from typing import Callable, Optional

from . import __version__
from .config import Config
from .engines import select_for
from .engines.demo import DemoEngine
from .models import ScanResult, Target
from .netguard import internal_reason

ProgressCb = Optional[Callable[[str], None]]

#: engines that map a target's attack surface; they run *before* the scanners so
#: their discovered URLs can be fed to the parameter engines (nuclei -l / dalfox).
DISCOVERY_ENGINES = ("katana", "httpx")


class Orchestrator:
    def __init__(self, config: Config, progress: ProgressCb = None,
                 selftest: bool = False):
        self.config = config
        self.progress = progress or (lambda _msg: None)
        self.selftest = selftest

    def _plan(self):
        """Yield (engine, target) pairs to execute."""
        for target in self.config.targets:
            if self.selftest:
                yield DemoEngine(), target
                continue
            engines = select_for(
                target,
                enabled=self.config.engines,
                disabled=self.config.disable,
                options=self.config.options,
                include_opt_in=self.config.include_opt_in,
            )
            for eng in engines:
                yield eng, target

    def run(self) -> ScanResult:
        result = ScanResult(version=__version__)
        pairs = list(self._plan())
        if not pairs:
            self.progress("nothing to run (no engines matched the targets)")
            result.finished_at = _now()
            return result

        active = [(e, t) for e, t in pairs if e.available() and e.handles(t)]
        self.progress(f"scheduling {len(pairs)} engine runs "
                      f"across {len(self.config.targets)} target(s) "
                      f"— {len(active)} will run, {len(pairs) - len(active)} skipped")
        for eng, tgt in active:
            self.progress(f"  ▶ {eng.name} @ {tgt.label}: running…")

        # Two phases: discovery first (so the crawler's URLs are ready), then the
        # scanners. Within each phase everything runs in parallel. When crawling
        # is off, or no discovery engine is selected, this collapses to a single
        # scan phase with identical behaviour to before.
        discovery = [(e, t) for e, t in pairs if e.name in DISCOVERY_ENGINES]
        scanning = [(e, t) for e, t in pairs if e.name not in DISCOVERY_ENGINES]

        cancelled = [False]
        try:
            if discovery:
                self._run_batch(discovery, result, cancelled)
                if self.config.crawl:
                    self._seed_from_discovery(result)
            self._run_batch(scanning, result, cancelled)
        except KeyboardInterrupt:
            self.progress("\n✗ scan cancelled — dropping queued engines…")
            raise
        result.finished_at = _now()
        return result

    def _run_batch(self, pairs, result: ScanResult, cancelled) -> None:
        """Run a set of (engine, target) pairs concurrently, folding their
        findings and run records into `result`."""
        if not pairs:
            return
        workers = max(1, int(self.config.parallelism))
        pool = futures.ThreadPoolExecutor(max_workers=workers)
        try:
            fut_map = {pool.submit(self._run_one, eng, tgt): (eng, tgt)
                       for eng, tgt in pairs}
            for fut in futures.as_completed(fut_map):
                eng, tgt = fut_map[fut]
                findings, rec = fut.result()
                result.add(findings)
                result.runs.append(rec)
                icon = {"ok": "✓", "skipped": "–", "error": "✗",
                        "timeout": "⏱"}.get(rec.status, "?")
                if rec.status != "skipped":
                    self.progress(f"  {icon} {eng.name} @ {tgt.label}: "
                                  f"{rec.status} ({rec.findings} findings, {rec.duration}s)"
                                  + (f" — {rec.message}" if rec.message else ""))
        except KeyboardInterrupt:
            cancelled[0] = True
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            pool.shutdown(wait=not cancelled[0])

    def _seed_from_discovery(self, result: ScanResult) -> None:
        """Feed the crawler's discovered URLs into each target's `seed_urls`, so
        the parameter scanners cover the whole surface. Capped and logged (never
        a silent truncation)."""
        by_label = {t.label: t for t in self.config.targets}
        for f in result.findings:
            if f.engine != "katana":
                continue
            endpoints = [u for u in (f.raw or {}).get("endpoints", []) if u]
            tgt = by_label.get(f.target)
            if not tgt or not endpoints:
                continue
            endpoints = self._contain(endpoints, tgt, result)
            if not endpoints:
                continue
            cap = self.config.crawl_max_urls
            tgt.seed_urls = endpoints[:cap] if cap and cap > 0 else endpoints
            dropped = max(0, len(endpoints) - len(tgt.seed_urls))
            note = f" (capped from {len(endpoints)}; raise crawl_max_urls)" if dropped else ""
            self.progress(f"  → crawler surfaced {len(tgt.seed_urls)} URL(s) for "
                          f"{tgt.label}; feeding the parameter scanners{note}")

    def _contain(self, urls, target: Target, result: ScanResult):
        """Drop discovered URLs that `Config.validate()` would have refused.

        `validate()` runs once, before anything executes, and sees only the
        targets the operator wrote. These URLs come from the crawler at
        runtime — katana follows links, and with `-jc` it extracts routes out
        of JS bundles — so a link to `169.254.169.254` on the target's own
        pages walks straight past the check and into nuclei and dalfox.
        Refusing at the seam is the only place that covers it.

        Refusals are recorded, not just dropped: the count and the first
        reason go onto the crawler's `EngineRun.message`, so `yubel.json`
        carries the fact. "The scan ignored something" must never be
        deducible only from a smaller number.
        """
        if self.config.allow_internal:
            return urls
        kept, refused = [], []
        for url in urls:
            reason = internal_reason(url)
            if reason:
                refused.append(f"{url} ({reason})")
            else:
                kept.append(url)
        if refused:
            note = (f"{len(refused)} discovered URL(s) refused as internal; "
                    f"first: {refused[0]}")
            self.progress(f"  ! {note}")
            for rec in result.runs:
                if rec.engine == "katana" and rec.target == target.label:
                    rec.message = f"{rec.message} — {note}" if rec.message else note
        return kept

    def _run_one(self, engine, target: Target):
        try:
            return engine.run(target)
        except Exception as e:  # last-resort guard
            from .models import EngineRun
            rec = EngineRun(engine=engine.name, target=target.label,
                            status="error", message=f"{type(e).__name__}: {e}")
            return [], rec


def gate(result: ScanResult, config: Config) -> int:
    """Return process exit code based on the fail_on threshold (for CI).

    With `fail_on_new`, only findings introduced since the baseline count —
    so an unchanged backlog never blocks a pipeline, but a newly introduced
    (or regressed) issue at/above the threshold does.
    """
    if config.fail_on is None:
        return 0
    worst = result.max_severity(only_new=config.fail_on_new)
    return 2 if worst >= config.fail_on else 0


def _now() -> float:
    import time
    return time.time()
