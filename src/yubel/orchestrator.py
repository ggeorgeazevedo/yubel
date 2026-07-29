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

ProgressCb = Optional[Callable[[str], None]]


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

        # how many will actually run (available + handles) vs be skipped
        active = [(e, t) for e, t in pairs if e.available() and e.handles(t)]
        self.progress(f"scheduling {len(pairs)} engine runs "
                      f"across {len(self.config.targets)} target(s) "
                      f"— {len(active)} will run, {len(pairs) - len(active)} skipped")
        for eng, tgt in active:
            self.progress(f"  ▶ {eng.name} @ {tgt.label}: running…")

        workers = max(1, int(self.config.parallelism))
        pool = futures.ThreadPoolExecutor(max_workers=workers)
        cancelled = False
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
                # keep the noisy per-engine "skipped (binary not found)" lines quiet
                # unless something actually ran or errored
                if rec.status != "skipped":
                    self.progress(f"  {icon} {eng.name} @ {tgt.label}: "
                                  f"{rec.status} ({rec.findings} findings, {rec.duration}s)"
                                  + (f" — {rec.message}" if rec.message else ""))
        except KeyboardInterrupt:
            cancelled = True
            self.progress("\n✗ scan cancelled — dropping queued engines…")
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            # on cancel, don't re-join in-flight engines (they receive SIGINT
            # with the process group); only wait on a normal completion.
            pool.shutdown(wait=not cancelled)
        result.finished_at = _now()
        return result

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
