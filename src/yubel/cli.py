"""Yubel command-line interface.

Subcommands:
  scan       run a scan from a config file and/or CLI-specified targets
  engines    list registered engines and whether they are available here
  selftest   run the synthetic engine and emit reports (no network needed)
  init       write a starter yubel.yaml
  version    print version
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .config import Config, OutputConfig
from .engines import ALL_ENGINES, OPT_IN
from .models import K8S_MODES, Auth, Target, TargetType
from .orchestrator import Orchestrator, gate
from .reporters import write_reports
from .severity import Severity
from .analysis import analyze
from .analysis.taxonomy import target_risk, grade

BANNER = r"""
 __   __ _   _ ____  _____ _
 \ \ / /| | | | __ )| ____| |
  \ V / | | | |  _ \|  _| | |          the ever-watchful guardian
   | |  | |_| | |_) | |___| |___       all-seeing dynamic security
   |_|   \___/|____/|_____|_____|      v{v}
""".format(v=__version__)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="yubel",
        description="Orchestrate best-of-breed OSS DAST engines against web, "
                    "APIs, cloud, containers and Kubernetes.")
    parser.add_argument("--version", action="version",
                        version=f"Yubel {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    # scan ---------------------------------------------------------------
    ps = sub.add_parser("scan", help="run a scan")
    ps.add_argument("-c", "--config", help="path to yubel.yaml")
    ps.add_argument("-t", "--target", action="append", default=[],
                    help="target URL (repeatable); shorthand for a web target")
    ps.add_argument("--type", default="web",
                    choices=[t.value for t in TargetType],
                    help="target type for --target (default: web)")
    ps.add_argument("--openapi", help="OpenAPI/Swagger spec path or URL (api targets)")
    ps.add_argument("--kube", help="Kubernetes remote host/IP (kubernetes target)")
    ps.add_argument("--k8s-mode", default="remote", choices=list(K8S_MODES))
    ps.add_argument("-e", "--engine", action="append", default=[],
                    help="allow-list an engine (repeatable)")
    ps.add_argument("-x", "--disable", action="append", default=[],
                    help="deny-list an engine (repeatable)")
    ps.add_argument("--bearer", help="bearer token for auth")
    ps.add_argument("--header", action="append", default=[],
                    help="extra header 'K: V' (repeatable)")
    ps.add_argument("--include-intrusive", action="store_true",
                    help=f"enable opt-in intrusive engines ({', '.join(sorted(OPT_IN))})")
    ps.add_argument("-p", "--parallelism", type=int, default=None,
                    help="max concurrent engines (default 4 / config value)")
    ps.add_argument("-o", "--out", default="yubel-report",
                    help="output directory")
    ps.add_argument("-f", "--format", action="append", default=[],
                    help="report format: json|html|markdown|sarif (repeatable)")
    ps.add_argument("--fail-on", choices=[s.name.lower() for s in Severity],
                    help="exit non-zero if any finding >= this severity (CI gate)")
    ps.add_argument("--baseline", help="prior yubel.json to diff against "
                    "(marks new/fixed/regressed)")
    ps.add_argument("--fail-on-new", action="store_true",
                    help="with --baseline, gate only on NEW/regressed findings")
    ps.add_argument("--no-chains", action="store_true",
                    help="disable attack-chain synthesis")
    ps.add_argument("--cluster", type=int, default=None, metavar="N",
                    help="cluster >=N similar info/low findings (0 disables; "
                         "default 8 / config value)")
    ps.add_argument("--fast", action="store_true",
                    help="quick profile: nuclei fuzzing-only high/critical, "
                         "short Nikto cap, tighter timeouts (for smoke tests)")
    ps.add_argument("--offline", action="store_true",
                    help="air-gapped hardening: engines make no external calls "
                         "(no OAST/interactsh, no update checks). Yubel's core "
                         "never phones home regardless.")
    ps.add_argument("--allow-internal", action="store_true",
                    help="permit link-local (169.254/16, the cloud metadata "
                         "service), loopback and RFC1918 targets. Refused by "
                         "default: the metadata endpoint answers with the "
                         "credentials of whatever is running the scan, and "
                         "those would land whole in the report.")
    ps.add_argument("--no-crawl", action="store_true",
                    help="do not feed crawler-discovered URLs to the parameter "
                         "scanners (scan only the seed URL of each target)")
    ps.add_argument("--crawl-headless", action="store_true",
                    help="run the katana crawler with a headless browser so it "
                         "discovers endpoints in JS/SPA apps (needs Chrome/Chromium)")
    ps.add_argument("-q", "--quiet", action="store_true")

    # engines ------------------------------------------------------------
    pe = sub.add_parser("engines", help="list engines and availability")
    pe.add_argument("--check", action="store_true",
                    help="exit 1 if any non-opt-in engine is missing "
                         "(for verifying an image or an install)")
    # setup --------------------------------------------------------------
    pu = sub.add_parser("setup", help="install the scanning engines (one command)")
    pu.add_argument("--install", action="store_true",
                    help="actually run the installers (default: just show the plan)")
    pu.add_argument("-e", "--engine", action="append", default=[],
                    help="only set up these engines (repeatable)")
    # selftest -----------------------------------------------------------
    pt = sub.add_parser("selftest", help="run synthetic scan (no network)")
    pt.add_argument("-o", "--out", default="yubel-selftest")
    # init ---------------------------------------------------------------
    pi = sub.add_parser("init", help="write a starter config")
    pi.add_argument("-o", "--out", default="yubel.yaml")
    sub.add_parser("version", help="print version")

    args = parser.parse_args(argv)
    if not args.cmd:
        print(BANNER)
        parser.print_help()
        return 0

    try:
        if args.cmd == "version":
            print(__version__)
            return 0
        if args.cmd == "engines":
            return _cmd_engines(check=args.check)
        if args.cmd == "setup":
            return _cmd_setup(args)
        if args.cmd == "init":
            return _cmd_init(args.out)
        if args.cmd == "selftest":
            return _cmd_selftest(args.out)
        if args.cmd == "scan":
            return _cmd_scan(args)
        return 1
    except KeyboardInterrupt:
        print("\n✗ cancelled by user (partial results discarded).",
              file=sys.stderr)
        return 130


def _cmd_engines(check: bool = False) -> int:
    """List the engines — and, with --check, refuse to stay quiet about gaps.

    `--check` exists because of a real incident: the published container image
    advertised thirteen engines and shipped eleven. The ZAP download 404'd on a
    pinned filename under a `latest/` path, `curl` without `-f` exits 0 on an
    HTTP error, and a trailing `|| true` swallowed what was left — so the build
    went green with no ZAP. Nothing ever asked the image what it actually had.
    Now the build asks, and fails if the answer is wrong.
    """
    print(BANNER)
    print(f"{'ENGINE':<16}{'AVAILABLE':<11}{'AUTH':<6}{'TARGETS':<34}CATEGORY")
    print("-" * 102)
    no_auth = []
    for cls in ALL_ENGINES:
        if cls.name == "demo":
            continue
        eng = cls()
        avail = "yes" if eng.available() else "no"
        # whether credentials actually reach this engine — a scan that runs
        # unauthenticated finds a fraction of what an authenticated one does,
        # and it used to be invisible which engines were in that boat
        auth = "yes" if eng.supports_auth() else "no"
        if not eng.supports_auth():
            no_auth.append(cls.name)
        tgts = ",".join(t.value for t in cls.supports)
        opt = "  (intrusive/opt-in)" if cls.name in OPT_IN else ""
        print(f"{cls.name:<16}{avail:<11}{auth:<6}{tgts:<34}{cls.category}{opt}")
    print("\nMissing engines are simply skipped at runtime — install them "
          "locally or use the Yubel Docker image.")
    if no_auth:
        print(f"AUTH=no means credentials are NOT passed to that engine, so it "
              f"scans anonymously: {', '.join(no_auth)}.")

    if check:
        # opt-in engines are excluded on purpose: sqlmap is intrusive and an
        # image is allowed to ship without it.
        missing = sorted(cls.name for cls in ALL_ENGINES
                         if cls.name != "demo" and cls.name not in OPT_IN
                         and not cls().available())
        if missing:
            print(f"\n✗ {len(missing)} engine(s) missing: "
                  f"{', '.join(missing)}", file=sys.stderr)
            return 1
        print("\n✓ every non-opt-in engine is present")
    return 0


def _cmd_setup(args) -> int:
    """Detect missing engines and install them with one command."""
    import subprocess
    from .engines.install import plan_for

    print(BANNER)
    wanted = args.engine or [c.name for c in ALL_ENGINES if c.name != "demo"]
    rows, todo = [], []
    for cls in ALL_ENGINES:
        if cls.name == "demo" or cls.name not in wanted:
            continue
        eng = cls()
        installed = eng.available()
        plan = plan_for(cls.name)
        label = plan[2] if plan else "—"
        rows.append((cls.name, installed, plan[0] if plan else "?", label))
        if not installed and plan and plan[0] != "manual":
            todo.append((cls.name, plan))

    print(f"{'ENGINE':<15}{'STATUS':<14}HOW TO INSTALL")
    print("-" * 78)
    for name, installed, _method, label in rows:
        status = "installed" if installed else "missing"
        print(f"{name:<15}{status:<14}{'' if installed else label}")

    if not todo:
        print("\nAll requested engines are installed. ✅")
        return 0

    if not args.install:
        print(f"\n{len(todo)} engine(s) missing. Run "
              f"'yubel setup --install' to install them automatically,")
        print("or run the commands shown above yourself.")
        return 0

    print(f"\nInstalling {len(todo)} engine(s)…\n")
    ok, failed = [], []
    for name, plan in todo:
        _method, argv, label = plan
        print(f"→ {name}: {label}")
        try:
            proc = subprocess.run(argv, text=True)
            (ok if proc.returncode == 0 else failed).append(name)
        except Exception as e:
            print(f"   error: {e}")
            failed.append(name)
    print(f"\nDone. Installed: {', '.join(ok) or 'none'}"
          + (f"  ·  failed: {', '.join(failed)}" if failed else ""))
    print("Run 'yubel engines' to confirm.")
    return 1 if failed else 0


def _cmd_init(path: str) -> int:
    from .templates import STARTER_CONFIG
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(STARTER_CONFIG)
    print(f"wrote starter config to {path}")
    return 0


def _cmd_selftest(out_dir: str) -> int:
    print(BANNER)
    cfg = Config(targets=[Target(type=TargetType.WEB, url="https://demo.example.com",
                                 name="selftest-target")],
                 output=OutputConfig(dir=out_dir))
    orch = Orchestrator(cfg, progress=print, selftest=True)
    result = analyze(orch.run().dedupe())
    paths = write_reports(result, out_dir, ["json", "html", "markdown"], sarif=True)
    print("\nreports:")
    for p in paths:
        print(f"  {p}")
    print(f"\nsummary: {result.counts()}")
    print("selftest OK ✅")
    return 0


def _build_auth(bearer: Optional[str],
                headers: Optional[List[str]]) -> Auth:
    """Combine `--bearer` and `--header` instead of letting one erase the other.

    These used to be two sequential assignments to the same variable, so
    `--bearer X --header "Y: Z"` silently dropped the token: the whole scan ran
    unauthenticated and reported the handful of findings an anonymous crawl
    finds. A false all-clear, which is the worst failure a security tool has.

    A bearer token *is* an Authorization header, so the two compose: the kind
    stays `bearer` when a token is present (engines that only understand
    bearer keep working), and the extra headers ride along for the engines
    that read them.
    """
    parsed = {}
    for item in headers or []:
        name, sep, value = (item or "").partition(":")
        if sep and name.strip():
            parsed[name.strip()] = value.strip()

    if bearer and parsed:
        return Auth(kind="bearer", token=bearer, headers=parsed)
    if bearer:
        return Auth(kind="bearer", token=bearer)
    if parsed:
        return Auth(kind="header", headers=parsed)
    return Auth()


def _cmd_scan(args) -> int:
    if not args.quiet:
        print(BANNER)

    if args.config:
        cfg = Config.load(args.config)
    else:
        cfg = Config()

    # merge CLI-specified targets
    auth = _build_auth(args.bearer, args.header)
    for url in args.target:
        cfg.targets.append(Target(type=TargetType(args.type), url=url,
                                  openapi=args.openapi, auth=auth))
    if args.kube:
        cfg.targets.append(Target(type=TargetType.KUBERNETES, host=args.kube,
                                  k8s_mode=args.k8s_mode))

    # CLI overrides
    if args.engine:
        cfg.engines = args.engine
    if args.disable:
        cfg.disable = args.disable
    if args.include_intrusive:
        cfg.include_opt_in = True
    if args.parallelism is not None:
        cfg.parallelism = args.parallelism
    if args.fail_on:
        cfg.fail_on = Severity.from_any(args.fail_on)
    if args.fail_on_new:
        cfg.fail_on_new = True
    if args.baseline:
        cfg.baseline = args.baseline
    if args.no_chains:
        cfg.chains = False
    if args.cluster is not None:
        cfg.cluster_threshold = args.cluster
    if args.fast:
        _apply_fast_profile(cfg)
    if args.offline:
        cfg.offline = True
    if cfg.offline:
        _apply_offline(cfg)
    if args.allow_internal:
        cfg.allow_internal = True
    if args.no_crawl:
        cfg.crawl = False
    if args.crawl_headless:
        cfg.options.setdefault("katana", {})["headless"] = True
    cfg.output.dir = args.out
    if args.format:
        cfg.output.formats = args.format

    errors = cfg.validate()
    if errors:
        for e in errors:
            print(f"config error: {e}", file=sys.stderr)
        return 1

    orch = Orchestrator(cfg, progress=(None if args.quiet else print))
    result = analyze(orch.run().dedupe(), baseline_path=cfg.baseline,
                     cluster_threshold=cfg.cluster_threshold,
                     enable_chains=cfg.chains)
    paths = write_reports(result, cfg.output.dir, cfg.output.formats,
                          sarif=cfg.output.sarif)
    if not args.quiet:
        _print_posture(result)
        print("\nreports written:")
        for p in paths:
            print(f"  {p}")

    code = gate(result, cfg)
    if code and not args.quiet:
        scope = "new/regressed " if cfg.fail_on_new else ""
        print(f"\n✗ gate failed: {scope}findings at/above '{cfg.fail_on.label}'")
    return code


def _apply_offline(cfg) -> None:
    """Air-gapped hardening: tell every engine to avoid external services.

    Yubel's own core makes zero network calls — it only ever talks to the
    targets you point it at. This flag additionally stops the *engines* from
    reaching out (e.g. Nuclei's OAST/interactsh server or template update
    checks), so the whole run stays inside your perimeter.
    """
    for name in ("nuclei", "katana", "httpx", "nikto", "wapiti", "testssl",
                 "dalfox", "schemathesis", "zap", "kube-hunter"):
        cfg.options.setdefault(name, {})["offline"] = True


def _apply_fast_profile(cfg) -> None:
    """A quick smoke-test profile: trade coverage for speed."""
    def opt(name):
        return cfg.options.setdefault(name, {})
    opt("nuclei").update({"full": False, "dast": True,
                          "severity": "high,critical", "timeout": 300})
    opt("nikto").update({"maxtime": 120, "timeout": 180})
    for eng in ("wapiti", "zap", "testssl", "dalfox", "katana", "schemathesis"):
        opt(eng).setdefault("timeout", 300)


def _print_posture(result) -> None:
    """Console summary: risk grade, severity counts, chains and diff."""
    risk = target_risk(result.findings)
    counts = result.counts()
    chains = [f for f in result.findings if f.is_chain]
    print(f"\n  risk posture: grade {grade(risk)}  (score {risk}/100)")
    print(f"  findings: {counts['Total']}  "
          f"[C{counts['Critical']} H{counts['High']} M{counts['Medium']} "
          f"L{counts['Low']} I{counts['Info']}]")
    if chains:
        print(f"  ⚑ {len(chains)} attack chain(s) synthesized:")
        for c in chains[:5]:
            print(f"     → {c.title}")
    if result.baseline:
        d = result.diff_counts()
        print(f"  Δ baseline: {d['new']} new, {d['regressed']} regressed, "
              f"{d['existing']} existing, {d['fixed']} fixed")


if __name__ == "__main__":
    raise SystemExit(main())
