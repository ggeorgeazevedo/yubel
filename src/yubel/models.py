"""Core data models: Targets, Findings, and Scan results.

These are engine-agnostic. Every engine adapter is responsible for translating
its native output into a list of `Finding` objects bound to a `Target`.
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional

from .severity import Severity


class TargetType(str, Enum):
    """What kind of thing we are pointing Yubel at.

    The type drives which engines are eligible. A `web` target runs the full
    crawl+attack suite; an `api` target runs spec-driven fuzzers; a `kubernetes`
    target runs cluster pentest engines; and so on.
    """
    WEB = "web"                # HTML app / SPA / portal / dashboard
    API = "api"                # REST / OpenAPI / SOAP
    GRAPHQL = "graphql"        # GraphQL endpoint
    GRPC = "grpc"              # gRPC service
    KUBERNETES = "kubernetes"  # a cluster (API server / ingress / pod-internal)
    CONTAINER = "container"    # a running container / image endpoint
    CLOUD = "cloud"            # cloud-hosted asset / external attack surface
    HOST = "host"              # bare host / IP with exposed services

    def __str__(self) -> str:  # nicer YAML/CLI display
        return self.value


@dataclass
class Auth:
    """Authentication context handed to engines that support it."""
    kind: str = "none"          # none|basic|bearer|cookie|header|form|oauth2
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    login_url: Optional[str] = None
    logged_in_regex: Optional[str] = None

    @property
    def enabled(self) -> bool:
        return self.kind and self.kind != "none"


#: The vantage points kube-hunter can be run from. This tuple is the only
#: place they are written down: `--k8s-mode` builds its argparse `choices`
#: from it, `Config.validate()` checks the YAML path against it, and
#: `KubeHunterEngine` matches on it. They used to be three independent
#: literals and two comments, which is exactly why the YAML path accepted
#: anything: `k8s_mode: pods` fell past all three branches and kube-hunter
#: ran with no vantage flag at all — a clean report for a scan that never
#: happened.
K8S_MODES = ("remote", "internal", "pod")


@dataclass
class Target:
    """A single thing to scan."""
    type: TargetType
    url: Optional[str] = None            # http(s) URL (web/api/graphql/cloud)
    host: Optional[str] = None           # host or IP (host/container/grpc)
    port: Optional[int] = None
    openapi: Optional[str] = None        # path/URL to OpenAPI/Swagger spec
    kubeconfig: Optional[str] = None     # for kubernetes targets
    k8s_mode: str = "remote"             # one of K8S_MODES
    scope: List[str] = field(default_factory=list)   # in-scope host regexes
    exclude: List[str] = field(default_factory=list)  # out-of-scope regexes
    auth: Auth = field(default_factory=Auth)
    tags: List[str] = field(default_factory=list)
    name: Optional[str] = None
    #: URLs discovered by the crawler at runtime (katana), fed to the parameter
    #: scanners (nuclei -l / dalfox) so they cover the whole attack surface, not
    #: just the seed URL. Populated by the orchestrator's discovery phase.
    seed_urls: List[str] = field(default_factory=list)

    def __post_init__(self):
        if isinstance(self.type, str):
            self.type = TargetType(self.type)
        if isinstance(self.auth, dict):
            self.auth = Auth(**self.auth)

    @property
    def label(self) -> str:
        return self.name or self.url or self.host or f"{self.type}-target"

    def endpoint(self) -> str:
        if self.url:
            return self.url
        if self.host and self.port:
            return f"{self.host}:{self.port}"
        return self.host or ""

    def scan_urls(self, limit: int = 0) -> List[str]:
        """The seed endpoint plus any crawler-discovered URLs, de-duplicated
        (endpoint first). `limit > 0` caps the total."""
        seen, out = set(), []
        for u in [self.endpoint(), *self.seed_urls]:
            u = (u or "").strip()
            if u and u not in seen:
                seen.add(u)
                out.append(u)
        return out[:limit] if limit and limit > 0 else out

    def param_urls(self, limit: int = 0) -> List[str]:
        """Discovered URLs that carry a query string (`?k=v`) — the only ones a
        parameter scanner like dalfox can actually test. Falls back to the seed
        endpoint if it has parameters and nothing else was discovered."""
        urls = [u for u in self.scan_urls() if "?" in u and "=" in u]
        return urls[:limit] if limit and limit > 0 else urls


def canon_cwe(value: Any) -> Optional[str]:
    """Normalise a CWE id to bare digits, or None.

    Every engine spells this differently: nuclei emits `cwe-79` (its JSON
    classification carries the prefix), ZAP and dalfox emit `79`, and testssl
    used to strip `CWE-` by hand at its own call site. The field feeds
    `Finding.fingerprint`, `analysis.chains` and `correlate._class_key`, so an
    inconsistent spelling silently splits one issue into two: the same XSS
    found by nuclei and by ZAP never corroborates, the attack-chain rules go
    blind to whichever engine spells it the other way, and the systemic
    correlation counts one class as two.

    Normalising at construction means no adapter, present or future, can
    reintroduce the split.
    """
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    # ZAP uses -1 for "no CWE mapped"; some tools use 0
    if raw.lstrip("+-").isdigit() and int(raw) <= 0:
        return None
    match = re.search(r"\d+", raw)          # first id wins in "CWE-1004, CWE-79"
    if not match:
        return None
    return match.group(0).lstrip("0") or None


@dataclass
class Finding:
    """A normalized security finding produced by an engine."""
    title: str
    severity: Severity
    engine: str
    target: str
    description: str = ""
    location: str = ""            # URL / path / parameter / resource
    evidence: str = ""
    cwe: Optional[str] = None
    cve: Optional[str] = None
    references: List[str] = field(default_factory=list)
    confidence: str = "medium"    # low|medium|high
    remediation: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)

    # ---- proof / evidence (the "where is it, prove it" trail) ----------
    param: str = ""               # the vulnerable parameter, when known
    payload: str = ""             # the payload/input that triggered it
    request: str = ""             # raw HTTP request that demonstrates the issue
    response: str = ""            # raw/snippet HTTP response that proves it
    verified: bool = False        # deterministically confirmed (see analysis)

    # ---- enrichment added by the analysis pipeline ---------------------
    also_reported_by: List[str] = field(default_factory=list)  # other engines
    corroboration: int = 1        # how many engines independently reported it
    instances: int = 1            # occurrences (after clustering)
    status: str = "new"           # new|existing|regressed|fixed (vs baseline)
    owasp: Optional[str] = None   # OWASP Top 10 2021 category, e.g. "A03:2021"
    owasp_api: Optional[str] = None   # OWASP API Top 10 2023, e.g. "API7:2023"
    mitre: List[str] = field(default_factory=list)   # ATT&CK technique ids
    risk_score: float = 0.0       # 0-100 composite (severity×corroboration×exposure)
    is_chain: bool = False        # synthesized attack-chain finding
    chain_steps: List[str] = field(default_factory=list)
    is_systemic: bool = False     # same issue class seen across multiple targets
    affected_targets: List[str] = field(default_factory=list)
    rationale: str = ""           # deterministic "why we believe this" trail

    def __post_init__(self):
        self.severity = Severity.from_any(self.severity)
        self.cwe = canon_cwe(self.cwe)

    @property
    def fingerprint(self) -> str:
        """Stable id used to de-duplicate the same issue seen by >1 engine."""
        basis = "|".join([
            "chain" if self.is_chain else "",
            self.title.strip().lower(),
            (self.location or self.target).strip().lower(),
            (self.cwe or "").lower(),
        ])
        return hashlib.sha1(basis.encode("utf-8", "ignore")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class EngineRun:
    """Bookkeeping for a single engine execution."""
    engine: str
    target: str
    status: str = "pending"       # pending|ok|skipped|error|timeout
    started_at: float = 0.0
    finished_at: float = 0.0
    findings: int = 0
    message: str = ""
    command: str = ""
    #: version of the underlying tool, "" when it could not be determined.
    #: For a scanner the version *is* the finding set, so a report that does
    #: not name it cannot be checked against a later one.
    tool_version: str = ""

    @property
    def duration(self) -> float:
        if self.started_at and self.finished_at:
            return round(self.finished_at - self.started_at, 2)
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["duration_s"] = self.duration
        return d


@dataclass
class ScanResult:
    """The full output of an Yubel run."""
    findings: List[Finding] = field(default_factory=list)
    runs: List[EngineRun] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    version: str = ""
    fixed: List[Finding] = field(default_factory=list)   # closed since baseline
    baseline: Optional[str] = None                       # baseline label/path

    def add(self, findings: List[Finding]):
        self.findings.extend(findings)

    def dedupe(self) -> "ScanResult":
        """Collapse duplicate findings, keeping the highest-severity copy and
        recording every engine that reported it (cross-engine corroboration)."""
        best: Dict[str, Finding] = {}
        engines_seen: Dict[str, set] = {}
        for f in self.findings:
            fp = f.fingerprint
            engines_seen.setdefault(fp, set()).add(f.engine)
            if fp not in best:
                best[fp] = f
            elif f.severity > best[fp].severity:
                best[fp] = f
        for fp, keep in best.items():
            others = sorted(engines_seen[fp] - {keep.engine})
            keep.also_reported_by = others
            keep.corroboration = len(engines_seen[fp])
        deduped = ScanResult(
            findings=sorted(best.values(),
                            key=lambda x: (-int(x.severity), x.title)),
            runs=self.runs,
            started_at=self.started_at,
            finished_at=self.finished_at,
            version=self.version,
        )
        deduped.fixed = self.fixed
        deduped.baseline = self.baseline
        return deduped

    def counts(self) -> Dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        out["Total"] = len(self.findings)
        return out

    def diff_counts(self) -> Dict[str, int]:
        """New/existing/regressed/fixed breakdown (populated when a baseline
        was supplied; otherwise everything is 'new')."""
        out = {"new": 0, "existing": 0, "regressed": 0, "fixed": len(self.fixed)}
        for f in self.findings:
            out[f.status] = out.get(f.status, 0) + 1
        return out

    def new_findings(self) -> List["Finding"]:
        return [f for f in self.findings if f.status in ("new", "regressed")]

    def max_severity(self, only_new: bool = False) -> Severity:
        pool = self.new_findings() if only_new else self.findings
        return max((f.severity for f in pool), default=Severity.INFO)

    def targets(self) -> List[str]:
        seen = []
        for f in self.findings:
            if f.target not in seen:
                seen.append(f.target)
        return seen

    @property
    def duration(self) -> float:
        end = self.finished_at or time.time()
        return round(end - self.started_at, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": self.duration,
            "summary": self.counts(),
            "diff": self.diff_counts(),
            "baseline": self.baseline,
            "engine_runs": [r.to_dict() for r in self.runs],
            "findings": [f.to_dict() for f in self.findings],
            "fixed": [f.to_dict() for f in self.fixed],
        }
