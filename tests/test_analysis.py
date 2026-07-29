"""Tests for the analysis pipeline: taxonomy, consensus, chains, clustering, baseline."""
import json

from yubel.models import ScanResult, Finding
from yubel.analysis import analyze
from yubel.analysis import taxonomy, correlate, chains
from yubel.severity import Severity


def _mk(*findings):
    r = ScanResult(version="test")
    r.add(list(findings))
    return r


def test_taxonomy_owasp_and_mitre():
    f = Finding("SQLi", "high", "nuclei", "t", cwe="89")
    taxonomy.enrich(f)
    assert f.owasp.startswith("A03:2021")
    assert "T1190" in f.mitre
    g = Finding("SSRF", "high", "nuclei", "t", cwe="918")
    taxonomy.enrich(g)
    assert g.owasp.startswith("A10:2021")
    assert g.owasp_api.startswith("API7:2023")


def test_taxonomy_keyword_fallback_without_cwe():
    f = Finding("Weak TLS cipher", "medium", "testssl", "t")
    taxonomy.enrich(f)
    assert f.owasp.startswith("A02:2021")


def test_risk_score_increases_with_corroboration():
    lone = Finding("X", "high", "a", "t", cwe="89")
    lone.corroboration = 1
    corr = Finding("X", "high", "a", "t", cwe="89")
    corr.corroboration = 3
    assert taxonomy.score(corr) > taxonomy.score(lone)


def test_consensus_upgrades_confidence():
    r = _mk(
        Finding("XSS", "high", "zap", "t", location="/x", cwe="79", confidence="medium"),
        Finding("XSS", "high", "dalfox", "t", location="/x", cwe="79", confidence="low"),
    )
    d = r.dedupe()
    correlate.consensus(d)
    assert d.findings[0].confidence == "high"
    assert d.findings[0].corroboration == 2


def test_clustering_collapses_noise():
    r = ScanResult()
    for i in range(10):
        r.add([Finding("Missing header", "info", "zap", "t",
                       location=f"/p{i}", cwe="16")])
    d = r.dedupe()
    correlate.cluster_noise(d, threshold=8)
    # 10 distinct locations -> but same title/cwe -> one clustered rep
    reps = [f for f in d.findings if f.instances > 1]
    assert len(reps) == 1
    assert reps[0].instances == 10
    # the count must NOT be baked into the title (keeps fingerprint stable so
    # baseline diff doesn't churn the whole cluster on every count change)
    assert "instances" not in reps[0].title.lower()


def test_cluster_fingerprint_stable_across_count_change():
    def cluster(n):
        r = ScanResult()
        for i in range(n):
            r.add([Finding("Missing header", "info", "zap", "t",
                           location="/same", cwe="16")])
        d = r.dedupe()
        correlate.cluster_noise(d, threshold=8)
        return d.findings[0]
    # same location, different counts -> identical fingerprint (no churn)
    assert cluster(8).fingerprint == cluster(12).fingerprint


def test_attack_chain_ssrf_to_imds():
    r = _mk(Finding("SSRF", "high", "nuclei", "shop", cwe="918",
                    location="https://shop/fetch?url=http://169.254.169.254/"))
    chains.synthesize(r)
    chain = [f for f in r.findings if f.is_chain]
    assert chain and "SSRF" in chain[0].title
    assert chain[0].severity == Severity.CRITICAL   # metadata IP => escalated


def test_attack_chain_k8s_takeover():
    r = _mk(
        Finding("Anonymous access to API server", "high", "kube-hunter", "c"),
        Finding("Kubelet read-only port 10255 exposed", "medium", "kube-hunter", "c"),
    )
    chains.synthesize(r)
    assert any(f.is_chain and "cluster takeover" in f.title for f in r.findings)


def test_attack_chain_jwt_admin():
    r = _mk(
        Finding("JWT accepts alg=none", "high", "jwt_tool", "api", cwe="347",
                location="/api/token"),
        Finding("Admin panel reachable", "medium", "nuclei", "api",
                location="/admin/users"),
    )
    chains.synthesize(r)
    chain = [f for f in r.findings if f.is_chain]
    assert chain and "authorization bypass" in chain[0].title
    assert chain[0].severity == Severity.CRITICAL


def test_attack_chain_smuggling_cache():
    r = _mk(
        Finding("HTTP request smuggling (CL.TE)", "high", "nuclei", "t",
                location="/", cwe="444"),
        Finding("Web cache poisoning via unkeyed header", "medium", "nuclei", "t",
                location="/"),
    )
    chains.synthesize(r)
    assert any(f.is_chain and "cache poisoning" in f.title for f in r.findings)


def test_attack_chain_cors_credentials():
    r = _mk(
        Finding("CORS reflects arbitrary Origin", "medium", "nuclei", "api",
                description="Access-Control-Allow-Origin reflected", cwe="942"),
        Finding("Authenticated API returns sensitive data", "medium", "zap", "api",
                description="bearer session data"),
    )
    chains.synthesize(r)
    assert any(f.is_chain and "cross-origin data theft" in f.title for f in r.findings)


def test_attack_chain_deserialization_rce():
    r = _mk(Finding("Insecure deserialization", "high", "nuclei", "t", cwe="502"))
    chains.synthesize(r)
    chain = [f for f in r.findings if f.is_chain]
    assert chain and chain[0].severity == Severity.CRITICAL


def test_attack_chain_lfi_upload_rce():
    r = _mk(
        Finding("Unrestricted file upload", "high", "wapiti", "t", cwe="434",
                location="/upload"),
        Finding("Path traversal", "high", "wapiti", "t", cwe="22",
                location="/download?f=../"),
    )
    chains.synthesize(r)
    assert any(f.is_chain and "remote code execution" in f.title for f in r.findings)


def test_chains_do_not_fire_without_both_conditions():
    # a lone admin endpoint (no JWT weakness) must NOT create the JWT chain
    r = _mk(Finding("Admin panel reachable", "low", "nuclei", "t", location="/admin"))
    chains.synthesize(r)
    assert not any(f.is_chain for f in r.findings)


def test_full_pipeline_orders_by_risk_and_labels():
    r = _mk(
        Finding("SQL Injection", "high", "nuclei", "shop", cwe="89", location="/x?id=1"),
        Finding("SQL Injection", "critical", "sqlmap", "shop", cwe="89", location="/x?id=1"),
        Finding("Verbose database error", "medium", "zap", "shop", cwe="209", location="/x"),
    )
    res = analyze(r.dedupe())
    # a chain (SQLi + verbose errors) should exist and rank at/near the top
    assert any(f.is_chain for f in res.findings)
    assert res.findings[0].risk_score >= res.findings[-1].risk_score
    # corroborated SQLi has both engines recorded
    sqli = [f for f in res.findings if f.title == "SQL Injection"][0]
    assert sqli.corroboration == 2


def test_baseline_diff(tmp_path):
    # first run -> save as baseline
    r1 = _mk(
        Finding("SQLi", "high", "nuclei", "t", cwe="89", location="/a"),
        Finding("XSS", "medium", "zap", "t", cwe="79", location="/b"),
    )
    from yubel.reporters import write_reports
    d1 = analyze(r1.dedupe())
    write_reports(d1, str(tmp_path), ["json"], sarif=False)
    baseline = str(tmp_path / "yubel.json")

    # second run: XSS fixed, SQLi remains, new SSRF appears
    r2 = _mk(
        Finding("SQLi", "high", "nuclei", "t", cwe="89", location="/a"),
        Finding("SSRF", "high", "nuclei", "t", cwe="918", location="/c"),
    )
    d2 = analyze(r2.dedupe(), baseline_path=baseline)
    diff = d2.diff_counts()
    statuses = {f.title: f.status for f in d2.findings}
    assert statuses["SQLi"] == "existing"
    assert statuses["SSRF"] == "new"
    assert diff["fixed"] >= 1            # XSS disappeared
    assert any(f.title == "XSS" for f in d2.fixed)


def test_systemic_correlation_across_targets():
    r = _mk(
        Finding("Reflected XSS", "high", "dalfox", "svc-a", cwe="79", location="/a"),
        Finding("Reflected XSS", "high", "nuclei", "svc-b", cwe="79", location="/b"),
    )
    res = analyze(r.dedupe())
    sysf = [f for f in res.findings if f.is_systemic]
    assert sysf and "across 2 targets" in sysf[0].title
    assert set(sysf[0].affected_targets) == {"svc-a", "svc-b"}


def test_systemic_needs_two_distinct_targets():
    r = _mk(
        Finding("Reflected XSS", "high", "dalfox", "svc-a", cwe="79", location="/a"),
        Finding("Reflected XSS", "high", "nuclei", "svc-a", cwe="79", location="/b"),
    )
    res = analyze(r.dedupe())
    assert not any(f.is_systemic for f in res.findings)


def test_rationale_is_deterministic_and_explains():
    r = _mk(
        Finding("SQLi", "critical", "sqlmap", "t", cwe="89", location="/x"),
        Finding("SQLi", "high", "nuclei", "t", cwe="89", location="/x"),
    )
    res = analyze(r.dedupe())
    f = [x for x in res.findings if x.title == "SQLi"][0]
    assert "Corroborated by 2" in f.rationale
    assert "CWE-89" in f.rationale and "risk" in f.rationale
    # deterministic: re-running yields the identical rationale
    r2 = _mk(
        Finding("SQLi", "critical", "sqlmap", "t", cwe="89", location="/x"),
        Finding("SQLi", "high", "nuclei", "t", cwe="89", location="/x"),
    )
    f2 = [x for x in analyze(r2.dedupe()).findings if x.title == "SQLi"][0]
    assert f.rationale == f2.rationale


def test_new_chain_rules():
    r = _mk(
        Finding("IDOR on /orders", "high", "nuclei", "api", cwe="639"),
        Finding("Sensitive data returned in response", "medium", "zap", "api",
                description="PII sensitive data"),
    )
    r2 = _mk(
        Finding("Default credentials admin:admin", "high", "nuclei", "t", cwe="798"),
        Finding("Admin panel reachable", "medium", "nuclei", "t", location="/admin"),
    )
    from yubel.analysis import chains
    chains.synthesize(r)
    chains.synthesize(r2)
    assert any(f.is_chain and "IDOR" in f.title or "object authorization" in f.title
               for f in r.findings)
    assert any(f.is_chain and "full compromise" in f.title for f in r2.findings)


def test_json_report_carries_enrichment(tmp_path):
    from yubel.reporters import write_reports
    r = _mk(Finding("SQL Injection", "high", "nuclei", "t", cwe="89", location="/x"))
    d = analyze(r.dedupe())
    write_reports(d, str(tmp_path), ["json"], sarif=False)
    data = json.load(open(tmp_path / "yubel.json"))
    f0 = data["findings"][0]
    assert "owasp" in f0 and "risk_score" in f0 and "mitre" in f0
    assert "diff" in data
