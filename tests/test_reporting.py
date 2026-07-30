"""Tests for the reporting upgrade: remediation KB, the confirmed/needs-review
tier, and evidence rendering. No network, no binaries."""
import os

from yubel.models import Finding, ScanResult, Target, TargetType
from yubel.analysis import analyze
from yubel.analysis.remediation import remediate
from yubel.reporters.html_reporter import write_html
from yubel.reporters.markdown_reporter import write_markdown


# ---- remediation knowledge base ---------------------------------------------

def test_remediation_by_cwe():
    f = Finding("SQL injection", "high", "nuclei", "t", cwe="89")
    remediate(f)
    assert "parameterized" in f.remediation.lower()


def test_remediation_engine_supplied_wins():
    f = Finding("x", "high", "nuclei", "t", cwe="89", remediation="already here")
    remediate(f)
    assert f.remediation == "already here"


def test_remediation_owasp_category_fallback():
    f = Finding("odd", "medium", "e", "t")
    f.owasp = "A05:2021 Security Misconfiguration"
    remediate(f)
    assert f.remediation and "harden" in f.remediation.lower()


def test_remediation_generic_last_resort():
    f = Finding("mystery", "low", "e", "t")
    remediate(f)
    assert f.remediation  # never empty


# ---- confirmed / needs-review tier ------------------------------------------

def _analyze_one(f):
    r = ScanResult()
    r.add([f])
    d = r.dedupe()
    analyze(d)
    return d.findings[0]


def test_verified_when_payload_has_proof():
    f = _analyze_one(Finding("XSS (reflected)", "high", "dalfox", "http://t",
                             location="http://t/?q=1", cwe="79", param="q",
                             payload="<script>alert(1)</script>", evidence="reflected",
                             confidence="high"))
    assert f.verified is True
    assert f.remediation  # KB filled it


def test_verified_when_corroborated():
    r = ScanResult()
    r.add([Finding("XSS", "high", "nuclei", "http://t", location="/x", cwe="79"),
           Finding("XSS", "high", "dalfox", "http://t", location="/x", cwe="79")])
    d = r.dedupe()
    analyze(d)
    assert d.findings[0].verified is True          # 2 engines => confirmed


def test_testssl_is_confirmed_observation():
    f = _analyze_one(Finding("TLS: weak cipher", "medium", "testssl", "http://t"))
    assert f.verified is True


def test_single_heuristic_needs_review():
    f = _analyze_one(Finding("Interesting header", "low", "nuclei", "http://t",
                             location="http://t", confidence="medium"))
    assert f.verified is False


# ---- reports render the proof + remediation + confirmed badge ---------------

def _sample_result():
    r = ScanResult()
    r.add([Finding("XSS (reflected)", "high", "dalfox", "http://t",
                   location="http://t/search?q=1", cwe="79", param="q",
                   payload="<script>alert(1)</script>", evidence="reflected in body",
                   request="GET /search?q=<script> HTTP/1.1\nHost: t",
                   response="HTTP/1.1 200 OK\n...<script>alert(1)</script>...",
                   confidence="high")])
    d = r.dedupe()
    analyze(d)
    return d


def test_html_report_has_proof_and_confirmed(tmp_path):
    d = _sample_result()
    p = str(tmp_path / "r.html")
    write_html(d, p)
    doc = open(p, encoding="utf-8").read()
    assert "confirmed" in doc.lower()
    assert "Proof" in doc
    assert "parameter" in doc.lower() and "payload" in doc.lower()
    assert "Remediation" in doc
    assert "encode" in doc.lower()          # CWE-79 (XSS) remediation text


def test_markdown_report_has_proof_and_remediation(tmp_path):
    d = _sample_result()
    p = str(tmp_path / "r.md")
    write_markdown(d, p)
    doc = open(p, encoding="utf-8").read()
    assert "confirmed" in doc.lower()
    assert "**Parameter:**" in doc
    assert "**Request (proof):**" in doc
    assert "**Remediation:**" in doc
