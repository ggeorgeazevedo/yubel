"""Attack-chain synthesis.

A single scanner reports isolated issues. Yubel sees *all* engines' findings for
a target at once, so it can recognize when several of them combine into a real
attack path and promote that path to its own high-impact finding. Each rule is a
predicate over a target's findings that, when satisfied, emits one composite
`Finding` (is_chain=True) explaining the chain, its steps and its escalated
severity. This is the analysis other DAST tools structurally cannot do.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Callable, List, Optional

from ..models import Finding, ScanResult
from ..severity import Severity


def _has(findings, *, cwe=None, kw=None) -> Optional[Finding]:
    """Return the first finding matching a CWE or any keyword in title/desc."""
    for f in findings:
        if cwe and f.cwe and str(f.cwe) == str(cwe):
            return f
        if kw:
            hay = f"{f.title} {f.description} {f.location}".lower()
            if any(k in hay for k in kw):
                return f
    return None


def _chain(target: str, title: str, severity, steps: List[Finding],
           description: str, remediation: str = "", cwe: str = None) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        engine="yubel-correlator",
        target=target,
        description=description,
        location=steps[0].location if steps else target,
        evidence="\n".join(f"[{s.engine}] {s.title} → {s.location}" for s in steps),
        confidence="high",
        cwe=cwe,
        is_chain=True,
        chain_steps=[f"{s.title} ({s.engine})" for s in steps],
        remediation=remediation,
        references=["https://owasp.org/www-community/"],
    )


# ---- rules: each takes (target, findings) -> Optional[Finding] -------------

def _rule_ssrf_to_imds(target, fs):
    ssrf = _has(fs, cwe=918) or _has(fs, kw=["ssrf", "server-side request"])
    if not ssrf:
        return None
    meta = "169.254.169.254" in (ssrf.location + ssrf.evidence) or \
        "metadata" in (ssrf.description + ssrf.evidence).lower()
    sev = Severity.CRITICAL if meta else Severity.HIGH
    return _chain(
        target, "Attack chain: SSRF → cloud metadata (IMDS) credential theft",
        sev, [ssrf],
        "A server-side request forgery reaches internal network space. On a "
        "cloud host this typically lets an attacker read the instance metadata "
        "service (169.254.169.254) and steal temporary IAM/service credentials, "
        "pivoting from a web bug to cloud account access.",
        "Block outbound requests to link-local/metadata ranges, enforce IMDSv2, "
        "and allow-list egress destinations.", cwe="918")


def _rule_xss_session_hijack(target, fs):
    xss = _has(fs, cwe=79) or _has(fs, kw=["cross-site scripting", "xss"])
    cookie = _has(fs, kw=["httponly", "http-only", "cookie without"])
    if xss and cookie:
        return _chain(
            target, "Attack chain: XSS + non-HttpOnly session cookie → account takeover",
            Severity.HIGH, [xss, cookie],
            "Reflected/stored XSS combined with a session cookie that lacks the "
            "HttpOnly flag means injected script can read the cookie and exfiltrate "
            "the victim's session — a direct account-takeover path.",
            "Fix the XSS (contextual output encoding + CSP) and set HttpOnly, "
            "Secure and SameSite on session cookies.", cwe="79")
    return None


def _rule_open_redirect_auth(target, fs):
    redir = _has(fs, cwe=601) or _has(fs, kw=["open redirect"])
    auth = _has(fs, kw=["oauth", "oidc", "openid", "sso", "saml", "login"])
    if redir and auth:
        return _chain(
            target, "Attack chain: open redirect in auth flow → OAuth token theft",
            Severity.HIGH, [redir, auth],
            "An open redirect on a host that also exposes an OAuth/OIDC/SSO flow "
            "can be abused as the redirect_uri to leak authorization codes or "
            "tokens to an attacker-controlled destination.",
            "Strictly allow-list redirect targets and registered redirect_uris.", cwe="601")
    return None


def _rule_weak_tls_creds(target, fs):
    tls = _has(fs, kw=["tls", "cipher", "ssl", "hsts", "certificate"])
    auth = _has(fs, kw=["login", "password", "auth", "jwt", "token", "basic"])
    if tls and auth and tls.severity >= Severity.MEDIUM:
        return _chain(
            target, "Attack chain: weak transport + credential surface → interception",
            Severity.HIGH, [tls, auth],
            "Weak TLS configuration on an endpoint that also transmits credentials "
            "or tokens exposes those secrets to adversary-in-the-middle capture.",
            "Enforce TLS 1.2+/strong ciphers, HSTS preload and mTLS where possible.", cwe="319")
    return None


def _rule_k8s_takeover(target, fs):
    api = _has(fs, kw=["anonymous", "api server", "unauthenticated"])
    node = _has(fs, kw=["kubelet", "read-only port", "10255", "cAdvisor",
                        "etcd", "dashboard"])
    if api and node:
        return _chain(
            target, "Attack chain: exposed K8s API + node service → cluster takeover",
            Severity.CRITICAL, [api, node],
            "Anonymous/unauthenticated access to the Kubernetes API together with "
            "an exposed node service (kubelet/etcd/dashboard) provides a realistic "
            "path to enumerate secrets, schedule pods and escalate to full cluster "
            "and host control.",
            "Disable anonymous-auth, lock down kubelet (10250/10255), restrict etcd "
            "and the dashboard, and apply least-privilege RBAC + NetworkPolicies.", cwe="284")
    return None


def _rule_sqli_data_exfil(target, fs):
    sqli = _has(fs, cwe=89) or _has(fs, kw=["sql injection", "sqli"])
    leak = _has(fs, kw=["verbose", "stack trace", "database error", "disclosure",
                        "debug"])
    if sqli and leak:
        return _chain(
            target, "Attack chain: SQL injection + verbose errors → data exfiltration",
            Severity.CRITICAL, [sqli, leak],
            "An injectable parameter alongside verbose database/error output lets "
            "an attacker iterate injection payloads efficiently and extract data "
            "(or achieve RCE via stacked queries).",
            "Use parameterized queries, disable detailed error output in production, "
            "and apply least-privilege DB accounts.", cwe="89")
    return None


def _rule_jwt_admin(target, fs):
    jwt = _has(fs, cwe=347) or _has(fs, kw=[
        "alg=none", "alg none", "jwt", "json web token", "signature not verified",
        "weak jwt", "key confusion"])
    admin = _has(fs, kw=[
        "/admin", " admin ", "admin panel", "privileged endpoint", "actuator",
        "management endpoint", "/manage", "internal api"])
    if jwt and admin:
        return _chain(
            target, "Attack chain: forgeable JWT + admin endpoint → authorization bypass",
            Severity.CRITICAL, [jwt, admin],
            "A JWT weakness (accepting alg=none, an unverified signature, or a "
            "weak/guessable key) lets an attacker mint arbitrary tokens. Combined "
            "with a reachable admin/privileged endpoint, this yields a direct "
            "authentication/authorization bypass into high-privilege functionality.",
            "Reject 'none' and unexpected algorithms, verify signatures with a "
            "strong secret/rotated keys, and enforce authorization server-side on "
            "every privileged route.", cwe="347")
    return None


def _rule_smuggling_cache(target, fs):
    smuggle = _has(fs, cwe=444) or _has(fs, kw=[
        "request smuggling", "desync", "cl.te", "te.cl", "h2c smuggling",
        "http/1.1 desync"])
    cache = _has(fs, kw=[
        "cache poisoning", "web cache", "cache deception", "cacheable",
        "unkeyed input", "x-cache"])
    if smuggle and cache:
        return _chain(
            target, "Attack chain: HTTP request smuggling + web cache poisoning → mass user compromise",
            Severity.CRITICAL, [smuggle, cache],
            "A front-end/back-end desync (request smuggling) that reaches a "
            "cacheable response lets an attacker poison the shared cache, serving "
            "malicious or hijacked responses to every subsequent user of the "
            "endpoint — turning a single request into a broad, persistent compromise.",
            "Normalize/agree on Content-Length vs Transfer-Encoding across the "
            "proxy chain, disable connection reuse where ambiguous, and exclude "
            "unkeyed inputs from the cache key.", cwe="444")
    return None


def _rule_cors_creds(target, fs):
    cors = _has(fs, kw=[
        "cors", "access-control-allow-origin", "cross-origin resource sharing",
        "acao wildcard", "reflected origin"])
    creds = _has(fs, kw=[
        "credential", "allow-credentials", "authenticated", "api key",
        "bearer", "session", "sensitive"])
    if cors and creds:
        return _chain(
            target, "Attack chain: permissive CORS + credentialed API → cross-origin data theft",
            Severity.HIGH, [cors, creds],
            "A CORS policy that reflects arbitrary origins while allowing "
            "credentials lets any attacker-controlled site read authenticated "
            "responses on behalf of a logged-in victim, exfiltrating their data "
            "cross-origin.",
            "Never reflect the Origin with Access-Control-Allow-Credentials:true; "
            "use a strict allow-list of trusted origins.", cwe="942")
    return None


def _rule_deserialization_rce(target, fs):
    deser = _has(fs, cwe=502) or _has(fs, kw=[
        "insecure deserialization", "deserialization", "ysoserial",
        "object injection", "pickle", "marshal"])
    if deser:
        return _chain(
            target, "Attack chain: insecure deserialization → remote code execution",
            Severity.CRITICAL, [deser],
            "Untrusted data flowing into a native deserializer is one of the most "
            "reliable paths to remote code execution: crafted gadget chains execute "
            "on the server during object reconstruction.",
            "Never deserialize untrusted input; use data-only formats (JSON) with "
            "strict schemas, or signed/whitelisted types.", cwe="502")
    return None


def _rule_lfi_upload_rce(target, fs):
    lfi = _has(fs, cwe=22) or _has(fs, kw=[
        "path traversal", "directory traversal", "local file inclusion", "lfi",
        "file inclusion"])
    upload = _has(fs, cwe=434) or _has(fs, kw=[
        "file upload", "unrestricted upload", "arbitrary file write"])
    if lfi and upload:
        return _chain(
            target, "Attack chain: file upload + path traversal → remote code execution",
            Severity.CRITICAL, [lfi, upload],
            "An unrestricted upload combined with a path-traversal/inclusion primitive "
            "lets an attacker place an executable payload inside the web root (or "
            "include an uploaded file) and execute it — a classic upload-to-RCE path.",
            "Validate file type/extension server-side, store uploads outside the web "
            "root with generated names, and canonicalize/deny traversal sequences.",
            cwe="434")
    return None


def _rule_idor_data_exposure(target, fs):
    idor = _has(fs, cwe=639) or _has(fs, cwe=284) or _has(fs, cwe=285) or \
        _has(fs, kw=["idor", "bola", "object level authorization",
                     "insecure direct object"])
    data = _has(fs, kw=["sensitive data", "pii", "personal data",
                        "sensitive information", "data exposure", "enumerat"])
    if idor and data:
        return _chain(
            target, "Attack chain: broken object authorization (IDOR/BOLA) + data exposure → bulk record theft",
            Severity.HIGH, [idor, data],
            "A missing object-level authorization check combined with an endpoint "
            "that returns sensitive data lets an attacker iterate identifiers and "
            "harvest other users' records at scale (the #1 API risk, OWASP API1).",
            "Enforce per-object authorization server-side on every request; never "
            "rely on unguessable IDs alone.", cwe="639")
    return None


def _rule_default_creds_admin(target, fs):
    creds = _has(fs, cwe=798) or _has(fs, cwe=1392) or \
        _has(fs, kw=["default credential", "default password", "weak password",
                     "hardcoded credential", "admin:admin"])
    admin = _has(fs, kw=["/admin", "admin panel", "dashboard", "management",
                         "console", "actuator"])
    if creds and admin:
        return _chain(
            target, "Attack chain: default/weak credentials + exposed admin → full compromise",
            Severity.CRITICAL, [creds, admin],
            "Default or weak credentials on a reachable admin/management interface "
            "give an attacker administrative control of the application without "
            "any exploit — often the fastest path to full compromise.",
            "Force credential rotation on first use, remove defaults, restrict "
            "admin interfaces by network/IP and require MFA.", cwe="798")
    return None


RULES: List[Callable] = [
    _rule_ssrf_to_imds, _rule_xss_session_hijack, _rule_open_redirect_auth,
    _rule_weak_tls_creds, _rule_k8s_takeover, _rule_sqli_data_exfil,
    _rule_jwt_admin, _rule_smuggling_cache, _rule_cors_creds,
    _rule_deserialization_rce, _rule_lfi_upload_rce,
    _rule_idor_data_exposure, _rule_default_creds_admin,
]


def synthesize(result: ScanResult) -> None:
    """Run every chain rule per target and append the composite findings."""
    by_target = defaultdict(list)
    for f in result.findings:
        by_target[f.target].append(f)

    new: List[Finding] = []
    seen_fps = {f.fingerprint for f in result.findings}
    for target, fs in by_target.items():
        for rule in RULES:
            try:
                chained = rule(target, fs)
            except Exception:
                chained = None
            if chained and chained.fingerprint not in seen_fps:
                seen_fps.add(chained.fingerprint)
                new.append(chained)
    result.findings.extend(new)
