"""Deterministic remediation knowledge base.

Every finding should tell the reader not just *what* and *where*, but *how to
fix it*. This module fills a finding's `remediation` field with concrete,
actionable guidance — keyed by CWE first (the identifier almost every engine
emits), then by OWASP category, then by keywords. It is fully deterministic: no
model, no network. Engine-supplied remediation is always preferred and never
overwritten.
"""
from __future__ import annotations

from typing import Dict, Optional

from ..models import Finding

# ---- remediation by CWE id (the precise layer) ----------------------------
_BY_CWE: Dict[int, str] = {
    79: ("Contextually output-encode all user input (HTML/attribute/JS/URL). "
         "Prefer a framework auto-escaping template engine; set a strict "
         "Content-Security-Policy; flag cookies HttpOnly. Never build HTML by "
         "string concatenation."),
    80: ("Encode user input on output and validate against an allow-list. Add a "
         "restrictive Content-Security-Policy as defense in depth."),
    89: ("Use parameterized queries / prepared statements (or a vetted ORM) for "
         "every query. Never concatenate input into SQL. Apply least-privilege "
         "DB accounts and validate input types."),
    91: ("Use a hardened XML parser with external-entity and DTD processing "
         "disabled; validate/allow-list input."),
    94: ("Never pass untrusted input to eval/exec/dynamic includes. Use safe "
         "APIs and strict allow-lists; sandbox where unavoidable."),
    78: ("Avoid shell calls with user input. Use language-native APIs with "
         "argument arrays (no shell string). Allow-list and escape arguments."),
    22: ("Canonicalize and validate file paths against an allow-list; reject "
         "`..` and absolute paths. Serve files from a fixed base directory."),
    98: ("Disable remote file includes; validate include paths against an "
         "allow-list; never build include targets from user input."),
    918: ("Validate and allow-list outbound URLs/hosts; block link-local and "
          "cloud-metadata ranges (169.254.169.254, ::1, internal CIDRs). Use a "
          "dedicated egress proxy and disable unused URL schemes/redirects."),
    601: ("Do not build redirect targets from user input. Use an allow-list of "
          "permitted destinations or server-side mapping keys."),
    352: ("Enforce anti-CSRF tokens on state-changing requests and set cookies "
          "SameSite=Lax/Strict. Prefer same-origin checks for sensitive actions."),
    611: ("Disable DTDs and external entity resolution in the XML parser "
          "(XXE-safe configuration)."),
    319: ("Enforce HTTPS everywhere with HSTS; redirect HTTP→HTTPS; never send "
          "credentials or tokens over cleartext."),
    326: ("Use strong, current algorithms and key sizes (e.g. AES-GCM, RSA≥2048/"
          "ECDSA P-256, SHA-256+). Retire weak ciphers and enable Forward Secrecy."),
    327: ("Replace broken/legacy crypto (MD5, SHA-1, DES, RC4) with vetted "
          "modern primitives; disable obsolete TLS versions and cipher suites."),
    295: ("Enforce full certificate validation (chain, hostname, expiry). Never "
          "disable verification; pin or use a managed trust store."),
    200: ("Remove sensitive data from responses/errors; return generic error "
          "messages; disable stack traces and verbose banners in production."),
    209: ("Return generic error messages to clients; log details server-side "
          "only. Disable debug/verbose error output in production."),
    16: ("Harden configuration: remove default files/accounts, disable unused "
         "features, add security headers (CSP, X-Content-Type-Options, HSTS)."),
    1004: ("Set the `HttpOnly` flag on session cookies so they are not readable "
           "from JavaScript; also set `Secure` and an appropriate `SameSite`."),
    614: ("Set the `Secure` flag on all cookies so they are only sent over HTTPS."),
    693: ("Add the missing security headers (Content-Security-Policy, "
          "X-Frame-Options/frame-ancestors, X-Content-Type-Options, HSTS)."),
    287: ("Enforce strong authentication: rate-limit and lock out brute force, "
          "require MFA for sensitive access, and use vetted session management."),
    307: ("Add rate limiting and account lockout/back-off on authentication "
          "endpoints; monitor and alert on credential-stuffing patterns."),
    798: ("Remove hard-coded credentials/keys from code and config; load secrets "
          "from a secret manager; rotate any exposed secret immediately."),
    862: ("Enforce server-side authorization on every object and action "
          "(deny by default); never rely on client-side checks or hidden IDs."),
    639: ("Enforce object-level authorization: verify the authenticated user is "
          "allowed to access the requested ID on every request (stops IDOR/BOLA)."),
    502: ("Do not deserialize untrusted data; use safe formats (JSON) with strict "
          "schemas; if unavoidable, sign payloads and use type allow-lists."),
    400: ("Enforce rate limiting, request-size and pagination limits, and "
          "timeouts to prevent resource-exhaustion / DoS."),
}

# ---- fallback by OWASP 2021 category prefix (the broad layer) -------------
_BY_OWASP: Dict[str, str] = {
    "A01": ("Enforce authorization server-side on every request (deny by "
            "default); validate object ownership; never trust client-side checks."),
    "A02": ("Protect data in transit and at rest with strong, current crypto; "
            "enforce HTTPS + HSTS; retire weak algorithms and enable Forward Secrecy."),
    "A03": ("Treat all input as untrusted: parameterize queries, context-encode "
            "output, and validate against allow-lists. Avoid dynamic eval/shell."),
    "A04": ("Address the design flaw: add the missing security control (rate "
            "limits, threat modeling, secure defaults) rather than patching one path."),
    "A05": ("Harden the configuration: remove defaults, disable unused features, "
            "add security headers, and suppress verbose errors in production."),
    "A06": ("Update or replace the vulnerable/outdated component; track "
            "dependencies with SCA and patch promptly."),
    "A07": ("Strengthen authentication and session management: MFA, brute-force "
            "protection, secure cookies, and no hard-coded secrets."),
    "A08": ("Verify integrity of code/data: sign and validate updates and "
            "serialized data; pin dependencies; use trusted sources only."),
    "A09": ("Add sufficient logging, monitoring and alerting for security events "
            "without recording sensitive data."),
    "A10": ("Validate and allow-list outbound requests; block internal/metadata "
            "ranges; disable unused URL schemes and redirects (SSRF defense)."),
}

_GENERIC = ("Review the finding against secure-coding guidance for its category, "
            "apply input validation / output encoding / secure configuration as "
            "appropriate, and re-test.")


def _cwe_int(f: Finding) -> Optional[int]:
    if not f.cwe:
        return None
    digits = "".join(ch for ch in str(f.cwe) if ch.isdigit())
    return int(digits) if digits else None


def remediate(f: Finding) -> None:
    """Fill `f.remediation` with concrete guidance if the engine didn't provide
    any. CWE-precise first, then OWASP category, then a safe generic. Idempotent."""
    if f.remediation and f.remediation.strip():
        return  # engine-supplied guidance wins
    cwe = _cwe_int(f)
    if cwe is not None and cwe in _BY_CWE:
        f.remediation = _BY_CWE[cwe]
        return
    if f.owasp:
        by_cat = _BY_OWASP.get(f.owasp[:3])
        if by_cat:
            f.remediation = by_cat
            return
    f.remediation = _GENERIC
