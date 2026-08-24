"""Refuse to point the scanners at the infrastructure running them.

Nothing stopped this:

    yubel scan -t http://169.254.169.254/latest/meta-data/iam/security-credentials/

That address is the cloud instance metadata service. It answers to whatever
is running the scan, and what it answers with is credentials. Two decisions
made elsewhere in this codebase are individually correct and combine badly
with it: nuclei runs with `-irr`, so the request and response are attached to
every finding — that is what makes a finding provable — and `redact.py`
deliberately does **not** mask a secret discovered *on the target*, because
masking it would destroy the finding. Together, with no target validation,
the role credential goes whole into `yubel.json` and into the HTML report.

So the check lives here, and it is deliberately narrow:

**No DNS.** A hostname is never resolved. Resolving would make `validate()`
do network I/O — in a tool whose selling point is that its core never phones
home — and it would leak the target list to a resolver before the operator
has agreed to anything. It also would not hold: DNS answers change between
the check and the request. The consequence is honest and stated in the
README: a name that resolves to 10.0.0.1 passes. This refuses what can be
refused by inspection, not everything reachable that is internal.

**A literal, not a heuristic.** Only an address the operator wrote as an IP,
or one of a handful of names that mean "the machine running this", is
refused. No guessing from a name's shape.

`--allow-internal` turns it off in one place, for the case this would
otherwise block: an authorized internal pentest.
"""
import ipaddress
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

#: Names that mean "the host running the scan" or "this cloud instance".
#: Kept to names that cannot mean anything else — no pattern matching on
#: `.internal` or `.local`, which are legitimate names for real targets.
INTERNAL_NAMES = {
    "localhost",
    "ip6-localhost",
    "metadata.google.internal",   # GCP IMDS
    "instance-data",              # EC2 IMDS alias
}

#: Explicit, rather than leaning on `ipaddress.is_private` alone: what that
#: property covers has moved between CPython releases (100.64.0.0/10 is
#: private on some, not on others), and this project's CI runs 3.9 through
#: 3.12. A containment rule that depends on the interpreter version is not a
#: containment rule. `is_private` still runs afterwards as a backstop.
_REFUSED: List[Tuple[str, str]] = [
    ("169.254.0.0/16", "link-local — the cloud instance metadata service lives here"),
    ("fe80::/10", "link-local"),
    ("127.0.0.0/8", "loopback — the machine running the scan"),
    ("::1/128", "loopback — the machine running the scan"),
    ("10.0.0.0/8", "private (RFC1918)"),
    ("172.16.0.0/12", "private (RFC1918)"),
    ("192.168.0.0/16", "private (RFC1918)"),
    ("fc00::/7", "private (unique local)"),
    ("100.64.0.0/10", "carrier-grade NAT — cluster pod ranges and the Alibaba "
                      "metadata service live here"),
    ("0.0.0.0/8", "unspecified"),
    ("::/128", "unspecified"),
]

_NETWORKS = [(ipaddress.ip_network(cidr), why) for cidr, why in _REFUSED]


def host_of(endpoint: str) -> str:
    """The host inside any shape `Target.endpoint()` can return.

    It returns a raw string that may be a full URL, `host:port`, a bare host,
    a bare IP, or empty — there is no parsing anywhere in the model. IPv6
    arrives bracketed from a URL and unbracketed from a bare host.
    """
    raw = (endpoint or "").strip()
    if not raw:
        return ""
    if "//" not in raw:
        raw = "//" + raw          # give urlsplit a netloc to find
    try:
        host = urlsplit(raw).hostname or ""
    except ValueError:            # malformed IPv6 literal, bad port
        return ""
    return host.strip("[]").lower()


def internal_reason(endpoint: str) -> Optional[str]:
    """Why this endpoint must not be scanned, or None if it may be.

    Returns a sentence naming the address, because "refused" without the
    reason sends the operator to the source to find out what happened.
    """
    host = host_of(endpoint)
    if not host:
        return None
    if host in INTERNAL_NAMES:
        return f"{host} names the machine running the scan"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None               # a name; see the module docstring on DNS
    for network, why in _NETWORKS:
        if ip.version == network.version and ip in network:
            return f"{ip} is {why}"
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return f"{ip} is not a globally routable address"
    return None
