"""The tool must not be aimable at the infrastructure running it.

The case that motivates all of this:

    yubel scan -t http://169.254.169.254/latest/meta-data/iam/security-credentials/

169.254.169.254 is the cloud instance metadata service. It answers to whoever
is running the scan, and it answers with credentials. Nuclei runs with `-irr`,
so request and response are attached to every finding, and `redact.py`
deliberately does not mask a secret found *on the target* — masking it would
destroy the finding. Each of those is right on its own. Together, with no
target validation, the role credential lands whole in `yubel.json`.
"""
import pytest

from yubel.config import Config
from yubel.models import Target, TargetType
from yubel.netguard import host_of, internal_reason
from yubel.orchestrator import Orchestrator
from yubel.models import EngineRun, Finding, ScanResult
from yubel.severity import Severity


# --------------------------------------------------------------------------
# host_of: four shapes, because `Target.endpoint()` returns a raw string
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("http://169.254.169.254/latest/meta-data/", "169.254.169.254"),
    ("https://Example.COM/path?a=b", "example.com"),   # scheme + case + query
    ("10.0.0.5:8443", "10.0.0.5"),                     # host:port, no scheme
    ("10.0.0.5", "10.0.0.5"),                          # bare host
    ("[::1]:8080", "::1"),                             # bracketed IPv6 + port
    ("http://[fd00::1]/x", "fd00::1"),                 # bracketed IPv6 in a URL
    ("", ""),
    (None, ""),
])
def test_host_of_handles_every_shape_the_model_can_produce(value, expected):
    assert host_of(value) == expected


def test_host_of_survives_garbage():
    """`endpoint()` is a free-text field; a parse error must not be a crash."""
    for junk in ("http://[oops", "http://x:notaport", "://", "   "):
        assert isinstance(host_of(junk), str)


# --------------------------------------------------------------------------
# What is refused
# --------------------------------------------------------------------------

@pytest.mark.parametrize("endpoint", [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.170.2/v2/credentials",        # ECS task role endpoint
    "http://100.100.100.200/latest/meta-data/",   # Alibaba, inside CGNAT
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://localhost:8080/",
    "http://127.0.0.1/",
    "https://10.1.2.3/admin",
    "https://172.16.5.4",
    "https://192.168.0.10:8443/x",
    "http://[::1]/",
    "http://[fe80::1]/",
    "http://[fd00:ec2::254]/",                    # EC2 IMDS over IPv6
    "0.0.0.0:9000",
])
def test_refused(endpoint):
    assert internal_reason(endpoint), f"{endpoint} should be refused"


@pytest.mark.parametrize("endpoint", [
    "https://example.com/app",
    "https://8.8.8.8",
    "https://staging.internal.example.com",   # a *name*, not resolved
    "https://93.184.216.34/",                 # an ordinary public address
    "",
])
def test_allowed(endpoint):
    assert internal_reason(endpoint) is None, f"{endpoint} should be allowed"


def test_the_backstop_catches_ranges_the_list_does_not_enumerate():
    """`is_private` runs after the explicit CIDRs, and catches the rest of
    what is not globally routable — documentation and benchmarking ranges.
    Refusing them costs nothing: there is no real service to DAST there."""
    assert internal_reason("192.0.2.10")      # TEST-NET-1
    assert internal_reason("198.18.0.1")      # benchmarking


def test_a_name_is_never_resolved():
    """Deliberate, and the honest half of this feature.

    Resolving would make `validate()` do network I/O in a tool whose core
    never phones home, would leak the target list to a resolver before the
    operator agreed to anything, and would not hold anyway — DNS answers
    change between the check and the request. So a name that points at
    10.0.0.1 passes, and the README says so.
    """
    assert internal_reason("http://this-resolves-to-localhost.example") is None


def test_the_reason_names_the_address():
    """"refused" with no reason sends the operator to the source to find out."""
    reason = internal_reason("http://169.254.169.254/")
    assert "169.254.169.254" in reason and "metadata" in reason.lower()


# --------------------------------------------------------------------------
# Config.validate()
# --------------------------------------------------------------------------

def _web(url):
    return Config(targets=[Target(type=TargetType.WEB, url=url)])


def test_validate_refuses_the_metadata_service():
    errors = _web("http://169.254.169.254/latest/meta-data/").validate()
    assert any("169.254.169.254" in e for e in errors)


def test_allow_internal_is_the_one_way_through():
    cfg = _web("http://10.0.0.5/")
    assert cfg.validate()
    cfg.allow_internal = True
    assert cfg.validate() == []


def test_the_openapi_spec_is_checked_too():
    """A second URL on the same target, fetched by ZAP and schemathesis.

    Checking only `endpoint()` would leave a target whose URL is public and
    whose spec is `http://169.254.169.254/...`.
    """
    cfg = Config(targets=[Target(type=TargetType.API, url="https://api.example.com",
                                 openapi="http://169.254.169.254/openapi.json")])
    assert any("openapi" in e for e in cfg.validate())


def test_the_schemathesis_base_url_is_checked_too():
    cfg = Config(targets=[Target(type=TargetType.API, url="https://api.example.com",
                                 openapi="https://api.example.com/openapi.json")],
                 options={"schemathesis": {"base_url": "http://127.0.0.1:8000"}})
    assert any("base_url" in e for e in cfg.validate())


def test_the_error_says_how_to_proceed():
    """An operator doing an authorized internal test must not have to read
    the source to find the way through."""
    errors = _web("http://10.0.0.5/").validate()
    assert any("--allow-internal" in e for e in errors)


# --------------------------------------------------------------------------
# The runtime half: the crawler walks past validate()
# --------------------------------------------------------------------------

def _crawled(urls):
    """A ScanResult shaped like one katana run that discovered `urls`."""
    result = ScanResult(version="test")
    result.runs.append(EngineRun(engine="katana", target="site", status="ok"))
    result.add([Finding(engine="katana", target="site", title="endpoints",
                        severity=Severity.INFO, raw={"endpoints": urls})])
    return result


def test_a_discovered_metadata_url_never_reaches_the_scanners():
    """`validate()` runs once, before anything executes, and sees only what
    the operator wrote. katana follows links and — with `-jc` — pulls routes
    out of JS bundles, so a link to the metadata service on the target's own
    pages arrives after the check and goes straight to nuclei and dalfox."""
    target = Target(type=TargetType.WEB, url="https://example.com", name="site")
    cfg = Config(targets=[target])
    result = _crawled(["https://example.com/a?x=1",
                       "http://169.254.169.254/latest/meta-data/"])

    Orchestrator(cfg)._seed_from_discovery(result)

    assert target.seed_urls == ["https://example.com/a?x=1"]


def test_the_refusal_is_recorded_not_just_dropped():
    """A scan that quietly ignored something must not be deducible only from
    a smaller number."""
    target = Target(type=TargetType.WEB, url="https://example.com", name="site")
    result = _crawled(["http://127.0.0.1:9000/", "https://example.com/a"])

    Orchestrator(Config(targets=[target]))._seed_from_discovery(result)

    run = next(r for r in result.runs if r.engine == "katana")
    assert "refused as internal" in run.message
    assert "127.0.0.1" in run.message


def test_allow_internal_reaches_the_crawler_seam_too():
    target = Target(type=TargetType.WEB, url="https://example.com", name="site")
    cfg = Config(targets=[target], allow_internal=True)
    result = _crawled(["http://10.0.0.9/admin"])

    Orchestrator(cfg)._seed_from_discovery(result)

    assert target.seed_urls == ["http://10.0.0.9/admin"]
