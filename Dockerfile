# Yubel — batteries-included image.
# Bundles the orchestrator plus the core OSS engines so `yubel scan` works
# out of the box on any container/Kubernetes/CI runtime.
#
#   docker build -t yubel:local .
#   docker run --rm -v "$PWD/out:/out" yubel:local \
#       scan -t https://example.com -o /out
#
# ---------------------------------------------------------------------------
# Two rules this file learned the hard way, after the published image
# advertised thirteen engines and shipped eleven:
#
# 1. **Nothing installs "latest".** Every version is an ARG below. The ZAP step
#    used to request a pinned *filename* from GitHub's `releases/latest/`
#    path — `ZAP_2.16.1_Linux.tar.gz` — which 404s the moment upstream cuts
#    2.17.0. Pinning half of a URL is worse than pinning none of it, because it
#    looks pinned.
#
# 2. **Nothing is allowed to fail quietly.** That same step ran `curl -sSL`
#    (no `-f`, so curl exits 0 on a 404 and writes the error page to the file)
#    inside a chain ending in `|| true` (which swallows a failure of *any*
#    command in the chain, not just the last). Every RUN now starts with
#    `set -eux`, every download uses `curl -f`, and the build ends by asking
#    the image what it actually has — `yubel engines --check` fails the build
#    if a non-opt-in engine is missing.
# ---------------------------------------------------------------------------

# ---- pinned versions (bump deliberately; Dependabot can see these) ---------
ARG GO_VERSION=1.26
ARG PYTHON_VERSION=3.12
ARG NUCLEI_VERSION=v3.11.1
ARG HTTPX_VERSION=v1.10.0
ARG KATANA_VERSION=v1.7.0
ARG DALFOX_VERSION=v3.2.1
ARG ZAP_VERSION=2.17.0
ARG NIKTO_VERSION=2.6.1
ARG TESTSSL_VERSION=v3.2.4
ARG GRAPHQL_COP_VERSION=1.16

# ---- stage 1: Go-based ProjectDiscovery + XSS tooling ----------------------
# --platform=$BUILDPLATFORM keeps this stage on the *builder's* architecture
# and cross-compiles via GOARCH, instead of running the Go toolchain under
# QEMU emulation. On a multi-arch build that is the difference between minutes
# and most of an hour.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS gotools
ARG TARGETARCH
ARG NUCLEI_VERSION
ARG HTTPX_VERSION
ARG KATANA_VERSION
ARG DALFOX_VERSION
ENV GOBIN=/gobin CGO_ENABLED=0 GOTOOLCHAIN=auto GOOS=linux
RUN set -eux; \
    export GOARCH="${TARGETARCH}"; \
    mkdir -p /gobin; \
    go install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}"; \
    go install "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}"; \
    go install "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}"; \
    go install "github.com/hahwul/dalfox/v2@${DALFOX_VERSION}"; \
    ls -1 /gobin

# ---- stage 2: runtime ------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm

LABEL org.opencontainers.image.title="Yubel" \
      org.opencontainers.image.description="Cloud-native, multi-target DAST orchestrator" \
      org.opencontainers.image.source="https://github.com/ggeorgeazevedo/yubel" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PATH="/usr/local/bin:${PATH}"

# System engines available from apt / git
# NB: nikto was removed from Debian bookworm's archive, so it is NOT installed
# via apt here — it is fetched from upstream git below. The perl modules are
# nikto's runtime deps: it loads XML::Writer at startup and the yubel adapter
# runs it with `-Format json` (JSON) over HTTP/HTTPS (Net::SSLeay for TLS).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        git curl ca-certificates bsdmainutils dnsutils \
        wapiti sqlmap openjdk-17-jre-headless procps \
        perl libnet-ssleay-perl libxml-writer-perl libjson-perl; \
    rm -rf /var/lib/apt/lists/*

# nikto (not packaged in Debian bookworm) — install from upstream git
ARG NIKTO_VERSION
RUN set -eux; \
    git clone --depth 1 --branch "${NIKTO_VERSION}" \
        https://github.com/sullo/nikto.git /opt/nikto; \
    chmod +x /opt/nikto/program/nikto.pl; \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto; \
    nikto -Version

# testssl.sh (dynamic TLS assessment)
ARG TESTSSL_VERSION
RUN set -eux; \
    git clone --depth 1 --branch "${TESTSSL_VERSION}" \
        https://github.com/testssl/testssl.sh.git /opt/testssl; \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh; \
    testssl.sh --version

# ZAP (packaged automation scripts: zap-baseline.py / zap-full-scan.py / zap-api-scan.py)
# The version appears twice in the URL on purpose — tag and filename must agree,
# and hard-coding both is what makes a bad bump fail loudly instead of 404ing.
ARG ZAP_VERSION
RUN set -eux; \
    curl -fsSL --retry 3 --retry-delay 2 \
        "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
        -o /tmp/zap.tgz; \
    mkdir -p /opt/zap; \
    tar -xzf /tmp/zap.tgz -C /opt/zap --strip-components=1; \
    rm /tmp/zap.tgz; \
    ln -sf /opt/zap/zap.sh /usr/local/bin/zap.sh; \
    for s in zap-baseline.py zap-full-scan.py zap-api-scan.py; do \
        curl -fsSL --retry 3 \
            "https://raw.githubusercontent.com/zaproxy/zaproxy/v${ZAP_VERSION}/docker/$s" \
            -o "/usr/local/bin/$s"; \
        chmod +x "/usr/local/bin/$s"; \
    done; \
    test -x /usr/local/bin/zap-baseline.py

# graphql-cop — from upstream git, NOT from PyPI.
# `pip install graphql-cop` resolves to a 0.0.1 package whose own summary is
# "Reserved name placeholder. No functionality." It installs cleanly, provides
# no binary, and left the published image without the engine. Its deps are
# installed unpinned rather than from its requirements.txt, which pins
# requests==2.25.1 and would drag schemathesis down with it.
ARG GRAPHQL_COP_VERSION
RUN set -eux; \
    git clone --depth 1 --branch "${GRAPHQL_COP_VERSION}" \
        https://github.com/dolevf/graphql-cop.git /opt/graphql-cop; \
    chmod +x /opt/graphql-cop/graphql-cop.py; \
    ln -s /opt/graphql-cop/graphql-cop.py /usr/local/bin/graphql-cop; \
    pip install --no-cache-dir requests simplejson termcolor PySocks; \
    graphql-cop --version

# Python-based engines.
# NB: netifaces (a kube-hunter dependency) is a C extension with no prebuilt
# wheel for Python 3.12, so it must be compiled. build-essential is installed
# only for the build and purged in the same layer to keep the image slim.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends build-essential; \
    pip install --no-cache-dir schemathesis graphw00f kube-hunter; \
    apt-get purge -y build-essential; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

# Go binaries from stage 1
COPY --from=gotools /gobin/nuclei /gobin/httpx /gobin/katana /gobin/dalfox /usr/local/bin/
RUN set -eux; nuclei -update-templates -silent; nuclei -version

# Yubel itself
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# The build asks the image what it actually shipped. This is the step whose
# absence let an image go out advertising thirteen engines with eleven in it.
RUN yubel engines --check

# Non-root by default; scans need no privileges except network egress.
RUN useradd -m -u 10001 yubel
USER yubel
WORKDIR /out

ENTRYPOINT ["yubel"]
CMD ["--help"]
