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
ARG DALFOX_VERSION=v2.13.0   # last Go release; v3+ is a Rust rewrite, see below
ARG ZAP_VERSION=2.17.0
ARG NIKTO_VERSION=2.6.1
ARG TESTSSL_VERSION=v3.2.4
ARG GRAPHQL_COP_VERSION=1.16
# schemathesis 4.x is a different CLI: `--hypothesis-max-examples` became
# `-n`, `--base-url` became `-u`, and `--report json` no longer exists.
# The adapter speaks 3.x and reports itself unavailable on 4.x, so the
# image pins the line it can actually drive.
ARG SCHEMATHESIS_VERSION=3.39.16
ARG GRAPHW00F_VERSION=0.0.1
ARG KUBE_HUNTER_VERSION=0.6.8

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

# A git tag is not a Go module version, and this is where that bites.
# dalfox v3.0.0 is a complete rewrite in Rust: those tags carry no `go.mod` at
# all, so `go install github.com/hahwul/dalfox/v2@v3.2.1` resolves to
# `github.com/hahwul/dalfox@v3.2.1+incompatible` and fails with "does not
# contain package .../v2". v2.13.0 is the last Go release and is exactly what
# the old `@latest` on the `/v2` module path was already resolving to — so the
# image's dalfox is unchanged by pinning, and pinning is what makes that
# visible. Moving to v3 means a Rust toolchain in this image *and* re-verifying
# the adapter against v3's CLI (subcommands consolidated under `scan`,
# `--concurrence` renamed to `--workers`, `-C/--cookie` to `--cookies`), so it
# is deliberately a separate change.

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
    pip install --no-cache-dir 'requests==2.34.2' 'simplejson==4.1.1' \
        'termcolor==3.3.0' 'PySocks==1.7.1'; \
    graphql-cop --version

# Python-based engines.
# NB: netifaces (a kube-hunter dependency) is a C extension with no prebuilt
# wheel for Python 3.12, so it must be compiled. build-essential is installed
# only for the build and purged in the same layer to keep the image slim.
ARG SCHEMATHESIS_VERSION
ARG GRAPHW00F_VERSION
ARG KUBE_HUNTER_VERSION
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends build-essential; \
    pip install --no-cache-dir \
        "schemathesis==${SCHEMATHESIS_VERSION}" \
        "graphw00f==${GRAPHW00F_VERSION}" \
        "kube-hunter==${KUBE_HUNTER_VERSION}"; \
    apt-get purge -y build-essential; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

# Go binaries from stage 1
COPY --from=gotools /gobin/nuclei /gobin/httpx /gobin/katana /gobin/dalfox /usr/local/bin/

# nuclei templates, in a path the runtime user can actually read.
#
# This step used to be a bare `nuclei -update-templates` placed *before*
# `useradd`, so the templates landed in root's home. The runtime process is uid
# 10001 with HOME=/home/yubel and never found them, so it re-downloaded them at
# scan time — inside the user's network, which is the thing baking them in was
# meant to avoid — and on the documented Kubernetes Job, where
# `readOnlyRootFilesystem: true` and only /out and /tmp are writable, that
# download fails outright. The image paid the size for templates nothing used.
#
# NUCLEI_TEMPLATES_DIR is read by nuclei itself (cmd/nuclei/main.go), so it
# points both this build step and every later run at the same place.
# NUCLEI_CONFIG_DIR has to stay *writable*: nuclei writes
# `.templates-config.json` on startup — before `-duc` is even consulted — and
# /tmp is the one path the k8s Job already backs with an emptyDir.
#
# The final `rm -rf` matters. This step runs as root, so the config nuclei
# writes here is root-owned, and the runtime user cannot rewrite it — the
# build's own uid-10001 check caught exactly that. The config directory is
# per-run state, not image content (on Kubernetes an emptyDir shadows /tmp
# regardless), so it is removed and each run recreates it under its own uid.
# /tmp being 1777 is what makes that work for an arbitrary user.
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates \
    NUCLEI_CONFIG_DIR=/tmp/nuclei-config
RUN set -eux; \
    nuclei -update-templates -silent; \
    chmod -R a+rX /opt/nuclei-templates; \
    count=$(find /opt/nuclei-templates -name '*.yaml' | wc -l); \
    echo "nuclei templates: ${count}"; \
    [ "${count}" -gt 100 ]; \
    nuclei -version; \
    rm -rf /tmp/nuclei-config

# Yubel itself
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# The build asks the image what it actually shipped. This is the step whose
# absence let an image go out advertising thirteen engines with eleven in it.
RUN yubel engines --check

# ...and again as the runtime user, because "root can read it" is not the
# question. This is exactly what the old build got wrong.
RUN set -eux; \
    useradd -m -u 10001 yubel; \
    su yubel -s /bin/sh -c 'yubel engines --check'; \
    su yubel -s /bin/sh -c 'nuclei -duc -silent -tl > /tmp/tl.txt'; \
    test -s /tmp/tl.txt; \
    echo "nuclei sees $(wc -l < /tmp/tl.txt) templates as uid 10001"; \
    rm -rf /tmp/tl.txt /tmp/nuclei-config

# Non-root by default; scans need no privileges except network egress.
USER yubel
WORKDIR /out

ENTRYPOINT ["yubel"]
CMD ["--help"]
