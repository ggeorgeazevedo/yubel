# Yubel — batteries-included image.
# Bundles the orchestrator plus the core OSS engines so `yubel scan` works
# out of the box on any container/Kubernetes/CI runtime.
#
#   docker build -t yubel:local .
#   docker run --rm -v "$PWD/out:/out" yubel:local \
#       scan -t https://example.com -o /out
#
# Multi-stage: grab prebuilt Go binaries, then assemble a slim runtime.

# ---- stage 1: Go-based ProjectDiscovery + XSS tooling ----------------------
FROM golang:1.26-bookworm AS gotools
ENV GOBIN=/gobin CGO_ENABLED=0
RUN mkdir -p /gobin && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/hahwul/dalfox/v2@latest

# ---- stage 2: runtime ------------------------------------------------------
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="Yubel" \
      org.opencontainers.image.description="Cloud-native, multi-target DAST orchestrator" \
      org.opencontainers.image.source="https://github.com/ggeorgeazevedo/yubel" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PATH="/usr/local/bin:${PATH}"

# System engines available from apt / git
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates bsdmainutils dnsutils \
        nikto wapiti sqlmap openjdk-17-jre-headless procps \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh (dynamic TLS assessment)
RUN git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# ZAP (packaged automation scripts: zap-baseline.py / zap-full-scan.py / zap-api-scan.py)
RUN curl -sSL https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_2.16.1_Linux.tar.gz \
        -o /tmp/zap.tgz 2>/dev/null && \
    mkdir -p /opt/zap && tar -xzf /tmp/zap.tgz -C /opt/zap --strip-components=1 && \
    rm /tmp/zap.tgz && \
    ln -sf /opt/zap/zap.sh /usr/local/bin/zap.sh && \
    for s in zap-baseline.py zap-full-scan.py zap-api-scan.py; do \
        curl -sSL "https://raw.githubusercontent.com/zaproxy/zaproxy/main/docker/$s" \
        -o "/usr/local/bin/$s" && chmod +x "/usr/local/bin/$s"; done || true

# Python-based engines
RUN pip install --no-cache-dir \
        schemathesis graphw00f graphql-cop kube-hunter

# Go binaries from stage 1
COPY --from=gotools /gobin/nuclei /gobin/httpx /gobin/katana /gobin/dalfox /usr/local/bin/
RUN nuclei -update-templates -silent || true

# Yubel itself
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Non-root by default; scans need no privileges except network egress.
RUN useradd -m -u 10001 yubel
USER yubel
WORKDIR /out

ENTRYPOINT ["yubel"]
CMD ["--help"]
