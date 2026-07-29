"""Yubel - The cloud-native, multi-target DAST orchestrator.

Yubel does not reinvent scanning engines. It orchestrates the best
open-source dynamic security engines (ZAP, Nuclei, Nikto, Wapiti, testssl.sh,
sqlmap, dalfox, katana, schemathesis, kube-hunter, ...) behind a single
config, normalizes their findings into one model, and runs anywhere:
a laptop, a Docker container, a Kubernetes Job, or a CI pipeline.
"""

__version__ = "0.5.7"
__all__ = ["__version__"]
