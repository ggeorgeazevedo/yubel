"""How to install each engine, used by `yubel setup`.

Yubel never bundles engine binaries (size, per-OS builds, GPL redistribution).
Instead `yubel setup` detects what's missing and installs it with the right
package manager — so the whole fleet is one command, without pip-vendoring.
"""
from __future__ import annotations

import shutil
import sys
from typing import List, Optional, Tuple

# Per engine: the package name for each install method. `yubel setup` picks the
# best method available on the machine (brew → pip → go), else prints a note.
INSTALL = {
    "nuclei":       {"brew": "nuclei",  "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    "httpx":        {"brew": "httpx",   "go": "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "katana":       {"brew": "katana",  "go": "github.com/projectdiscovery/katana/cmd/katana@latest"},
    # Homebrew ships dalfox 3.x (the Rust rewrite); the Go module path only
    # ever resolves to the 2.x line, because v3 tags carry no go.mod. Both work
    # — the adapter detects the major and picks the subcommand — but they are
    # different programs, so which one you get depends on which installer ran.
    "dalfox":       {"brew": "dalfox",  "go": "github.com/hahwul/dalfox/v2@latest"},
    "nikto":        {"brew": "nikto"},
    "sqlmap":       {"brew": "sqlmap",  "pip": "sqlmap"},
    "testssl":      {"brew": "testssl"},
    "wapiti":       {"pip": "wapiti3"},
    "schemathesis": {"pip": "schemathesis"},
    "graphw00f":    {"pip": "graphw00f"},
    "graphql-cop":  {"pip": "graphql-cop"},
    "kube-hunter":  {"pip": "kube-hunter"},
    "zap":          {"manual": "ZAP is easiest via the Yubel Docker image "
                               "(bundles ZAP + its automation scripts). Local "
                               "install: get ZAP and put zap-baseline.py on PATH."},
}


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def plan_for(name: str) -> Optional[Tuple[str, List[str], str]]:
    """Return (method, argv, label) to install `name`, or None if unknown.

    Prefers brew (macOS/Linuxbrew), then pip (into the current interpreter/venv),
    then go. `manual` engines return a method of 'manual' with an empty argv.
    """
    spec = INSTALL.get(name)
    if not spec:
        return None
    if "brew" in spec and have("brew"):
        return "brew", ["brew", "install", spec["brew"]], f"brew install {spec['brew']}"
    if "pip" in spec:
        pkg = spec["pip"]
        return "pip", [sys.executable, "-m", "pip", "install", pkg], f"pip install {pkg}"
    if "go" in spec and have("go"):
        return "go", ["go", "install", spec["go"]], f"go install {spec['go']}"
    if "manual" in spec:
        return "manual", [], spec["manual"]
    # brew listed but brew absent, and no pip/go fallback
    if "brew" in spec:
        return "manual", [], f"install '{spec['brew']}' (Homebrew not found — see https://brew.sh)"
    return "manual", [], "no known installer"
