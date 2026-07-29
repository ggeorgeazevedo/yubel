"""Report writers. Each takes a (deduped) ScanResult and writes one artifact."""
from __future__ import annotations

import os
from typing import List

from ..models import ScanResult
from .json_reporter import write_json
from .markdown_reporter import write_markdown
from .html_reporter import write_html
from .sarif_reporter import write_sarif

WRITERS = {
    "json": ("yubel.json", write_json),
    "markdown": ("yubel.md", write_markdown),
    "md": ("yubel.md", write_markdown),
    "html": ("yubel.html", write_html),
    "sarif": ("yubel.sarif", write_sarif),
}


def write_reports(result: ScanResult, out_dir: str, formats: List[str],
                  sarif: bool = True) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    written: List[str] = []
    wanted = list(formats)
    if sarif and "sarif" not in wanted:
        wanted.append("sarif")
    seen_files = set()
    for fmt in wanted:
        entry = WRITERS.get(fmt.lower())
        if not entry:
            continue
        filename, writer = entry
        if filename in seen_files:
            continue
        seen_files.add(filename)
        path = os.path.join(out_dir, filename)
        writer(result, path)
        written.append(path)
    return written
