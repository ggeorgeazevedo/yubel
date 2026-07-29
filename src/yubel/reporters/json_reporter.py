from __future__ import annotations

import json

from ..models import ScanResult


def write_json(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)
