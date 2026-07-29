#!/usr/bin/env python3
"""Generate the DAST landscape reference (CSV + Markdown) from the curated
catalog. This is the research corpus that informs which engines Yubel wraps
and which alternatives exist. Run: python scripts/gen_landscape.py
"""
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

from dast_data import C, COLS  # noqa: E402

OUT_DATA = os.path.join(HERE, "..", "data")
OUT_DOCS = os.path.join(HERE, "..", "docs")
os.makedirs(OUT_DATA, exist_ok=True)
os.makedirs(OUT_DOCS, exist_ok=True)


def write_csv():
    path = os.path.join(OUT_DATA, "dast-landscape.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(COLS)
        for row in C:
            w.writerow(row)
    return path, len(C)


def write_markdown():
    path = os.path.join(OUT_DOCS, "LANDSCAPE.md")
    # group by "Classe" (col index 3)
    groups = {}
    for row in C:
        groups.setdefault(row[3], []).append(row)
    lines = ["# DAST & Dynamic Security Testing Landscape",
             "",
             f"A curated catalog of **{len(C)} tools** that perform some form of "
             "dynamic security testing — commercial, open source, research, "
             "abandoned and experimental. It is the research corpus behind "
             "Yubel's engine selection; Yubel wraps the strongest OSS "
             "engines here and this list documents the wider ecosystem.",
             "",
             "> Status legend: **Ativo** = actively maintained · **Manutencao** = "
             "maintenance only · **Novo/Beta** = new/experimental · "
             "**Abandonado/Descontinuado/Arquivado** = not maintained. "
             "Columns S/N/P = Yes/No/Partial. Verify before adopting.",
             ""]
    for cls in sorted(groups):
        lines.append(f"## {cls}")
        lines.append("")
        lines.append("| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |")
        lines.append("|---|---|---|:--:|---|---|:--:|:--:|:--:|---|")
        for r in groups[cls]:
            name, vendor, cat, _cls, oss, lic, _entrega, web, api, ck8s, *_rest = r
            link = r[15]
            lines.append(f"| {name} | {vendor} | {cat} | {oss} | {lic} | {r[13]} | "
                         f"{web} | {api} | {ck8s} | [link]({link}) |")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


if __name__ == "__main__":
    csv_path, n = write_csv()
    md_path = write_markdown()
    print(f"wrote {csv_path} ({n} rows)")
    print(f"wrote {md_path}")
