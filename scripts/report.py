#!/usr/bin/env python3
"""report.py — render findings.yaml into report.md, findings.csv and SARIF.

usage:
  report.py findings.yaml
  report.py findings.yaml --outdir report/
  report.py findings.yaml --format md,csv,sarif

Requires PyYAML. No other dependencies.
"""
import argparse
import csv
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "none"}
SEV_LABEL = {k: k.capitalize() for k in SEV_ORDER}


def load(path):
    data = yaml.safe_load(Path(path).read_text())
    findings = data.get("findings", [])
    findings.sort(key=lambda f: SEV_ORDER.get(f.get("severity", "info"), 9))
    return data, findings


def render_md(data, findings):
    eng = data.get("engagement", {})
    counts = {k: 0 for k in SEV_ORDER}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

    L = []
    L.append(f"# Penetration Test Report — {eng.get('client', '')}\n")
    L.append(f"**Engagement:** {eng.get('name', '')}  ")
    L.append(f"**Target:** {eng.get('target', '')}  ")
    L.append(f"**Period:** {eng.get('start', '')} → {eng.get('end', '')}  ")
    L.append(f"**Classification:** {eng.get('classification', 'Confidential')}\n")

    L.append("## Severity summary\n")
    L.append("| Severity | Count |")
    L.append("| --- | --- |")
    for sev in SEV_ORDER:
        L.append(f"| {SEV_LABEL[sev]} | {counts.get(sev, 0)} |")
    L.append("")

    L.append("## Findings\n")
    for f in findings:
        sev = f.get("severity", "info")
        L.append(f"### {f.get('id', 'F-??')} — {f.get('title', '')}\n")
        L.append(f"**Severity:** {SEV_LABEL.get(sev, sev)}  ")
        L.append(f"**CVSS 3.1:** {f.get('cvss', '')} — `{f.get('vector', '')}`  ")
        L.append(f"**Asset:** {f.get('asset', '')}  ")
        L.append(f"**Component:** {f.get('component', '')}  ")
        L.append(f"**Status:** {f.get('status', 'open')}\n")

        if f.get("attack"):
            L.append(f"**ATT&CK:** {', '.join(f['attack'])}\n")
        if f.get("summary"):
            L.append("**Summary**\n")
            L.append(f"{f['summary'].strip()}\n")
        if f.get("preconditions"):
            L.append("**Preconditions**\n")
            L.extend(f"- {p}" for p in f["preconditions"])
            L.append("")
        if f.get("steps"):
            L.append("**Steps to reproduce**\n")
            for i, s in enumerate(f["steps"], 1):
                L.append(f"{i}. {s}")
            L.append("")
        if f.get("impact"):
            L.append("**Impact**\n")
            L.append(f"{f['impact'].strip()}\n")
        if f.get("chain"):
            L.append("**Chain**\n")
            L.append(f"{f['chain'].strip()}\n")
        if f.get("remediation"):
            L.append("**Remediation**\n")
            L.append(f"{f['remediation'].strip()}\n")
        if f.get("evidence"):
            L.append("**Evidence**\n")
            L.extend(f"- `{e}`" for e in f["evidence"])
            L.append("")
        if f.get("references"):
            L.append("**References**\n")
            L.extend(f"- {r}" for r in f["references"])
            L.append("")
    return "\n".join(L)


def render_csv(findings):
    cols = ["id", "title", "severity", "cvss", "vector", "asset", "component",
            "status", "impact", "remediation"]
    rows = []
    for f in findings:
        rows.append({c: (f.get(c, "") or "").strip() if isinstance(f.get(c, ""), str)
                     else f.get(c, "") for c in cols})
    return cols, rows


def render_sarif(data, findings):
    rules, results = [], []
    for f in findings:
        fid = f.get("id", "F-??")
        rules.append({
            "id": fid,
            "name": f.get("title", fid),
            "shortDescription": {"text": f.get("title", fid)},
            "help": {"text": (f.get("remediation") or "").strip()},
            "properties": {"severity": f.get("severity"),
                           "cvss": f.get("cvss"),
                           "vector": f.get("vector")},
        })
        results.append({
            "ruleId": fid,
            "level": SARIF_LEVEL.get(f.get("severity", "info"), "note"),
            "message": {"text": (f.get("summary") or f.get("title", "")).strip()},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("asset", "")},
                }
            }],
            "properties": {"severity": f.get("severity"), "cvss": f.get("cvss")},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "offsec-report",
                "informationUri": "https://github.com/",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("yaml_file")
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--format", default="md,csv,sarif")
    args = ap.parse_args()

    data, findings = load(args.yaml_file)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    formats = {f.strip() for f in args.format.split(",")}

    if "md" in formats:
        (outdir / "report.md").write_text(render_md(data, findings))
        print(f"wrote {outdir/'report.md'}")
    if "csv" in formats:
        cols, rows = render_csv(findings)
        with open(outdir / "findings.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
        print(f"wrote {outdir/'findings.csv'}")
    if "sarif" in formats:
        (outdir / "report.sarif").write_text(json.dumps(render_sarif(data, findings), indent=2))
        print(f"wrote {outdir/'report.sarif'}")

    print(f"{len(findings)} findings rendered")


if __name__ == "__main__":
    main()
