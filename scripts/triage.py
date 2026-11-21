#!/usr/bin/env python3
"""triage.py — turn nmap XML into a reviewable service table.

usage:
  triage.py scan.xml                 # markdown table to stdout
  triage.py scan.xml --csv out.csv
  triage.py scan.xml -o notes.md

Only open ports are emitted. Handles multiple -oX files.
"""
import argparse
import csv
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HEADERS = ["host", "hostname", "port", "proto", "service", "product", "version", "extra"]


def parse(path):
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        print(f"skip {path}: {exc}", file=sys.stderr)
        return []

    rows = []
    for host in root.findall("host"):
        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")

        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            rows.append({
                "host": addr,
                "hostname": hostname,
                "port": port.get("portid", ""),
                "proto": port.get("protocol", ""),
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "extra": svc.get("extrainfo", "") if svc is not None else "",
            })
    return rows


def render_markdown(rows):
    if not rows:
        return "_no open ports found_\n"
    out = ["| host | hostname | port | proto | service | product | version |",
           "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in sorted(rows, key=lambda x: (x["host"], int(x["port"] or 0))):
        out.append(
            f"| {r['host']} | {r['hostname']} | {r['port']} | {r['proto']} | "
            f"{r['service']} | {r['product']} | {r['version']} {r['extra']} |".rstrip()
        )
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("-o", "--out")
    ap.add_argument("--csv")
    args = ap.parse_args()

    rows = []
    for f in args.files:
        rows.extend(parse(f))

    md = render_markdown(rows)
    if args.out:
        Path(args.out).write_text(md)
        print(f"wrote {args.out} ({len(rows)} open ports)")
    else:
        print(md, end="")

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=HEADERS)
            w.writeheader()
            w.writerows(rows)
        print(f"wrote {args.csv}")


if __name__ == "__main__":
    main()
