#!/usr/bin/env python3
"""
label_flow.py

Label CICFlowMeter v3/v4 CSV flows according to roles defined in roles.json.

Rules:
- Source IP in "normals" -> benign
- Source IP in "bots"    -> attack
- Other source IPs       -> spoofed

Usage:
    python label_flow.py -i flow.csv -o flow_label.csv
    (if -o is not provided, will write flow_label.csv in same directory as input)
"""

import argparse
import pandas as pd
import ipaddress
import json
import logging
import re
import os
from collections import Counter

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

RANGE_RE = re.compile(r"^(.+)\.(\d{1,3})-(\d{1,3})$")


def load_roles_from_json(path: str):
    with open(path, "r") as f:
        j = json.load(f)

    roles = {}
    for role_name, entries in j.items():
        nets, prefixes = [], []
        for ent in entries:
            ent = str(ent).strip()
            if ent.endswith("."):
                prefixes.append(ent)
                continue
            m = RANGE_RE.match(ent)
            if m:
                base, start, end = m.group(1), int(m.group(2)), int(m.group(3))
                for i in range(start, end + 1):
                    nets.append(ipaddress.ip_network(f"{base}.{i}/32", strict=False))
                continue
            try:
                if "/" in ent:
                    nets.append(ipaddress.ip_network(ent, strict=False))
                else:
                    ipobj = ipaddress.ip_address(ent)
                    nets.append(
                        ipaddress.ip_network(
                            f"{ent}/{'32' if ipobj.version == 4 else '128'}",
                            strict=False,
                        )
                    )
            except Exception as e:
                logging.warning(f"Invalid role entry {ent}: {e}")
        roles[role_name.lower()] = {"networks": nets, "prefixes": prefixes}
    return roles


def ip_matches(ip_str: str, role_def: dict) -> bool:
    if not ip_str:
        return False
    for pref in role_def.get("prefixes", []):
        if ip_str.startswith(pref):
            return True
    try:
        ipobj = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    for net in role_def.get("networks", []):
        if ipobj in net:
            return True
    return False


def assign_label(src: str, roles: dict) -> str:
    if "normals" in roles and ip_matches(src, roles["normals"]):
        return "benign"
    if "bots" in roles and ip_matches(src, roles["bots"]):
        return "attack"
    if "idc_subnets" in roles and ip_matches(src, roles["idc_subnets"]):
        return "spoofed"
    return "spoofed"


def main():
    parser = argparse.ArgumentParser(description="Label CICFlowMeter flows with roles from roles.json")
    parser.add_argument("-i", "--input", required=True, help="Input CSV file")
    parser.add_argument("-o", "--output", help="Output CSV file (default: <input>_label.csv in same dir)")
    parser.add_argument("--roles-json", default="roles.json", help="Roles JSON file (default: roles.json)")
    args = parser.parse_args()

    # Default output name
    if args.output:
        output_file = args.output
    else:
        base, ext = os.path.splitext(args.input)
        output_file = f"{base}_label{ext}"

    # Load roles
    roles = load_roles_from_json(args.roles_json)
    logging.info(f"Loaded roles: {list(roles.keys())}")

    # Read input CSV
    df = pd.read_csv(args.input, low_memory=False)

    # Auto-detect column name for source IP
    src_col = None
    for cand in ["src_ip", "Src IP", "source_ip"]:
        if cand in df.columns:
            src_col = cand
            break
    if not src_col:
        raise KeyError("No source IP column found (expected one of: src_ip, Src IP, source_ip)")

    # Apply labeling
    df["label"] = df[src_col].astype(str).apply(lambda ip: assign_label(ip.strip(), roles))

    # Save result
    df.to_csv(output_file, index=False)
    logging.info(f"Saved labeled CSV to {output_file}")

    # Show distribution
    counts = Counter(df["label"])
    logging.info("Label distribution:")
    for label, cnt in counts.items():
        logging.info(f"  {label}: {cnt}")


if __name__ == "__main__":
    main()