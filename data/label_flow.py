#!/usr/bin/env python3
"""
label_flow.py

Label CICFlowMeter v3/v4 CSV flows according to roles defined in roles.json.

Rules:
- benign  : (src in normals and dst in idc_subnets) or (dst in normals and src in idc_subnets)
- attack  : (src in bots and dst in idc_subnets) or (src in idc_subnets and dst in bots)
- spoofed : (src not in normals/bots/idc_subnets) and (dst in idc_subnets)
- unknown : everything else
"""

import argparse
import pandas as pd
import ipaddress
import json
import logging
import re
import os
from collections import Counter
from functools import lru_cache

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){2})\.(\d{1,3})-(\d{1,3})$")
V4_PREFIX_RE = re.compile(r"^(?:\d{1,3}\.){1,3}$")  # e.g. "10.", "10.0.", "10.0.10."

SRC_IP_CANDS = ["src_ip", "Src IP", "SrcIP", "source_ip", "Source IP"]
DST_IP_CANDS = ["dst_ip", "Dst IP", "DstIP", "dest_ip", "Destination IP"]

# global variable to hold roles
ROLES = {}


def find_column(df: pd.DataFrame, candidates):
    for c in candidates:
        if c in df.columns:
            return c
    lower_map = {c.lower(): c for c in df.columns}
    for c in candidates:
        if c.lower() in lower_map:
            return lower_map[c.lower()]
    raise KeyError(f"None of {candidates} found in columns: {list(df.columns)}")


def _prefix_to_networks(prefix: str):
    """Convert dotted prefix like '10.0.10.' to a network."""
    p = prefix.strip()
    if not V4_PREFIX_RE.match(p):
        return []
    octets = [o for o in p.split(".") if o != ""]
    mask = 8 * len(octets)
    base = octets + ["0"] * (4 - len(octets))
    try:
        return [ipaddress.ip_network(".".join(base) + f"/{mask}", strict=False)]
    except Exception:
        return []


def load_roles_from_json(path: str):
    with open(path, "r") as f:
        j = json.load(f)

    roles = {}
    for role_name, entries in j.items():
        nets = []
        for ent in entries:
            ent = str(ent).strip()
            if ent.endswith("."):
                nets += _prefix_to_networks(ent)
                continue
            m = RANGE_RE.match(ent)
            if m:
                base3, start, end = m.group(1), int(m.group(2)), int(m.group(3))
                for i in range(start, end + 1):
                    nets.append(ipaddress.ip_network(f"{base3}.{i}/32", strict=False))
                continue
            try:
                if "/" in ent:
                    nets.append(ipaddress.ip_network(ent, strict=False))
                else:
                    ipobj = ipaddress.ip_address(ent)
                    cidr = "32" if ipobj.version == 4 else "128"
                    nets.append(ipaddress.ip_network(f"{ent}/{cidr}", strict=False))
            except Exception as e:
                logging.warning(f"Invalid role entry {ent}: {e}")
        roles[role_name.lower()] = nets
    return roles


@lru_cache(maxsize=100000)
def ip_in_any(ip_str: str, role_name: str) -> bool:
    """Check if ip_str is in any network of given role_name, using global ROLES."""
    nets = ROLES.get(role_name, [])
    if not ip_str or not nets:
        return False
    try:
        ipobj = ipaddress.ip_address(ip_str.strip())
    except Exception:
        return False
    return any(ipobj in net for net in nets)


def classify(src_ip: str, dst_ip: str) -> str:
    s_norm = ip_in_any(src_ip, "normals")
    d_norm = ip_in_any(dst_ip, "normals")
    s_bot = ip_in_any(src_ip, "bots")
    d_bot = ip_in_any(dst_ip, "bots")
    s_idc = ip_in_any(src_ip, "idc_subnets")
    d_idc = ip_in_any(dst_ip, "idc_subnets")

    if (s_norm and d_idc) or (d_norm and s_idc):
        return "benign"
    if (s_bot and d_idc) or (s_idc and d_bot):
        return "attack"
    if not (s_norm or s_bot or s_idc) and d_idc:
        return "spoofed"
    return "unknown"


def main():
    global ROLES
    parser = argparse.ArgumentParser(description="Label CICFlowMeter flows with roles from roles.json")
    parser.add_argument("-i", "--input", required=True, help="Input CSV file")
    parser.add_argument("-o", "--output", help="Output CSV file (default: <input>_label.csv)")
    parser.add_argument("--roles-json", default="roles.json", help="Roles JSON file")
    args = parser.parse_args()

    # Default output name
    output_file = args.output or f"{os.path.splitext(args.input)[0]}_label{os.path.splitext(args.input)[1]}"

    # Load roles
    ROLES = load_roles_from_json(args.roles_json)
    logging.info(f"Loaded roles: { {k: len(v) for k,v in ROLES.items()} }")

    # Read CSV
    df = pd.read_csv(args.input, low_memory=False)

    # Find IP columns
    src_col = find_column(df, SRC_IP_CANDS)
    dst_col = find_column(df, DST_IP_CANDS)

    # Apply classification
    df["label"] = df.apply(lambda r: classify(str(r[src_col]), str(r[dst_col])), axis=1)

    # Save
    df.to_csv(output_file, index=False)
    logging.info(f"Saved labeled CSV to {output_file}")

    # Show distribution
    counts = Counter(df["label"])
    logging.info("Label distribution:")
    for label, cnt in counts.items():
        logging.info(f"  {label}: {cnt}")


if __name__ == "__main__":
    main()