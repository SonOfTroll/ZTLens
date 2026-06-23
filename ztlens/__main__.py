"""
entry point for running ztlens as a module
python -m ztlens --config <file>
"""

import argparse
import sys
import os

from ztlens.parser.ios_parser import ConfigParser
from ztlens.graph.reach_graph import ReachGraph
from ztlens.utils.helpers import print_banner, fmt_table, CLR_RED, CLR_GREEN, CLR_YELLOW, CLR_RESET, CLR_BOLD


def build_args():
    """set up argument parser"""
    parser = argparse.ArgumentParser(
        prog="ztlens",
        description="zero trust configuration auditor for cisco networks",
    )
    parser.add_argument(
        "--config", "-c",
        required=True,
        help="path to cisco ios running-config file",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="show detailed output",
    )
    # might add these later
    parser.add_argument(
        "--output", "-o",
        help="output file for report (not implemented yet)",
    )
    return parser


def print_vlan_table(vlans):
    """print parsed vlans as a table"""
    print(f"\n{CLR_BOLD}  VLANs Found:{CLR_RESET}\n")
    headers = ["ID", "Name", "Source"]
    rows = [[v["id"], v["name"], v["source"]] for v in vlans]
    print(fmt_table(headers, rows))


def print_interface_summary(interfaces):
    """print interface summary"""
    print(f"{CLR_BOLD}  Interfaces:{CLR_RESET}\n")

    # count by type
    type_counts = {}
    for iface in interfaces:
        t = iface["type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    headers = ["Name", "Type", "VLAN", "IP Address", "ACL In", "ACL Out"]
    rows = []
    for iface in interfaces:
        # skip boring ones
        if iface["type"] in ("loopback",) and not iface.get("ip_address"):
            continue

        vlan_str = str(iface.get("vlan", "-"))
        if iface["type"] == "trunk":
            native = iface.get("native_vlan", "?")
            allowed = iface.get("allowed_vlans", [])
            vlan_str = f"native:{native} allowed:{allowed}"

        rows.append([
            iface["name"],
            iface["type"],
            vlan_str,
            iface.get("ip_address", "-"),
            iface.get("acl_in", "-"),
            iface.get("acl_out", "-"),
        ])

    print(fmt_table(headers, rows))

    # show type summary
    print(f"  Types: ", end="")
    for t, count in sorted(type_counts.items()):
        print(f"{t}={count} ", end="")
    print("\n")


def print_acl_summary(acls):
    """print acl summary"""
    print(f"{CLR_BOLD}  ACLs:{CLR_RESET}\n")

    if not acls:
        print("  no acls found\n")
        return

    headers = ["#/Name", "Action", "Protocol", "Source", "Destination", "Type"]
    rows = []
    for acl in acls:
        identifier = str(acl.get("number", "")) or acl.get("name", "?")
        src = acl.get("src", "?")
        dst = acl.get("dst", "?")

        # add wildcard if its not any or host
        if acl.get("src_wildcard") and acl["src_wildcard"] != "0.0.0.0":
            src += f" {acl['src_wildcard']}"
        if acl.get("dst_wildcard") and acl["dst_wildcard"] != "0.0.0.0":
            dst += f" {acl['dst_wildcard']}"

        rows.append([
            identifier,
            acl.get("action", "?"),
            acl.get("protocol", "?"),
            src,
            dst,
            acl.get("type", "?"),
        ])

    print(fmt_table(headers, rows))


def print_reachability(graph):
    """print the reachability matrix"""
    print(f"{CLR_BOLD}  Reachability Matrix:{CLR_RESET}\n")

    matrix = graph.get_vlan_reach_matrix()

    if not matrix:
        print("  no reachability data\n")
        return

    for src, targets in sorted(matrix.items()):
        if not targets:
            print(f"  {src} -> (isolated)")
            continue

        for target in targets:
            dst = target["target"]
            via = target.get("via", "?")
            has_acl = target.get("has_acl", False)

            if has_acl:
                acl_str = f"{CLR_GREEN}[ACL]{CLR_RESET}"
            else:
                acl_str = f"{CLR_RED}[NO ACL]{CLR_RESET}"

            print(f"  {src} -> {dst}  via:{via}  {acl_str}")

    # print unrestricted paths warning
    unrestricted = graph.get_unrestricted_paths()
    if unrestricted:
        print(f"\n  {CLR_RED}{CLR_BOLD}⚠ {len(unrestricted)} unrestricted paths found!{CLR_RESET}")
        for path in unrestricted[:5]:
            print(f"  {CLR_RED}  {path['src']} -> {path['dst']} ({path['via']}){CLR_RESET}")
        if len(unrestricted) > 5:
            print(f"  {CLR_YELLOW}  ... and {len(unrestricted) - 5} more{CLR_RESET}")

    print()


def print_graph_stats(graph):
    """print quick stats about the graph"""
    stats = graph.get_graph_stats()
    print(f"{CLR_BOLD}  Graph Stats:{CLR_RESET}\n")
    print(f"  total vlans:          {stats['total_vlans']}")
    print(f"  total paths:          {stats['total_paths']}")
    print(f"  paths with acl:       {CLR_GREEN}{stats['paths_with_acl']}{CLR_RESET}")
    print(f"  paths without acl:    {CLR_RED}{stats['paths_without_acl']}{CLR_RESET}")
    print(f"  unrestricted paths:   {CLR_RED}{stats['unrestricted_count']}{CLR_RESET}")
    print()


def main():
    parser = build_args()
    args = parser.parse_args()

    # check if config file exists
    if not os.path.isfile(args.config):
        print(f"error: config file not found: {args.config}")
        sys.exit(1)

    print_banner()

    print(f"  analyzing: {args.config}\n")
    print(f"  {'-' * 50}\n")

    # parse the config
    cfg_parser = ConfigParser()
    try:
        parsed = cfg_parser.parse(args.config)
    except Exception as e:
        print(f"error parsing config: {e}")
        sys.exit(1)

    print(f"  hostname: {parsed['hostname']}\n")

    # show parsed data
    print_vlan_table(parsed["vlans"])
    print_interface_summary(parsed["interfaces"])
    print_acl_summary(parsed["acls"])

    # build and show the reachability graph
    rg = ReachGraph()
    rg.build_graph(parsed)

    print_graph_stats(rg)
    print_reachability(rg)

    # port security summary
    if parsed.get("port_security"):
        ps_enabled = sum(1 for ps in parsed["port_security"] if ps["enabled"])
        ps_total = len(parsed["port_security"])
        print(f"  port security: {ps_enabled}/{ps_total} access ports secured")
        if ps_enabled < ps_total:
            unsecured = [ps["interface"] for ps in parsed["port_security"] if not ps["enabled"]]
            print(f"  {CLR_YELLOW}unsecured ports: {', '.join(unsecured)}{CLR_RESET}")
        print()

    if args.verbose:
        # dump raw sections for debugging
        print(f"\n{CLR_BOLD}  Raw Sections:{CLR_RESET}\n")
        for section, blocks in cfg_parser.sections.items():
            print(f"  [{section}] - {len(blocks)} blocks")

    print(f"  {'-' * 50}")
    print(f"  done - phase 2 will add zero trust findings engine\n")


if __name__ == "__main__":
    main()
