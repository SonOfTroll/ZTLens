"""
reachability graph engine

takes parsed cisco config data and builds a networkx directed graph
showing which vlans/subnets can talk to which and through what path

this is what the findings engine and visualizer will consume
"""

import networkx as nx
from typing import Optional


# sensitivity tags for common vlan names
# used to flag high value targets in the graph
SENSITIVE_TAGS = {
    "finance": "critical",
    "hr": "critical",
    "payroll": "critical",
    "executive": "critical",
    "management": "high",
    "server": "high",
    "dmz": "medium",
    "guest": "untrusted",
    "iot": "untrusted",
}

# not using this yet but might be useful for scoring
_max_score = 100


class ReachGraph:
    """builds and queries a network reachability graph

    nodes are vlans/subnets
    edges are traffic paths between them
    each edge has attributes about what acls gate the traffic
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.vlan_map = {}      # vlan_id -> node data
        self.iface_map = {}     # interface_name -> interface data
        self._parsed = None

    def build_graph(self, parsed_config: dict) -> nx.DiGraph:
        """build the reachability graph from parsed config data

        this is the main method - takes the output of ConfigParser.parse()
        and creates the full graph
        """
        self._parsed = parsed_config
        vlans = parsed_config.get("vlans", [])
        interfaces = parsed_config.get("interfaces", [])
        acls = parsed_config.get("acls", [])

        # step 1 - add vlan nodes
        self._add_vlan_nodes(vlans)

        # step 2 - figure out which vlans are connected via routing
        self._add_routing_edges(interfaces, acls)

        # step 3 - check trunk links for direct vlan connectivity
        self._add_trunk_edges(interfaces)

        return self.graph

    def _add_vlan_nodes(self, vlans: list):
        """add each vlan as a node in the graph"""
        for vlan in vlans:
            vid = vlan["id"]
            name = vlan.get("name", f"VLAN{vid}")

            # figure out sensitivity based on name
            sensitivity = "low"
            for keyword, tag in SENSITIVE_TAGS.items():
                if keyword in name.lower():
                    sensitivity = tag
                    break

            # try to find the subnet for this vlan from interfaces
            subnet = self._find_subnet_for_vlan(vid)

            self.graph.add_node(
                f"VLAN{vid}",
                vlan_id=vid,
                name=name,
                sensitivity=sensitivity,
                subnet=subnet,
                label=f"{name} (VLAN {vid})",
            )

            self.vlan_map[vid] = {
                "name": name,
                "sensitivity": sensitivity,
                "subnet": subnet,
            }

    def _find_subnet_for_vlan(self, vlan_id: int) -> str:
        """look through interfaces to find the subnet for a vlan"""
        if not self._parsed:
            return "unknown"

        for iface in self._parsed.get("interfaces", []):
            # check subinterfaces with encapsulation
            if iface.get("encapsulation") == vlan_id and iface.get("ip_address"):
                return f"{iface['ip_address']}/{iface['subnet_mask']}"

            # check svi interfaces (interface Vlan10)
            if iface.get("type") == "svi" and iface.get("name") == f"Vlan{vlan_id}":
                if iface.get("ip_address"):
                    return f"{iface['ip_address']}/{iface['subnet_mask']}"

            # check access ports - they dont have IPs usually
            if iface.get("vlan") == vlan_id and iface.get("ip_address"):
                return f"{iface['ip_address']}/{iface['subnet_mask']}"

        return "unknown"

    def _add_routing_edges(self, interfaces: list, acls: list):
        """add edges between vlans that are connected via routing

        looks at subinterfaces (router on a stick) and svi interfaces
        to figure out which vlans can route to each other
        """
        # collect all routed vlans (ones that have a gateway interface)
        routed_vlans = []
        for iface in interfaces:
            vlan_id = None

            if iface.get("type") == "subinterface" and iface.get("encapsulation"):
                vlan_id = iface["encapsulation"]
            elif iface.get("type") == "svi":
                # extract vlan id from interface name like "Vlan10"
                name = iface.get("name", "")
                if name.startswith("Vlan"):
                    try:
                        vlan_id = int(name[4:])
                    except ValueError:
                        pass

            if vlan_id is not None:
                routed_vlans.append({
                    "vlan_id": vlan_id,
                    "interface": iface["name"],
                    "acl_in": iface.get("acl_in"),
                    "acl_out": iface.get("acl_out"),
                    "ip": iface.get("ip_address"),
                })

        # every routed vlan can potentially reach every other routed vlan
        # unless theres an acl blocking it
        for src in routed_vlans:
            for dst in routed_vlans:
                if src["vlan_id"] == dst["vlan_id"]:
                    continue

                src_node = f"VLAN{src['vlan_id']}"
                dst_node = f"VLAN{dst['vlan_id']}"

                # check if both nodes exist
                if src_node not in self.graph or dst_node not in self.graph:
                    continue

                # figure out what acls apply to this path
                acl_info = self._get_acl_for_path(src, dst, acls)

                self.graph.add_edge(
                    src_node,
                    dst_node,
                    via="routed",
                    src_interface=src["interface"],
                    dst_interface=dst["interface"],
                    acl_in=dst.get("acl_in"),
                    acl_out=src.get("acl_out"),
                    acl_details=acl_info,
                    has_acl=bool(dst.get("acl_in") or src.get("acl_out")),
                )

    def _add_trunk_edges(self, interfaces: list):
        """add edges for vlans that share trunk links

        if two vlans are on the same trunk they can reach
        each other at layer 2 which is relevant for security
        """
        # find all trunk interfaces
        trunks = [i for i in interfaces if i.get("type") == "trunk"]

        for trunk in trunks:
            allowed = trunk.get("allowed_vlans", [])
            native = trunk.get("native_vlan")

            # every pair of allowed vlans on the same trunk
            for i, v1 in enumerate(allowed):
                for v2 in allowed[i + 1:]:
                    src_node = f"VLAN{v1}"
                    dst_node = f"VLAN{v2}"

                    if src_node in self.graph and dst_node in self.graph:
                        # dont overwrite routing edges - routing takes priority
                        if not self.graph.has_edge(src_node, dst_node):
                            self.graph.add_edge(
                                src_node, dst_node,
                                via="trunk",
                                trunk_interface=trunk["name"],
                                native_vlan=native,
                                has_acl=False,
                            )
                        if not self.graph.has_edge(dst_node, src_node):
                            self.graph.add_edge(
                                dst_node, src_node,
                                via="trunk",
                                trunk_interface=trunk["name"],
                                native_vlan=native,
                                has_acl=False,
                            )

    def _get_acl_for_path(self, src: dict, dst: dict, acls: list) -> list:
        """find acl entries that apply to traffic from src to dst

        checks both the outbound acl on src interface and
        inbound acl on dst interface
        """
        relevant = []

        # check outbound acl on source
        if src.get("acl_out"):
            acl_id = src["acl_out"]
            for acl in acls:
                if str(acl.get("number")) == acl_id or acl.get("name") == acl_id:
                    relevant.append(acl)

        # check inbound acl on destination
        if dst.get("acl_in"):
            acl_id = dst["acl_in"]
            for acl in acls:
                if str(acl.get("number")) == acl_id or acl.get("name") == acl_id:
                    relevant.append(acl)

        return relevant

    # --- query methods ---

    def check_reachability(self, src_vlan: int, dst_vlan: int) -> dict:
        """check if src_vlan can reach dst_vlan and how

        returns the path and what acls gate it
        """
        src_node = f"VLAN{src_vlan}"
        dst_node = f"VLAN{dst_vlan}"

        if src_node not in self.graph or dst_node not in self.graph:
            return {
                "reachable": False,
                "reason": "one or both vlans not in graph",
            }

        # check direct edge
        if self.graph.has_edge(src_node, dst_node):
            edge = self.graph.edges[src_node, dst_node]
            return {
                "reachable": True,
                "path": [src_node, dst_node],
                "via": edge.get("via"),
                "has_acl": edge.get("has_acl", False),
                "acl_in": edge.get("acl_in"),
                "acl_out": edge.get("acl_out"),
                "acl_details": edge.get("acl_details", []),
            }

        # check if theres a multi-hop path
        try:
            path = nx.shortest_path(self.graph, src_node, dst_node)
            return {
                "reachable": True,
                "path": path,
                "via": "multi-hop",
                "has_acl": any(
                    self.graph.edges[path[i], path[i + 1]].get("has_acl", False)
                    for i in range(len(path) - 1)
                ),
            }
        except nx.NetworkXNoPath:
            return {
                "reachable": False,
                "reason": "no path exists",
            }

    def get_unrestricted_paths(self) -> list:
        """find all vlan pairs that can reach each other with no acl

        these are the biggest zero trust violations
        """
        unrestricted = []

        for src, dst, data in self.graph.edges(data=True):
            if not data.get("has_acl", False):
                unrestricted.append({
                    "src": src,
                    "dst": dst,
                    "via": data.get("via", "unknown"),
                    "src_sensitivity": self.graph.nodes[src].get("sensitivity", "low"),
                    "dst_sensitivity": self.graph.nodes[dst].get("sensitivity", "low"),
                })

        # sort by sensitivity - critical ones first
        severity_order = {"critical": 0, "high": 1, "medium": 2, "untrusted": 3, "low": 4}
        unrestricted.sort(
            key=lambda x: min(
                severity_order.get(x["src_sensitivity"], 5),
                severity_order.get(x["dst_sensitivity"], 5),
            )
        )

        return unrestricted

    def get_vlan_reach_matrix(self) -> dict:
        """build a matrix showing what each vlan can reach

        returns a dict of vlan -> list of reachable vlans with details
        useful for printing a summary table
        """
        matrix = {}

        for node in self.graph.nodes():
            reachable = []
            for neighbor in self.graph.successors(node):
                edge = self.graph.edges[node, neighbor]
                reachable.append({
                    "target": neighbor,
                    "via": edge.get("via"),
                    "has_acl": edge.get("has_acl", False),
                    "acl_in": edge.get("acl_in"),
                })
            matrix[node] = reachable

        return matrix

    def get_graph_stats(self) -> dict:
        """basic stats about the graph"""
        total_edges = self.graph.number_of_edges()
        acl_edges = sum(
            1 for _, _, d in self.graph.edges(data=True)
            if d.get("has_acl", False)
        )
        return {
            "total_vlans": self.graph.number_of_nodes(),
            "total_paths": total_edges,
            "paths_with_acl": acl_edges,
            "paths_without_acl": total_edges - acl_edges,
            "unrestricted_count": len(self.get_unrestricted_paths()),
        }
