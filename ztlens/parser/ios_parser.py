"""
cisco ios running-config parser

reads a show running-config dump and breaks it into
structured data we can actually work with
"""

import re
from typing import Optional


# section markers in ios configs
# these tell us where one block ends and another starts
SECTION_MARKERS = [
    "interface",
    "vlan",
    "access-list",
    "ip access-list",
    "line",
    "router",
]

# might need this later for filtering
_debug_mode = False


class ConfigParser:
    """parses a cisco ios running-config into structured sections"""

    def __init__(self, filepath: Optional[str] = None):
        self.filepath = filepath
        self.raw_config = ""
        self.cfg_lines = []
        self.sections = {}
        self.hostname = "unknown"

        # parsed data goes here
        self.vlans = []
        self.interfaces = []
        self.acls = []
        self.port_security = []
        self.stp_config = {}

    def load_config(self, filepath: Optional[str] = None) -> list:
        """read the config file and split into lines"""
        path = filepath or self.filepath
        if not path:
            raise ValueError("no config file specified")

        with open(path, "r") as f:
            self.raw_config = f.read()

        # strip empty lines and trailing whitespace but keep leading spaces
        # leading spaces matter in ios configs for indentation
        self.cfg_lines = []
        for line in self.raw_config.splitlines():
            stripped = line.rstrip()
            if stripped:
                self.cfg_lines.append(stripped)

        # grab hostname while were here
        self._extract_hostname()

        return self.cfg_lines

    def _extract_hostname(self):
        """pull out the hostname from config"""
        for line in self.cfg_lines:
            if line.startswith("hostname "):
                self.hostname = line.split("hostname ")[1].strip()
                break

    def _split_sections(self) -> dict:
        """break the config into logical sections

        groups lines by their section type so we can
        parse each type separately
        """
        current_section = "global"
        current_block = []
        self.sections = {"global": []}

        for line in self.cfg_lines:
            # check if this line starts a new section
            is_new_section = False
            for marker in SECTION_MARKERS:
                if line.startswith(marker):
                    # save the previous block
                    if current_block:
                        if current_section not in self.sections:
                            self.sections[current_section] = []
                        self.sections[current_section].append(current_block)
                        current_block = []

                    current_section = marker
                    is_new_section = True
                    break

            # the ! character ends a section in ios
            if line.strip() == "!":
                if current_block:
                    if current_section not in self.sections:
                        self.sections[current_section] = []
                    self.sections[current_section].append(current_block)
                    current_block = []
                current_section = "global"
                continue

            current_block.append(line)

        # dont forget the last block
        if current_block:
            if current_section not in self.sections:
                self.sections[current_section] = []
            self.sections[current_section].append(current_block)

        return self.sections

    def parse(self, filepath: Optional[str] = None) -> dict:
        """main entry point - load and parse everything

        returns a dict with all parsed data
        """
        self.load_config(filepath)
        self._split_sections()

        # these get implemented in the next commits
        self.grab_vlans()
        self.grab_interfaces()
        self.grab_acls()
        self.grab_port_security()

        return {
            "hostname": self.hostname,
            "vlans": self.vlans,
            "interfaces": self.interfaces,
            "acls": self.acls,
            "port_security": self.port_security,
            "stp": self.stp_config,
        }

    # --- extraction methods ---

    def grab_vlans(self):
        """extract vlan definitions from config

        looks for vlan X / name Y blocks and also catches
        vlans referenced in interface configs even if they
        dont have a dedicated vlan block
        """
        self.vlans = []
        seen_ids = set()

        # first grab explicitly defined vlans
        vlan_blocks = self.sections.get("vlan", [])
        for block in vlan_blocks:
            vlan_id = None
            vlan_name = ""

            for line in block:
                # match "vlan 10" or "vlan 10,20,30"
                id_match = re.match(r"^vlan\s+(\d+)", line)
                if id_match:
                    vlan_id = int(id_match.group(1))

                # match "name Finance"
                name_match = re.match(r"^\s*name\s+(.+)", line)
                if name_match:
                    vlan_name = name_match.group(1).strip()

            if vlan_id and vlan_id not in seen_ids:
                self.vlans.append({
                    "id": vlan_id,
                    "name": vlan_name or f"VLAN{vlan_id}",
                    "source": "explicit",
                })
                seen_ids.add(vlan_id)

        # also grab vlans referenced in interfaces that we might have missed
        iface_blocks = self.sections.get("interface", [])
        for block in iface_blocks:
            for line in block:
                # switchport access vlan 10
                access_match = re.match(r"^\s*switchport access vlan\s+(\d+)", line)
                if access_match:
                    vid = int(access_match.group(1))
                    if vid not in seen_ids:
                        self.vlans.append({
                            "id": vid,
                            "name": f"VLAN{vid}",
                            "source": "implicit",
                        })
                        seen_ids.add(vid)

                # switchport trunk allowed vlan 10,20,30
                trunk_match = re.match(r"^\s*switchport trunk allowed vlan\s+(.+)", line)
                if trunk_match:
                    vlan_str = trunk_match.group(1).strip()
                    for v in vlan_str.split(","):
                        v = v.strip()
                        if v.isdigit():
                            vid = int(v)
                            if vid not in seen_ids:
                                self.vlans.append({
                                    "id": vid,
                                    "name": f"VLAN{vid}",
                                    "source": "implicit",
                                })
                                seen_ids.add(vid)

        # sort by vlan id just to keep things clean
        self.vlans.sort(key=lambda x: x["id"])

        return self.vlans

    def grab_interfaces(self):
        """extract interface configs - access ports trunk ports etc

        figures out which ports are access vs trunk
        what vlan theyre on and what the native vlan is
        also picks up subinterfaces for router on a stick setups
        """
        self.interfaces = []

        iface_blocks = self.sections.get("interface", [])
        for block in iface_blocks:
            if not block:
                continue

            iface = {
                "name": "",
                "type": "unknown",     # access / trunk / routed / loopback
                "vlan": None,
                "native_vlan": None,
                "allowed_vlans": [],
                "ip_address": None,
                "subnet_mask": None,
                "acl_in": None,
                "acl_out": None,
                "shutdown": False,
                "port_security": False,
                "encapsulation": None,
                "raw_lines": block,
            }

            for line in block:
                # interface name is always the first line
                iface_match = re.match(r"^interface\s+(.+)", line)
                if iface_match:
                    iface["name"] = iface_match.group(1).strip()
                    # figure out if its a subinterface
                    if "." in iface["name"]:
                        iface["type"] = "subinterface"
                    elif "Loopback" in iface["name"]:
                        iface["type"] = "loopback"
                    elif "Vlan" in iface["name"]:
                        iface["type"] = "svi"
                    continue

                # access mode
                if "switchport mode access" in line:
                    iface["type"] = "access"

                # trunk mode
                if "switchport mode trunk" in line:
                    iface["type"] = "trunk"

                # access vlan
                av_match = re.match(r"^\s*switchport access vlan\s+(\d+)", line)
                if av_match:
                    iface["vlan"] = int(av_match.group(1))

                # native vlan on trunk
                nv_match = re.match(r"^\s*switchport trunk native vlan\s+(\d+)", line)
                if nv_match:
                    iface["native_vlan"] = int(nv_match.group(1))

                # allowed vlans on trunk
                av_trunk = re.match(r"^\s*switchport trunk allowed vlan\s+(.+)", line)
                if av_trunk:
                    vlan_str = av_trunk.group(1).strip()
                    for v in vlan_str.split(","):
                        v = v.strip()
                        if v.isdigit():
                            iface["allowed_vlans"].append(int(v))
                        elif "-" in v:
                            # handle ranges like 10-30
                            parts = v.split("-")
                            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                                start = int(parts[0])
                                end = int(parts[1])
                                iface["allowed_vlans"].extend(range(start, end + 1))

                # ip address
                ip_match = re.match(r"^\s*ip address\s+(\S+)\s+(\S+)", line)
                if ip_match:
                    iface["ip_address"] = ip_match.group(1)
                    iface["subnet_mask"] = ip_match.group(2)
                    if iface["type"] == "unknown":
                        iface["type"] = "routed"

                # acl applied to interface
                acl_in = re.match(r"^\s*ip access-group\s+(\S+)\s+in", line)
                if acl_in:
                    iface["acl_in"] = acl_in.group(1)

                acl_out = re.match(r"^\s*ip access-group\s+(\S+)\s+out", line)
                if acl_out:
                    iface["acl_out"] = acl_out.group(1)

                # shutdown check
                if line.strip() == "shutdown":
                    iface["shutdown"] = True

                # port security
                if "switchport port-security" in line:
                    iface["port_security"] = True

                # encapsulation for subinterfaces
                encap_match = re.match(r"^\s*encapsulation dot1Q\s+(\d+)", line)
                if encap_match:
                    iface["encapsulation"] = int(encap_match.group(1))
                    iface["vlan"] = int(encap_match.group(1))

            # if its a trunk with no native vlan set thats default vlan 1
            # this is a common misconfiguration
            if iface["type"] == "trunk" and iface["native_vlan"] is None:
                iface["native_vlan"] = 1

            self.interfaces.append(iface)

        return self.interfaces

    def grab_acls(self):
        """extract access control lists

        handles both numbered and named acls
        numbered: access-list 101 permit ip ...
        named: ip access-list extended BLOCK_GUEST
        """
        self.acls = []

        # numbered acls from global config lines
        # these show up as "access-list 101 permit ip ..."
        acl_blocks = self.sections.get("access-list", [])
        for block in acl_blocks:
            for line in block:
                entry = self._parse_acl_line(line)
                if entry:
                    self.acls.append(entry)

        # also check global section for standalone access-list lines
        global_lines = self.sections.get("global", [])
        for block in global_lines:
            if isinstance(block, list):
                for line in block:
                    if line.startswith("access-list"):
                        entry = self._parse_acl_line(line)
                        if entry:
                            # dont add duplicates
                            if entry not in self.acls:
                                self.acls.append(entry)
            elif isinstance(block, str) and block.startswith("access-list"):
                entry = self._parse_acl_line(block)
                if entry:
                    if entry not in self.acls:
                        self.acls.append(entry)

        # named extended acls
        named_blocks = self.sections.get("ip access-list", [])
        for block in named_blocks:
            acl_name = None
            line_num = 0

            for line in block:
                # first line is the acl name
                name_match = re.match(r"^ip access-list (?:extended|standard)\s+(\S+)", line)
                if name_match:
                    acl_name = name_match.group(1)
                    continue

                if not acl_name:
                    continue

                line_num += 10
                entry = self._parse_named_acl_entry(line, acl_name, line_num)
                if entry:
                    self.acls.append(entry)

        return self.acls

    def _parse_acl_line(self, line: str) -> dict:
        """parse a single numbered acl line

        format: access-list <num> <permit|deny> <protocol> <src> <src_wc> <dst> <dst_wc>
        theres a bunch of variations but we handle the common ones
        """
        # extended acl
        ext_match = re.match(
            r"^access-list\s+(\d+)\s+(permit|deny)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)",
            line
        )
        if ext_match:
            return {
                "number": int(ext_match.group(1)),
                "name": None,
                "action": ext_match.group(2),
                "protocol": ext_match.group(3),
                "src": ext_match.group(4),
                "src_wildcard": ext_match.group(5),
                "dst": ext_match.group(6),
                "dst_wildcard": ext_match.group(7),
                "line": line.strip(),
                "type": "extended",
            }

        # extended with "any" keyword
        ext_any = re.match(
            r"^access-list\s+(\d+)\s+(permit|deny)\s+(\S+)\s+(\S+)\s+(\S+)\s+(any)",
            line
        )
        if ext_any:
            return {
                "number": int(ext_any.group(1)),
                "name": None,
                "action": ext_any.group(2),
                "protocol": ext_any.group(3),
                "src": ext_any.group(4),
                "src_wildcard": ext_any.group(5),
                "dst": "any",
                "dst_wildcard": "0.0.0.0",
                "line": line.strip(),
                "type": "extended",
            }

        # simple numbered acl - just src
        simple_match = re.match(
            r"^access-list\s+(\d+)\s+(permit|deny)\s+(\S+)\s*(\S*)",
            line
        )
        if simple_match:
            src = simple_match.group(3)
            src_wc = simple_match.group(4) if simple_match.group(4) else "0.0.0.0"
            return {
                "number": int(simple_match.group(1)),
                "name": None,
                "action": simple_match.group(2),
                "protocol": "ip",
                "src": src,
                "src_wildcard": src_wc,
                "dst": "any",
                "dst_wildcard": "0.0.0.0",
                "line": line.strip(),
                "type": "standard",
            }

        return None

    def _parse_named_acl_entry(self, line: str, acl_name: str, line_num: int) -> dict:
        """parse a single line from a named acl"""
        line = line.strip()
        if not line or line.startswith("!"):
            return None

        # permit/deny protocol src src_wc dst dst_wc
        match = re.match(
            r"^(permit|deny)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)",
            line
        )
        if match:
            return {
                "number": None,
                "name": acl_name,
                "action": match.group(1),
                "protocol": match.group(2),
                "src": match.group(3),
                "src_wildcard": match.group(4),
                "dst": match.group(5),
                "dst_wildcard": match.group(6),
                "line": line,
                "type": "named_extended",
                "line_number": line_num,
            }

        # permit/deny src wildcard (standard named)
        std_match = re.match(r"^(permit|deny)\s+(\S+)\s*(\S*)", line)
        if std_match:
            return {
                "number": None,
                "name": acl_name,
                "action": std_match.group(1),
                "protocol": "ip",
                "src": std_match.group(2),
                "src_wildcard": std_match.group(3) if std_match.group(3) else "0.0.0.0",
                "dst": "any",
                "dst_wildcard": "0.0.0.0",
                "line": line,
                "type": "named_standard",
                "line_number": line_num,
            }

        return None

    def grab_port_security(self):
        """check for port security configs on access port interfaces

        looks at each access port and checks if port security
        is enabled and how its configured
        """
        self.port_security = []

        for iface in self.interfaces:
            if iface["type"] != "access":
                continue

            ps_info = {
                "interface": iface["name"],
                "enabled": False,
                "max_addresses": 1,     # default
                "violation_mode": "shutdown",   # default
                "sticky": False,
            }

            for line in iface.get("raw_lines", []):
                if "switchport port-security" in line and "maximum" not in line and "violation" not in line and "mac" not in line:
                    ps_info["enabled"] = True

                max_match = re.match(r"^\s*switchport port-security maximum\s+(\d+)", line)
                if max_match:
                    ps_info["max_addresses"] = int(max_match.group(1))

                if "violation" in line:
                    viol_match = re.match(r"^\s*switchport port-security violation\s+(\S+)", line)
                    if viol_match:
                        ps_info["violation_mode"] = viol_match.group(1)

                if "mac-address sticky" in line:
                    ps_info["sticky"] = True

            self.port_security.append(ps_info)

        return self.port_security

    def grab_stp_config(self):
        """extract spanning tree config

        checks for things like root bridge priority
        bpdu guard and portfast settings
        """
        # fixme this is pretty basic right now
        self.stp_config = {
            "mode": "pvst",     # default
            "portfast_default": False,
            "bpdu_guard_default": False,
        }

        # check global lines for stp settings
        for block in self.sections.get("global", []):
            lines = block if isinstance(block, list) else [block]
            for line in lines:
                if "spanning-tree mode" in line:
                    mode_match = re.match(r"spanning-tree mode\s+(\S+)", line)
                    if mode_match:
                        self.stp_config["mode"] = mode_match.group(1)

                if "spanning-tree portfast default" in line:
                    self.stp_config["portfast_default"] = True

                if "spanning-tree portfast bpduguard default" in line:
                    self.stp_config["bpdu_guard_default"] = True

        return self.stp_config

