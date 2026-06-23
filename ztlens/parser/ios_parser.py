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

    # --- these are stubs for now ---

    def grab_vlans(self):
        """extract vlan definitions from config"""
        # todo implement vlan parsing
        pass

    def grab_interfaces(self):
        """extract interface configs - access ports trunk ports etc"""
        # todo implement interface parsing
        pass

    def grab_acls(self):
        """extract access control lists"""
        # todo implement acl parsing
        pass

    def grab_port_security(self):
        """check for port security configs on interfaces"""
        # todo implement port security checks
        pass

    def grab_stp_config(self):
        """extract spanning tree config"""
        # probably not critical for phase 1 but adding the stub
        pass
