
<div align="center">

<div align="center">

<pre>
 _______ _______ _
|___  /|__   __| |
   / /    | |  | |     ___ _ __  ___
  / /     | |  | |    / _ \ '_ \/ __|
 / /__    | |  | |___|  __/ | | \__ \
/_____|   |_|  |______\___|_| |_|___/

      Zero Trust Configuration Auditor
</pre>

</div>




**AI-Powered Zero Trust Auditor for Cisco Networks**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

</div>

---

## What Is This

ZTLens is an AI-driven Zero Trust configuration auditor for Cisco networks. You feed it Cisco device configs (from Packet Tracer, GNS3, or real hardware), and it tells you whether your network actually enforces Zero Trust — not just whether the config is syntactically correct, but whether it's *secure by design*.

Most network auditing tools check syntax. ZTLens checks **intent vs reality** — does your network do what your security policy says it should?

---

## Features

| Feature | Description |
|---------|-------------|
| **Config Ingestion** | Parses Cisco IOS running-configs — VLANs, trunks, ACLs, port security, STP |
| **Zero Trust Analysis** | Checks configs against ZT principles — least privilege, micro-segmentation, assume breach |
| **Reachability Graph** | Builds a NetworkX graph showing which VLANs can reach which, through what path |
| **Findings Engine** | Structured findings with severity, attack path, exact config line, and fix |
| **AI Explainer** | Claude API explains findings in plain English and answers questions |
| **Topology Visualizer** | Interactive network graph — color-coded by compliance status |
| **Report Generator** | One-click PDF/HTML audit reports with ZT compliance score |

---

## License

MIT License — see [LICENSE](./LICENSE) for details.

---

<div align="center">
<sub>Built for network security professionals. Audit responsibly.</sub>
</div>
