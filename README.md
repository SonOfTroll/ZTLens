# ZTLens

<div align="center">

```
  _______ _
 |__   __| |
    | |  | |     ___ _ __  ___
    | |  | |    / _ \ '_ \/ __|
    | |  | |___|  __/ | | \__ \
    |_|  |______\___|_| |_|___/

    Zero Trust Configuration Auditor
```

**AI-Powered Zero Trust Auditor for Cisco Networks**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

</div>

---

## ⚠️ What Is This

ZTLens is an AI-driven Zero Trust configuration auditor for Cisco networks. You feed it Cisco device configs (from Packet Tracer, GNS3, or real hardware), and it tells you whether your network actually enforces Zero Trust — not just whether the config is syntactically correct, but whether it's *secure by design*.

Most network auditing tools check syntax. ZTLens checks **intent vs reality** — does your network do what your security policy says it should?

---

## 🚀 Features

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

## 📦 Installation

```bash
# clone the repo
git clone https://github.com/SonOfTroll/ZTLens.git
cd ZTLens

# install dependencies
pip install -r requirements.txt
```

---

## 🖥️ Usage

```bash
# analyze a cisco config
python -m ztlens --config configs/sample_campus.cfg

# verbose output
python -m ztlens --config configs/sample_campus.cfg --verbose
```

---

## 🏗️ Architecture

```
ZTLens/
├── configs/              # sample cisco configs for testing
├── ztlens/
│   ├── parser/           # cisco ios config parser
│   ├── graph/            # networkx reachability graph
│   ├── engine/           # zero trust findings engine
│   ├── ai/               # claude api integration
│   ├── dashboard/        # web ui and visualization
│   └── reports/          # pdf/html report generation
```

---

## 🛠️ Tech Stack

| Layer | Tool |
|-------|------|
| Config parsing | Python (regex + custom IOS parser) |
| Graph engine | NetworkX |
| AI layer | Claude API (Anthropic) |
| Visualization | Cytoscape.js / D3.js |
| Report generation | ReportLab / WeasyPrint |
| Lab simulation | Cisco Packet Tracer / GNS3 |

---

## 📋 Build Phases

- [x] **Phase 1** — Parser + reachability graph
- [ ] **Phase 2** — Zero Trust findings engine
- [ ] **Phase 3** — AI explainer via Claude API
- [ ] **Phase 4** — Dashboard + visualization
- [ ] **Phase 5** — Report generator + polish

---

## 📄 License

MIT License — see [LICENSE](./LICENSE) for details.

---

<div align="center">
<sub>Built for network security professionals. Audit responsibly.</sub>
</div>
