# 🛡️ NAIL Institute — AVE Database

[![AVE Cards](https://img.shields.io/badge/AVE_Cards-100-blue)](./ave-database/)
[![Production Packages](https://img.shields.io/badge/Production_Packages-12-brightgreen)](./AVE-PLATFORM-OVERVIEW.md)
[![Service Blueprints](https://img.shields.io/badge/Service_Blueprints-117-purple)](./AVE-PLATFORM-OVERVIEW.md)
[![Phases](https://img.shields.io/badge/Phases-31%2F31_designed-yellow)](./ROADMAP.md)
[![License](https://img.shields.io/badge/License-CC--BY--SA--4.0-green)](https://creativecommons.org/licenses/by-sa/4.0/)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-orange)](./CONTRIBUTING.md)
[![Hall of Fame](https://img.shields.io/badge/Hall_of_Fame-🏆-gold)](./HALL_OF_FAME.md)

> **The MITRE ATT&CK of the Agentic Era.**
>
> An open, community-driven catalogue of AI agent vulnerabilities — plus
> 12 production-tested packages and 117 service blueprints for autonomous
> defence, threat intelligence, compliance, and governance of agentic AI systems.

---

## At a Glance

| Metric | Value |
|--------|-------|
| **AVE Cards** | 100 across 20 categories |
| **Severity** | 32 Critical · 42 High · 26 Medium |
| **AVSS Range** | 3.1 – 10.0 (mean 7.9) |
| **Production Packages** | 12 tested packages (~44K lines, 29 test files) |
| **Service Blueprints** | 117 single-file FastAPI prototypes (designed, not yet tested) |
| **Phases** | 31 designed · 10 production-tested · 21 blueprinted |
| **Vendor Integrations** | 9 (Splunk, Sentinel, ServiceNow, CrowdStrike, Elastic, Palo Alto XSOAR, Tenable, Jira, Snyk) |
| **Academic Modules** | 13 courses (AAS-101 → AAS-304) |
| **Annual Report** | 14-chapter inaugural edition (2025) |
| **Stack** | Python · FastAPI · Pydantic · Docker Compose |

---

## What Is This?

AI agents are being deployed in production — executing code, calling APIs,
managing infrastructure, handling sensitive data. But there's no CVE database
for the ways they fail.

**Until now.**

The **AVE Database** (Agentic Vulnerabilities & Exposures) documents every
known failure mode of autonomous AI agents:

- 🧠 **Memory poisoning** — Agents trust corrupted shared state
- 🔗 **Tool chain exploits** — Confused deputy attacks via MCP/function calling
- 🎭 **Alignment failures** — Sycophantic collapse, deceptive alignment
- ⏰ **Temporal attacks** — Sleeper payloads, chronological desynchronisation
- 💸 **Resource exhaustion** — Token embezzlement, EDoS attacks
- 🤝 **Social failures** — Agent collusion, consensus paralysis
- …and 80 more documented vulnerabilities

Beyond the vulnerability database, the AVE platform includes **autonomous
defence agents**, **real-time threat intelligence**, **compliance automation**,
**governance-as-code**, and a full **research and education programme** —
see the [**Platform Overview**](./AVE-PLATFORM-OVERVIEW.md) for all 155
services across 31 phases.

## Browse the Database

📖 **[ave-database/](./ave-database/)** — All 50 vulnerability cards

Each card contains:
- **What** — Name, category, severity, blast radius
- **Where** — Affected frameworks (LangGraph, AutoGen, CrewAI, and more)
- **How to Defend** — Known mitigation strategies (names only in public tier)
- **AVSS Score** — Agentic Vulnerability Scoring System rating (0–10)

> 🔒 Full mechanism details, evidence data, PoC scripts, and defence implementations
> are available through the [NAIL SDK](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY).

## Quick Start

```bash
# Clone the repo
git clone https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database.git
cd ave-database

# Install the AVE toolkit
pip install -e ave/

# Explore
python -m ave list                       # All 50 cards
python -m ave show AVE-2025-0001         # Card details
python -m ave search -k "injection"      # Search
python -m ave stats                      # Statistics
python -m ave leaderboard                # Top contributors

# Run a micro-service (Phases 11–31)
docker compose -f docker-compose.phase11.yml up -d   # Ports 9780–9784
```

## The Platform

### Production Packages (12 — tested, importable, used in production)

| Package | Lines | Tests | Description |
|---------|------:|:-----:|-------------|
| **ave** | 8,040 | 4 | AVE card schema, scoring, registry, CLI |
| **nail_monitor** | 4,701 | 1 | 20 pathology detectors (deployed in NAIL SaaS) |
| **integration** | 6,019 | 7 | Cross-package integration harness |
| **canary** | 4,424 | 3 | Canary deployment & smoke testing |
| **arena** | 4,268 | 3 | Adversarial battle arena |
| **ctf** | 3,482 | 2 | Capture-the-flag framework |
| **threatfeed** | 2,857 | 2 | Threat intelligence feed |
| **rmap** | 2,506 | 5 | Regulatory mapping |
| **horizon** | 2,086 | 1 | Horizon scanning & campaign runner |
| **dese** | 1,950 | 1 | Deterministic entropy simulation engine |
| **diagnostic** | 1,950 | 1 | System diagnostic toolkit |
| **nail_harness** | — | — | Agent test harness (Ollama + VQC) |

### Service Blueprints (117 — designed, not yet integration-tested)

108 single-file FastAPI prototypes + 9 multi-file services. Each contains
real endpoint logic and Pydantic models, but they have **no tests, no
pyproject.toml, and have not been run against production data**. They
represent the *design intent* for the full platform.

The AVE Database is the core of a much larger security platform. All 31
phases have been designed:

| Phase Range | Focus | Services |
|:-----------:|-------|:--------:|
| **1–10** | Foundation, community, API, research, CTF, quantum, standards, governance, ecosystem | Core infrastructure |
| **11–13** | Autonomous defence, real-time intel, threat mesh, knowledge graph | 15 |
| **14–16** | Self-evolving defences, quantum-safe crypto, neuro-symbolic reasoning | 15 |
| **17–19** | Meta-cognitive architecture, temporal forensics, ethical reasoning | 15 |
| **20–22** | Post-quantum vault, digital twins, evolutionary red-teaming | 15 |
| **23–25** | Self-healing mesh, chaos engineering, human-AI teaming | 15 |
| **26–28** | Policy compilation, constitutional AI, resilience engineering | 15 |
| **29–31** | Meta-learning, swarm consensus, governance audit trails | 15 |

📖 **[AVE-PLATFORM-OVERVIEW.md](./AVE-PLATFORM-OVERVIEW.md)** — Full service catalogue with ports, descriptions, and capabilities

Each phase has a Docker Compose file (`docker-compose.phase11.yml` through
`docker-compose.phase31.yml`) for local development.

## 🎓 Academic Programme

A 13-module university curriculum covering all aspects of agentic AI security:

| Level | Modules | Focus |
|-------|---------|-------|
| **100** | AAS-101, 102, 103 | Foundations — threats, taxonomy, prompt injection |
| **200** | AAS-201 – 204 | Intermediate — multi-agent, tools, guardrails, AVSS |
| **300** | AAS-301 – 304 | Advanced — red-teaming, formal verification, emergence, supply chain |

📖 **[academic/courses/](./academic/courses/)** — Full course materials

## 🔌 Vendor Integrations

Pre-built integrations for enterprise security toolchains:

| Integration | Type | Directory |
|------------|------|-----------|
| **Splunk** | SIEM | [vendor-integrations/integrations/splunk/](./vendor-integrations/integrations/splunk/) |
| **Microsoft Sentinel** | SIEM | [vendor-integrations/integrations/sentinel/](./vendor-integrations/integrations/sentinel/) |
| **ServiceNow** | GRC/ITSM | [vendor-integrations/integrations/servicenow/](./vendor-integrations/integrations/servicenow/) |
| **CrowdStrike** | EDR | [vendor-integrations/integrations/crowdstrike/](./vendor-integrations/integrations/crowdstrike/) |
| **Elastic** | SIEM | [vendor-integrations/integrations/elastic/](./vendor-integrations/integrations/elastic/) |
| **Palo Alto XSOAR** | SOAR | [vendor-integrations/integrations/xsoar/](./vendor-integrations/integrations/xsoar/) |
| **Tenable** | Vuln Mgmt | [vendor-integrations/integrations/tenable/](./vendor-integrations/integrations/tenable/) |
| **Jira** | Issue Tracking | [vendor-integrations/integrations/jira/](./vendor-integrations/integrations/jira/) |
| **Snyk** | Dev Security | [vendor-integrations/integrations/snyk/](./vendor-integrations/integrations/snyk/) |

Plus a **Python SDK** for building custom integrations: [vendor-integrations/sdk/](./vendor-integrations/sdk/)

## 📊 Annual Report

The inaugural **State of Agentic AI Security** report — 14 chapters covering
the vulnerability landscape, multi-agent threats, defence effectiveness,
industry impact, regulatory analysis, and predictions for 2026.

📖 **[annual-report/2025/](./annual-report/2025/)** — Full report

## Contribute

**Anyone can submit vulnerabilities.** If you've observed an AI agent behave
unexpectedly, fail in a repeatable way, or found an exploitable pattern —
we want to hear about it.

| Method | For |
|--------|-----|
| [**📝 Submit via Issue**](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database/issues/new?template=ave-submission.yml) | Easiest — fill out a form |
| [**🔀 Submit via PR**](./CONTRIBUTING.md) | Experienced contributors |
| [**🔒 Private Disclosure**](./SECURITY.md) | Severe / weaponizable findings |

### Earn Recognition

Every accepted card earns **XP**, unlocks **badges**, and climbs the **leaderboard**:

| Tier | XP | Perks |
|------|----|-------|
| 👁️ Watcher | 0+ | Welcome to the hunt |
| 🏹 Hunter | 500+ | Hall of Fame listing |
| 🛡️ Sentinel | 1,500+ | Fast-track review |
| 🏗️ Architect | 4,000+ | Invited to review PRs |
| ⭐ Fellow | 8,000+ | NAIL Research Fellow |

See the [**🏆 Hall of Fame**](./HALL_OF_FAME.md) for current standings.

## 🔬 Research

29 experiments across 5 model families, plus quantum research on DGX Spark:

| Finding | Key Result |
|---------|-----------|
| **Confused Deputy Attack** | 100% exploit rate on Claude/Gemini (p=0.0002) |
| **AI Bystander Effect** | 20% failure in multi-agent teams |
| **GA-Evolved Defences** | 100% detection, 0% corruption |
| **5-Layer Defence Stack** | Eliminates all tested attack vectors |
| **QAOA Threshold Optimizer** | +3.1% fitness, +17.6% accuracy over GA (20 qubits) |
| **Hybrid QNN Classifier** | 84.2% accuracy, 100% on 3/6 pathology classes |
| **Robustness Certification** | 🥇 Gold (99% CI: 97.4%–100%) |

📖 **[research/](./research/)** — Findings, statistics, defence architecture, paper abstract
📄 **[quantum/](./quantum/)** — Paper, experiments, visualizations, staging configs

## 🏁 CTF Events

Capture-The-Flag competitions where human red teamers exploit defended AI agents.
Novel attacks discovered during events become AVE database entries.

🏁 **[CTF Portal](https://nail-institute-for-agentic-security.github.io/ave-database/ctf.html)** — Events, challenges, rules, and results

## 🌐 Public API

Read-only API for programmatic access to the AVE database.

📡 **[api/](./api/)** — FastAPI server with search, filtering, and statistics

## 💬 Community

- [**Discussions**](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database/discussions) — AVE proposals, research, defences, CTF events
- [**Hall of Fame**](./HALL_OF_FAME.md) — Contributor leaderboard with XP, badges, and tiers
- [**Contributing Guide**](./CONTRIBUTING.md) — How to submit vulnerabilities
- [**Roadmap**](./ROADMAP.md) — Completed phases and what's next
- [**Awesome List**](./AWESOME.md) — Curated resources for agentic AI security
- [**Changelog**](./CHANGELOG.md) — All notable changes
- [**Platform Overview**](./AVE-PLATFORM-OVERVIEW.md) — All 155 services at a glance

## Project Structure

```
├── ave-database/              # The vulnerability database (50 cards)
├── ave/                       # Python CLI toolkit
├── api/                       # Public read-only API (FastAPI)
├── research/                  # Published research artifacts
├── quantum/                   # Quantum research (DGX Spark)
├── academic/                  # 13-module university curriculum (AAS-101→304)
├── annual-report/             # 2025 Annual Report (14 chapters)
├── vendor-integrations/       # 9 vendor integrations + SDK
├── schema-v2/                 # AVE 2.0 schema (20 categories)
├── chapters/                  # Regional chapters (NA, EU, APAC)
├── certification/             # 4-tier NAIL Certified programme
├── training/                  # 4-track workshop curriculum
├── conference/                # Conference presence kit
├── sustainability/            # Financial model & grant strategy
├── live-feed/                 # Real-time WebSocket/SSE feed (port 9780)
├── autonomous-redteam/        # Self-directed red team agent (port 9781)
├── defence-orchestration/     # Guardrail lifecycle management (port 9782)
├── threat-intel/              # STIX/TAXII threat sharing (port 9783)
├── knowledge-graph/           # Neo4j knowledge graph (port 9784)
├── ...                        # 150 more service directories (ports 9785–9934)
├── docker-compose.phase*.yml  # 21 Docker Compose files (phases 11–31)
├── docs/                      # Documentation site (GitHub Pages)
├── .github/                   # CI, issue/PR templates, Discussions
├── AVE-PLATFORM-OVERVIEW.md   # Full 155-service catalogue
├── ROADMAP.md                 # Public roadmap
├── CHANGELOG.md               # Version history
├── CONTRIBUTING.md             # How to contribute
├── SECURITY.md                # Responsible disclosure
├── CODE_OF_CONDUCT.md         # Community standards
├── HALL_OF_FAME.md            # Contributor leaderboard
└── LICENSE                    # CC-BY-SA-4.0
```

## License

All AVE Database content is licensed under
[**CC-BY-SA-4.0**](https://creativecommons.org/licenses/by-sa/4.0/).
Code is licensed under [**Apache 2.0**](https://www.apache.org/licenses/LICENSE-2.0).
Free to use, share, and build upon — with attribution.

---

<p align="center">
  <b>Built by the <a href="https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY">NAIL Institute</a></b><br>
  <i>Building the safety infrastructure for agentic AI.</i><br>
  <i>12 production packages · 117 blueprints · 100 vulnerability cards · 100% open</i>
</p>
