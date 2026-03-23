# 🛡️ NAIL Institute — AVE Database

[![AVE Cards](https://img.shields.io/badge/AVE_Cards-36-blue)](./ave-database/)
[![License](https://img.shields.io/badge/License-CC--BY--SA--4.0-green)](https://creativecommons.org/licenses/by-sa/4.0/)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-orange)](./CONTRIBUTING.md)
[![Hall of Fame](https://img.shields.io/badge/Hall_of_Fame-🏆-gold)](./HALL_OF_FAME.md)

> **The MITRE ATT&CK of the Agentic Era.**
>
> An open, community-driven catalogue of AI agent vulnerabilities — behavioural
> failure modes, attack vectors, and emergent pathologies affecting autonomous
> AI systems.

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
- …and 30 more documented vulnerabilities

## Browse the Database

📖 **[ave-database/](./ave-database/)** — All 36 vulnerability cards

Each card contains:
- **What** — Name, category, severity, blast radius
- **Where** — Affected frameworks, agent configurations
- **How to Defend** — Known mitigation strategies (names only in public tier)

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
python -m ave list                       # All cards
python -m ave show AVE-2025-0001         # Card details
python -m ave search -k "injection"      # Search
python -m ave stats                      # Statistics
python -m ave leaderboard                # Top contributors
```

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

## Project Structure

```
├── ave-database/          # The vulnerability database
│   ├── cards/             #   Individual AVE cards (JSON + Markdown)
│   ├── index.json         #   Database index
│   └── README.md          #   Database documentation
├── ave/                   # Python toolkit
│   └── ave/               #   CLI, validation, submission tools
├── .github/               # Issue templates, PR templates, CI
├── CONTRIBUTING.md        # How to contribute
├── SECURITY.md            # Responsible disclosure
├── CODE_OF_CONDUCT.md     # Community standards
├── HALL_OF_FAME.md        # Contributor leaderboard
└── LICENSE                # CC-BY-SA-4.0
```

## License

All AVE Database content is licensed under
[**CC-BY-SA-4.0**](https://creativecommons.org/licenses/by-sa/4.0/).
Free to use, share, and build upon — with attribution.

---

<p align="center">
  <b>Built by the <a href="https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY">NAIL Institute</a></b><br>
  <i>Building the safety infrastructure for agentic AI.</i>
</p>
