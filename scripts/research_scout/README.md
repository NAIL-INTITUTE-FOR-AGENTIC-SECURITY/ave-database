# 🔍 Research Scout — Automated AVE Discovery Agent

> Automated tool that scans research feeds, CVE databases, and incident reports to discover new agentic AI vulnerability classes.

## Overview

Research Scout continuously monitors the AI security research landscape to identify potential new vulnerability classes that should be added to the AVE database. It processes:

- **arXiv papers** — AI safety and security research
- **CVE/NVD databases** — Relevant vulnerability disclosures
- **GitHub advisories** — AI/ML framework security issues
- **Blog posts & reports** — Security research from major AI labs
- **Incident databases** — AI incident reports (AIAAIC, etc.)

## Quick Start

```bash
cd scripts/research_scout/

# Install dependencies
pip install -r requirements.txt

# Run a discovery scan
python scout.py scan --sources arxiv,cve,github

# Scan with specific keywords
python scout.py scan --keywords "prompt injection,jailbreak,agent exploit"

# Check against existing AVE cards for novelty
python scout.py analyse --input findings.json --check-duplicates

# Generate discovery report
python scout.py report --format markdown
```

## Architecture

```
                    ┌──────────────────┐
                    │  Research Scout   │
                    │     Engine        │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │   Source    │  │   Source    │  │   Source    │
     │  Adapters   │  │  Adapters   │  │  Adapters   │
     │  (arXiv)    │  │  (CVE/NVD) │  │  (GitHub)  │
     └──────┬─────┘  └──────┬─────┘  └──────┬─────┘
            │               │               │
            ▼               ▼               ▼
     ┌──────────────────────────────────────────┐
     │         Candidate Extraction              │
     │  (NLP + keyword + pattern matching)       │
     └──────────────────┬───────────────────────┘
                        │
                        ▼
     ┌──────────────────────────────────────────┐
     │         Novelty Assessment                │
     │  (Compare against existing 50 AVE cards)  │
     └──────────────────┬───────────────────────┘
                        │
                        ▼
     ┌──────────────────────────────────────────┐
     │         Severity Estimation               │
     │  (AVSS-style preliminary scoring)         │
     └──────────────────┬───────────────────────┘
                        │
                        ▼
     ┌──────────────────────────────────────────┐
     │         Report Generation                 │
     │  (JSON + Markdown + Draft AVE cards)      │
     └──────────────────────────────────────────┘
```

## Source Adapters

| Source | Method | Rate Limit | Coverage |
|--------|--------|------------|----------|
| arXiv | RSS/API | 3 req/s | AI safety, security, ML papers |
| CVE/NVD | REST API | 5 req/30s | AI/ML related CVEs |
| GitHub Advisories | GraphQL | 5000/hr | AI framework advisories |
| AIAAIC | Web scrape | 1 req/5s | AI incident database |
| AI labs blogs | RSS | 1 req/s | OpenAI, Anthropic, Google, Meta |

## Configuration

See `config.yaml` for:
- Source endpoints and API keys
- Keyword lists and search patterns
- Novelty threshold settings
- Scheduling (cron expression)
- Notification settings

## Output

### Discovery Candidates

```json
{
  "candidate_id": "DISC-2026-0042",
  "source": "arxiv",
  "source_id": "2603.12345",
  "title": "Novel Attack on Multi-Agent Reward Sharing",
  "summary": "...",
  "relevance_score": 0.87,
  "novelty_score": 0.72,
  "estimated_severity": "high",
  "closest_ave": "AVE-2024-007",
  "similarity_to_closest": 0.34,
  "suggested_category": "alignment",
  "recommended_action": "review_for_new_ave"
}
```

### Actions

- `review_for_new_ave` — High novelty, warrants new AVE card
- `update_existing` — Extends knowledge of existing AVE
- `monitor` — Interesting but needs more evidence
- `skip` — Not relevant or already covered

---

*Part of the [NAIL Institute AVE Database](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database)*
