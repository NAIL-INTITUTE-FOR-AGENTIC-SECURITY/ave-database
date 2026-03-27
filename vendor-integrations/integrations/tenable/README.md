# Tenable.io Integration for NAIL AVE Database

## Overview

Import NAIL AVE agentic AI vulnerability data into Tenable.io for unified
vulnerability management — tracking agentic AI risks alongside traditional
infrastructure and application vulnerabilities in a single pane of glass.

## Architecture

```
NAIL AVE API ──► Tenable.io API (Custom Plugins / Tags)
                        │
              ┌─────────┼──────────────┐
              │         │              │
         ┌────▼────┐ ┌─▼──────────┐ ┌▼────────────┐
         │ Vuln    │ │ Asset      │ │ Lumin       │
         │ Mgmt    │ │ Tagging    │ │ Exposure    │
         └─────────┘ └────────────┘ └─────────────┘
```

## Integration Approach

Tenable.io's primary focus is infrastructure and application vulnerability
scanning. For agentic AI vulnerabilities, we integrate via:

1. **Custom Asset Tags** — Tag assets running AI agents
2. **Vulnerability Import API** — Import AVE cards as custom findings
3. **Lumin Exposure Score** — Factor agentic AI risk into cyber exposure
4. **Dashboard Widgets** — Custom widgets for AVE visibility

## Quick Start

### Step 1: Tag Agent Infrastructure

```python
import requests

TENABLE_BASE = "https://cloud.tenable.com"
TENABLE_API_KEY = "YOUR_ACCESS_KEY"
TENABLE_SECRET = "YOUR_SECRET_KEY"

headers = {
    "X-ApiKeys": f"accessKey={TENABLE_API_KEY};secretKey={TENABLE_SECRET}",
    "Content-Type": "application/json",
}

# Create tag category for AI agents
tag_category = requests.post(
    f"{TENABLE_BASE}/tags/values",
    headers=headers,
    json={
        "category_name": "AI Agent Infrastructure",
        "value": "LangChain Agent Host",
        "description": "Hosts running LangChain-based agentic AI systems",
    }
)

# Create tags for each framework
frameworks = [
    "LangChain Agent Host",
    "CrewAI Agent Host",
    "AutoGen Agent Host",
    "LlamaIndex Agent Host",
    "MCP Server Host",
    "Custom Agent Host",
]

for framework in frameworks:
    requests.post(
        f"{TENABLE_BASE}/tags/values",
        headers=headers,
        json={
            "category_name": "AI Agent Infrastructure",
            "value": framework,
        }
    )
```

### Step 2: Import AVE Cards as Custom Findings

```python
from nail_ave_sdk import AVEClient

# Fetch critical and high AVE cards
client = AVEClient()
cards = client.get_cards(severity=["critical", "high"])

# Map AVSS to CVSS-like score for Tenable compatibility
def avss_to_cvss(avss_score):
    """Map AVSS 0-10 to CVSSv3 0-10 range."""
    return round(avss_score, 1)

# Map AVE severity to Tenable severity
severity_map = {
    "critical": 4,  # Critical
    "high": 3,      # High
    "medium": 2,    # Medium
    "low": 1,       # Low
}

# Create custom findings
for card in cards:
    finding = {
        "plugin_id": hash(card["ave_id"]) % 900000 + 100000,  # Custom range
        "plugin_name": f"NAIL AVE: {card['name']}",
        "plugin_family": "AI Agent Security",
        "severity": severity_map.get(card["severity"], 2),
        "description": card["summary"],
        "solution": "\n".join(card.get("defences", [])),
        "see_also": f"https://nailinstitute.org/ave/{card['ave_id']}",
        "cvss3_base_score": avss_to_cvss(card.get("avss_score", {}).get("base", 5.0)),
        "synopsis": f"{card['category']}: {card['name']}",
        "risk_factor": card["severity"].title(),
        "references": [
            card.get("cwe_mapping", ""),
            card.get("mitre_mapping", ""),
        ],
    }
    
    # Submit to Tenable (via custom plugin or import API)
    print(f"Imported: {card['ave_id']} — {card['name']}")
```

### Step 3: Create Asset Group for Agent Hosts

```python
# Create dynamic asset group matching AI agent tags
asset_group = requests.post(
    f"{TENABLE_BASE}/asset-groups",
    headers=headers,
    json={
        "name": "AI Agent Infrastructure",
        "type": "dynamic",
        "rules": {
            "operator": "or",
            "terms": [
                {
                    "type": "tag",
                    "operator": "set-has",
                    "value": "AI Agent Infrastructure"
                }
            ]
        }
    }
)
```

## Vulnerability Dashboard Configuration

### Widget: AVE Vulnerability Summary

| Metric | Query |
|--------|-------|
| Total AVE Findings | `plugin_family:"AI Agent Security"` |
| Critical AVE Findings | `plugin_family:"AI Agent Security" AND severity:critical` |
| Agent Hosts Affected | Assets in "AI Agent Infrastructure" group with AVE findings |
| Avg AVSS Score | Average `cvss3_base_score` for AI Agent Security plugin family |

### Widget: AVE Category Distribution

```
plugin_family:"AI Agent Security"
| GROUP BY synopsis
| COUNT
| SORT desc
```

### Widget: Remediation Progress

Track the remediation state of AVE findings:

| State | Filter |
|-------|--------|
| Open | `state:open AND plugin_family:"AI Agent Security"` |
| In Progress | `state:fixed AND plugin_family:"AI Agent Security" AND last_seen > -7d` |
| Resolved | `state:fixed AND plugin_family:"AI Agent Security"` |
| Accepted Risk | `state:accepted AND plugin_family:"AI Agent Security"` |

## Lumin Exposure Integration

Factor agentic AI risk into your overall Cyber Exposure Score:

### Custom Exposure Metric: AI Agent Risk

```python
# Calculate AI Agent Exposure sub-score
def calculate_ai_exposure(tenable_client, nail_client):
    # Count tagged agent hosts
    agent_hosts = tenable_client.get_assets(
        tags=["AI Agent Infrastructure"]
    )
    total_agent_hosts = len(agent_hosts)
    
    # Count unmitigated critical AVE findings
    critical_findings = tenable_client.get_findings(
        plugin_family="AI Agent Security",
        severity="critical",
        state="open"
    )
    
    # Factor into exposure
    exposure_contribution = (
        len(critical_findings) * 10 +
        total_agent_hosts * 2
    ) / max(total_agent_hosts, 1)
    
    return min(exposure_contribution, 100)
```

## Scheduled Sync Script

```python
#!/usr/bin/env python3
"""Sync NAIL AVE cards to Tenable.io on a schedule."""

import schedule
import time
from nail_ave_sdk import AVEClient
from nail_ave_sdk.state import StateTracker

tracker = StateTracker("tenable-integration")
nail_client = AVEClient()

def sync_ave_to_tenable():
    last_sync = tracker.get_last_sync()
    cards = nail_client.get_cards(updated_since=last_sync)
    
    if not cards:
        print("No new AVE cards since last sync")
        return
    
    for card in cards:
        import_to_tenable(card)
    
    tracker.set_last_sync()
    print(f"Synced {len(cards)} AVE cards to Tenable.io")

# Run every hour
schedule.every(1).hours.do(sync_ave_to_tenable)

while True:
    schedule.run_pending()
    time.sleep(60)
```

## Compliance Reporting

Map AVE coverage to compliance frameworks in Tenable:

| Framework | Tenable Audit | AVE Mapping |
|-----------|-------------|-------------|
| EU AI Act | Custom audit file | All 14 AVE categories |
| NIST AI RMF | Custom audit file | Risk management categories |
| ISO 42001 | Custom audit file | AI management system controls |
| SOC 2 | CC6/CC7 controls | Security-relevant categories |

### Custom Audit File (.audit)

```
# NAIL AVE Compliance Checks

<custom_item>
  type: POLICY_TEXT
  description: "AVE-CHECK-001: Prompt injection defences deployed"
  info: "Verify that agentic AI systems have prompt injection defences"
  reference: "NAIL AVE Category: prompt_injection"
  solution: "Implement input guardrails, instruction hierarchy, dual-LLM pattern"
  see_also: "https://nailinstitute.org/ave-database"
</custom_item>

<custom_item>
  type: POLICY_TEXT
  description: "AVE-CHECK-002: Agent tool permissions restricted"
  info: "Verify least-privilege tool access for all AI agents"
  reference: "NAIL AVE Category: privilege_escalation"
  solution: "Implement tool permission policies with allowlists"
</custom_item>
```

## Requirements

- Tenable.io account (Vulnerability Management licence)
- Tenable.io API keys (access key + secret key)
- Network access to `api.nailinstitute.org`
- Python 3.9+ (for sync scripts)
- Optional: Tenable.sc (SecurityCenter) for on-prem deployments

## Support

- **Docs**: This README
- **Issues**: GitHub issues on `ave-database`
- **Slack**: `#vendor-integrations`
- **Email**: vendor-integrations@nailinstitute.org
