# CrowdStrike Falcon Integration for NAIL AVE Database

## Overview

Enrich CrowdStrike Falcon threat intelligence with NAIL AVE agentic AI
vulnerability data, enabling detection of AI-specific threats, custom IOA
(Indicators of Attack) rules, and automated response workflows via Falcon
Fusion SOAR.

## Architecture

```
NAIL AVE API ──► CrowdStrike Falcon API (Custom IOCs / IOAs)
                        │
              ┌─────────┼────────────────┐
              │         │                │
         ┌────▼────┐ ┌─▼──────────┐ ┌──▼──────────┐
         │ Custom  │ │ Falcon     │ │ Falcon      │
         │  IOAs   │ │ Fusion     │ │ Spotlight   │
         │         │ │ (SOAR)     │ │ (Vuln Mgmt) │
         └─────────┘ └────────────┘ └─────────────┘
```

## Integration Methods

### Method 1: Custom IOA Rules via Falcon API

Map AVE categories to custom IOA rule groups that detect agentic AI attack
patterns on endpoints:

```python
import requests

FALCON_BASE = "https://api.crowdstrike.com"
FALCON_CLIENT_ID = "YOUR_CLIENT_ID"
FALCON_CLIENT_SECRET = "YOUR_CLIENT_SECRET"

# Authenticate
auth = requests.post(f"{FALCON_BASE}/oauth2/token", data={
    "client_id": FALCON_CLIENT_ID,
    "client_secret": FALCON_CLIENT_SECRET,
})
token = auth.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# Fetch AVE cards
nail_cards = requests.get(
    "https://api.nailinstitute.org/api/v1/cards",
    params={"severity": "critical"}
).json()

# Create Custom IOA Rule Group for AVE threats
rule_group = requests.post(
    f"{FALCON_BASE}/ioarules/entities/rule-groups/v1",
    headers=headers,
    json={
        "name": "NAIL AVE — Agentic AI Threats",
        "description": "Detection rules derived from NAIL AVE database",
        "platform": "windows",
        "enabled": True,
    }
)
rule_group_id = rule_group.json()["resources"][0]["id"]
```

### Method 2: Falcon Fusion SOAR Workflow

Create an automated workflow that:
1. Polls the NAIL AVE API hourly
2. Compares new cards against deployed agent infrastructure
3. Creates Falcon incidents for matching vulnerabilities
4. Triggers response playbooks

```yaml
# Falcon Fusion Workflow: NAIL AVE Monitor
name: NAIL AVE Vulnerability Monitor
trigger:
  type: scheduled
  interval: 1h

actions:
  - name: Fetch AVE Cards
    type: http_request
    config:
      method: GET
      url: https://api.nailinstitute.org/api/v1/cards
      params:
        updated_since: "{{last_run_time}}"
      headers:
        Accept: application/json

  - name: Filter Critical
    type: filter
    condition: "{{item.severity}} in ['critical', 'high']"

  - name: Check Agent Infrastructure
    type: falcon_api
    config:
      endpoint: /devices/queries/devices/v1
      filter: "tags:['ai-agent-host']"

  - name: Create Incident
    type: create_incident
    condition: "{{matched_hosts}} > 0"
    config:
      name: "NAIL AVE {{item.ave_id}}: {{item.name}}"
      description: "{{item.summary}}"
      severity: "{{map_severity(item.severity)}}"
      tags: ["nail-ave", "agentic-ai", "{{item.category}}"]
```

### Method 3: Falcon Spotlight Vulnerability Import

Import AVE cards as custom vulnerability definitions in Falcon Spotlight:

```python
# Map AVE cards to Spotlight vulnerability format
def ave_to_spotlight(card):
    return {
        "id": card["ave_id"],
        "name": card["name"],
        "description": card["summary"],
        "severity": map_severity_to_cvss(card["severity"]),
        "published_date": card["date_published"],
        "remediation": "\n".join(card.get("defences", [])),
        "references": [
            f"https://nailinstitute.org/ave/{card['ave_id']}"
        ],
        "tags": ["nail-ave", card["category"]],
    }

# Severity mapping (AVE severity → Falcon Spotlight)
def map_severity_to_cvss(severity):
    mapping = {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
    }
    return mapping.get(severity, 5.0)
```

## Falcon LogScale (Humio) Queries

If using Falcon LogScale for log aggregation, query ingested AVE data:

### All AVE Cards
```logscale
#source=nail_ave
| table([ave_id, name, category, severity, avss_score])
```

### Critical Cards in Last 24h
```logscale
#source=nail_ave severity=critical
| @timestamp > now() - 24h
| sort(@timestamp, order=desc)
```

### Category Breakdown
```logscale
#source=nail_ave
| groupBy(category, function=count())
| sort(_count, order=desc)
```

### AVSS Score Histogram
```logscale
#source=nail_ave
| bucket(field=avss_score, span=1)
| groupBy(_bucket, function=count())
```

## Response Playbooks

### Playbook 1: Critical AVE Card — Immediate Response

```
Trigger: New AVE card with severity=critical matching deployed frameworks

1. CREATE incident in Falcon with severity=Critical
2. TAG affected hosts with "nail-ave-{ave_id}"
3. ISOLATE hosts running vulnerable agent configurations (if auto-response enabled)
4. NOTIFY security team via Slack/PagerDuty
5. CREATE Jira ticket for remediation
6. SCHEDULE follow-up review in 24 hours
```

### Playbook 2: High AVSS Score — Investigation Required

```
Trigger: New AVE card with avss_score >= 7.0

1. CREATE investigation in Falcon
2. QUERY Falcon telemetry for indicators matching the AVE mechanism
3. CHECK if any agent processes exhibit the described behaviour
4. GENERATE report with affected scope
5. ESCALATE to AI security team
```

### Playbook 3: Supply Chain AVE — Dependency Audit

```
Trigger: New AVE card with category=supply_chain

1. SCAN deployed agent software for affected dependencies
2. CHECK Falcon Spotlight for matching vulnerabilities
3. CROSS-REFERENCE with AI-SBOM data
4. CREATE change request to update affected dependencies
5. MONITOR for exploitation attempts for 30 days
```

## Host Tagging for Agent Infrastructure

Tag hosts running AI agents for automated matching:

```python
# Tag hosts that run AI agent workloads
def tag_agent_hosts(falcon_client):
    # Query hosts running agent processes
    agent_processes = ["langchain", "crewai", "autogen", "llamaindex"]
    
    for process in agent_processes:
        hosts = falcon_client.query_devices(
            filter=f"processes.name:'{process}'"
        )
        for host_id in hosts:
            falcon_client.update_device_tags(
                host_id,
                tags=[f"ai-agent-host", f"framework:{process}"]
            )
```

## AVE Category → MITRE ATT&CK Mapping for Falcon

| AVE Category | Falcon Tactic | Falcon Technique |
|-------------|--------------|-----------------|
| Prompt Injection | Initial Access | T1190 (Exploit Public-Facing Application) |
| Goal Hijacking | Execution | T1059 (Command and Scripting Interpreter) |
| Unsafe Code Execution | Execution | T1059.006 (Python) |
| Privilege Escalation | Privilege Escalation | T1068 (Exploitation for Privilege Escalation) |
| Information Leakage | Exfiltration | T1041 (Exfiltration Over C2 Channel) |
| Supply Chain | Initial Access | T1195 (Supply Chain Compromise) |
| Memory Poisoning | Impact | T1565 (Data Manipulation) |
| Monitoring Evasion | Defense Evasion | T1562 (Impair Defenses) |

## Requirements

- CrowdStrike Falcon platform (any tier)
- Falcon API client credentials with appropriate scopes:
  - `custom-ioa:write` (for IOA rules)
  - `incidents:write` (for incident creation)
  - `hosts:read` (for host queries)
  - `spotlight-vulnerabilities:read` (for Spotlight)
- Network access to `api.nailinstitute.org`
- Python 3.9+ (for integration scripts)

## Support

- **Docs**: This README
- **Issues**: GitHub issues on `ave-database`
- **Slack**: `#vendor-integrations`
- **Email**: vendor-integrations@nailinstitute.org
