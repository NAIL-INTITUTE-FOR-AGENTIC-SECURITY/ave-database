# Jira (Atlassian) Integration for NAIL AVE Database

## Overview

Automatically create, track, and resolve Jira issues from NAIL AVE agentic
AI vulnerability data — bridging the gap between security research and
engineering remediation workflows.

## Architecture

```
NAIL AVE API ──► Jira Cloud / Data Center API
                        │
              ┌─────────┼──────────────┐
              │         │              │
         ┌────▼────┐ ┌─▼──────────┐ ┌▼────────────┐
         │ Issue   │ │ Dashboards │ │ Automation  │
         │ Tracker │ │ & Filters  │ │ Rules       │
         └─────────┘ └────────────┘ └─────────────┘
```

## Integration Methods

### Method 1: Jira Automation (No-Code)

Create a Jira Automation rule that polls the NAIL AVE API:

1. **Trigger**: Scheduled (every 1 hour)
2. **Action**: Send web request
   - URL: `https://api.nailinstitute.org/api/v1/cards?severity=critical,high&updated_since={{now.minusHours(1)}}`
   - Method: GET
   - Headers: `Accept: application/json`
3. **Branch**: For each item in `{{webResponse.body.cards}}`
4. **Condition**: JQL check — `project = AISEC AND "AVE ID" ~ "{{item.ave_id}}"` returns 0 results
5. **Action**: Create issue
   - Project: AISEC
   - Issue Type: Vulnerability
   - Summary: `[{{item.ave_id}}] {{item.name}}`
   - Description: (see template below)
   - Priority: Map from severity

### Method 2: Python Integration Script

```python
#!/usr/bin/env python3
"""Sync NAIL AVE cards to Jira as issues."""

import requests
from nail_ave_sdk import AVEClient
from nail_ave_sdk.state import StateTracker

# Configuration
JIRA_BASE = "https://your-org.atlassian.net"
JIRA_EMAIL = "your-email@company.com"
JIRA_API_TOKEN = "YOUR_API_TOKEN"
JIRA_PROJECT = "AISEC"

JIRA_AUTH = (JIRA_EMAIL, JIRA_API_TOKEN)
JIRA_HEADERS = {"Content-Type": "application/json"}

# Severity → Jira Priority mapping
PRIORITY_MAP = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

nail_client = AVEClient()
tracker = StateTracker("jira-integration")

def create_jira_issue(card):
    """Create a Jira issue from an AVE card."""
    
    # Check if issue already exists
    jql = f'project = {JIRA_PROJECT} AND "AVE ID" ~ "{card["ave_id"]}"'
    search = requests.get(
        f"{JIRA_BASE}/rest/api/3/search",
        auth=JIRA_AUTH,
        params={"jql": jql}
    )
    if search.json().get("total", 0) > 0:
        return None  # Already exists
    
    # Build description
    defences = "\n".join(f"* {d}" for d in card.get("defences", []))
    description = f"""h2. {card['name']}

*AVE ID*: [{card['ave_id']}|https://nailinstitute.org/ave/{card['ave_id']}]
*Category*: {card['category']}
*Severity*: {card['severity'].upper()}
*AVSS Score*: {card.get('avss_score', {}).get('base', 'N/A')}
*MITRE Mapping*: {card.get('mitre_mapping', 'N/A')}
*CWE*: {card.get('cwe_mapping', 'N/A')}

h3. Summary
{card['summary']}

h3. Mechanism
{card.get('mechanism', 'See AVE card for details.')}

h3. Recommended Defences
{defences}

h3. Blast Radius
{card.get('blast_radius', 'See AVE card for details.')}

----
_Auto-generated from NAIL AVE Database. See [full card|https://nailinstitute.org/ave/{card['ave_id']}]._
"""
    
    issue = requests.post(
        f"{JIRA_BASE}/rest/api/3/issue",
        auth=JIRA_AUTH,
        headers=JIRA_HEADERS,
        json={
            "fields": {
                "project": {"key": JIRA_PROJECT},
                "issuetype": {"name": "Bug"},
                "summary": f"[{card['ave_id']}] {card['name']}",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{"type": "paragraph", "content": [
                        {"type": "text", "text": description}
                    ]}]
                },
                "priority": {"name": PRIORITY_MAP.get(card["severity"], "Medium")},
                "labels": ["nail-ave", card["category"], f"severity-{card['severity']}"],
            }
        }
    )
    return issue.json().get("key")

def sync():
    last_sync = tracker.get_last_sync()
    cards = nail_client.get_cards(
        severity=["critical", "high"],
        updated_since=last_sync
    )
    
    created = 0
    for card in cards:
        key = create_jira_issue(card)
        if key:
            print(f"Created: {key} ← {card['ave_id']}")
            created += 1
    
    tracker.set_last_sync()
    print(f"Sync complete: {created} new issues from {len(cards)} cards")

if __name__ == "__main__":
    sync()
```

### Method 3: Jira Webhook (Push-Based)

Configure the NAIL AVE API to push notifications to a Jira webhook:

```bash
# Register webhook with NAIL API
curl -X POST https://api.nailinstitute.org/api/v1/webhooks \
  -H "Authorization: Bearer YOUR_NAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-org.atlassian.net/rest/api/3/issue",
    "events": ["card.created", "card.updated"],
    "filters": { "severity": ["critical", "high"] }
  }'
```

## Custom Fields

Create these custom fields in Jira for rich AVE data:

| Field Name | Field Type | Purpose |
|------------|-----------|---------|
| AVE ID | Short Text | Unique AVE identifier |
| AVSS Score | Number | Severity score (0–10) |
| AVE Category | Select List | AVE vulnerability category |
| Agent Frameworks | Labels/Multi-select | Affected frameworks |
| MITRE Mapping | Short Text | ATT&CK technique ID |
| CWE Mapping | Short Text | CWE identifier |
| Defence Status | Select List | Not Started / In Progress / Implemented / Verified |

## JQL Filters

### All Open AVE Issues
```jql
project = AISEC AND status != Done AND labels = nail-ave ORDER BY priority DESC
```

### Critical AVE Issues (SLA: 24 hours)
```jql
project = AISEC AND labels = nail-ave AND labels = severity-critical
AND status != Done AND created >= -24h
```

### AVE Issues by Category
```jql
project = AISEC AND labels = nail-ave AND labels = prompt_injection
```

### Overdue AVE Remediation
```jql
project = AISEC AND labels = nail-ave AND labels = severity-critical
AND status != Done AND created < -7d
```

### Framework-Specific Issues
```jql
project = AISEC AND labels = nail-ave AND "Agent Frameworks" = LangChain
```

### AVE Issues Missing Defences
```jql
project = AISEC AND labels = nail-ave AND "Defence Status" = "Not Started"
AND labels in (severity-critical, severity-high)
```

## Dashboards

### Dashboard: AI Security Vulnerability Tracker

| Gadget | Type | JQL |
|--------|------|-----|
| Open AVE Issues | Filter Results | `labels = nail-ave AND status != Done` |
| Severity Pie Chart | Pie Chart | `labels = nail-ave` grouped by priority |
| Category Bar Chart | Two-Dimensional Filter | `labels = nail-ave` grouped by AVE Category |
| Resolution Time | Average Age | `labels = nail-ave AND status = Done` |
| SLA Compliance | Filter Results | Critical issues resolved within 24h |
| Sprint Burndown | Agile Board | AVE issues in current sprint |

### Dashboard: AVE Remediation Progress

| Gadget | Data |
|--------|------|
| Total AVE Issues | Count of all nail-ave labelled issues |
| Defence Implementation Rate | % of issues with Defence Status = Implemented |
| Mean Time to Remediate | Average days from Created to Done |
| Framework Coverage Matrix | Issues by framework × category |
| Trending Categories | New issues per category per week |

## Jira Automation Rules

### Rule 1: Auto-Assign Critical AVE Issues

```
WHEN: Issue created
IF: labels contains "severity-critical" AND labels contains "nail-ave"
THEN: Assign to "AI Security Lead"
AND: Add comment "⚠️ Critical AVE vulnerability. SLA: 24 hours."
AND: Send Slack notification to #ai-security
```

### Rule 2: SLA Escalation

```
WHEN: Scheduled (every 4 hours)
IF: labels contains "severity-critical" AND labels contains "nail-ave"
    AND status != Done AND created < -24h
THEN: Set priority to "Blocker"
AND: Add comment "🚨 SLA breach — critical AVE issue open > 24 hours"
AND: Send email to engineering-managers@company.com
```

### Rule 3: Auto-Close on AVE Card Withdrawal

```
WHEN: Webhook received (NAIL AVE card.updated)
IF: status = "withdrawn"
THEN: Transition issue to "Done"
AND: Resolution = "Won't Fix"
AND: Add comment "AVE card withdrawn by NAIL Institute. Closing."
```

### Rule 4: Link Related AVE Issues

```
WHEN: Issue created with label "nail-ave"
IF: AVE card has related_aves field
THEN: For each related AVE ID, search and link issues
```

## Confluence Integration

Auto-publish AVE summaries to Confluence for wider visibility:

```python
def publish_to_confluence(card, confluence_space="AISEC"):
    """Create/update a Confluence page for an AVE card."""
    page_title = f"AVE: {card['ave_id']} — {card['name']}"
    
    body = f"""
    <h2>Vulnerability Details</h2>
    <table>
      <tr><td><strong>AVE ID</strong></td><td>{card['ave_id']}</td></tr>
      <tr><td><strong>Category</strong></td><td>{card['category']}</td></tr>
      <tr><td><strong>Severity</strong></td><td>{card['severity']}</td></tr>
      <tr><td><strong>AVSS Score</strong></td><td>{card.get('avss_score', {}).get('base', 'N/A')}</td></tr>
    </table>
    <h2>Summary</h2><p>{card['summary']}</p>
    <h2>Mechanism</h2><p>{card.get('mechanism', '')}</p>
    <h2>Defences</h2><ul>{''.join(f'<li>{d}</li>' for d in card.get('defences', []))}</ul>
    <h2>Jira Tracking</h2>
    <p><ac:structured-macro ac:name="jira">
      <ac:parameter ac:name="jqlQuery">labels = nail-ave AND "AVE ID" ~ "{card['ave_id']}"</ac:parameter>
    </ac:structured-macro></p>
    """
    
    requests.post(
        f"{JIRA_BASE}/wiki/rest/api/content",
        auth=JIRA_AUTH,
        json={
            "type": "page",
            "title": page_title,
            "space": {"key": confluence_space},
            "body": {"storage": {"value": body, "representation": "storage"}},
        }
    )
```

## Requirements

- Jira Cloud or Jira Data Center 9.x+
- Jira API token (Cloud) or personal access token (Data Center)
- Project with issue creation permissions
- Network access to `api.nailinstitute.org`
- Python 3.9+ (for sync script)
- Optional: Confluence (for knowledge base integration)
- Optional: Jira Automation (included in Jira Cloud Premium/Enterprise)

## Support

- **Docs**: This README
- **Issues**: GitHub issues on `ave-database`
- **Slack**: `#vendor-integrations`
- **Email**: vendor-integrations@nailinstitute.org
