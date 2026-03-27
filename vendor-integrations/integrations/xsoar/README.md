# Palo Alto XSOAR Integration for NAIL AVE Database

## Overview

Automate agentic AI vulnerability response with Cortex XSOAR — ingesting
NAIL AVE cards, enriching incidents with vulnerability context, and
executing remediation playbooks across your security stack.

## Architecture

```
NAIL AVE API ──► XSOAR Integration Instance
                        │
              ┌─────────┼──────────────┐
              │         │              │
         ┌────▼────┐ ┌─▼─────────┐ ┌─▼──────────┐
         │Incident │ │ Playbook  │ │ War Room   │
         │ Ingest  │ │ Execution │ │ & Reports  │
         └─────────┘ └───────────┘ └────────────┘
```

## Integration Setup

### Step 1: Create NAIL AVE Integration Instance

In XSOAR: Settings → Integrations → Add Instance

| Parameter | Value |
|-----------|-------|
| **Name** | NAIL AVE Database |
| **API URL** | `https://api.nailinstitute.org/api/v1` |
| **Fetch Incidents** | ✅ Enabled |
| **Incident Type** | NAIL AVE Vulnerability |
| **Fetch Interval** | 1 hour |
| **Severity Filter** | critical, high (configurable) |
| **First Fetch Time** | 30 days ago |

### Step 2: Create Incident Type

Create a custom incident type `NAIL AVE Vulnerability` with fields:

| Field | Type | Description |
|-------|------|-------------|
| `ave_id` | Short Text | AVE identifier |
| `ave_category` | Single Select | AVE category |
| `ave_severity` | Single Select | critical/high/medium/low |
| `avss_score` | Number | AVSS base score (0–10) |
| `mechanism` | Long Text | Attack mechanism description |
| `defences` | Long Text | Known defences |
| `affected_frameworks` | Tags | Agent frameworks affected |
| `mitre_mapping` | Short Text | MITRE ATT&CK technique ID |
| `cwe_mapping` | Short Text | CWE identifier |

### Step 3: Configure Classifier & Mapper

**Classifier**: Map incoming AVE data to incident type:
```json
{
  "NAIL AVE Vulnerability": {
    "filter": { "ave_id": { "$exists": true } }
  }
}
```

**Mapper (Incoming)**:
```json
{
  "name": { "simple": "name" },
  "severity": { "simple": "severity", "transformer": "MapSeverity" },
  "ave_id": { "simple": "ave_id" },
  "ave_category": { "simple": "category" },
  "avss_score": { "simple": "avss_score.base" },
  "mechanism": { "simple": "mechanism" },
  "defences": { "simple": "defences" },
  "mitre_mapping": { "simple": "mitre_mapping" }
}
```

## Commands

### Fetch Commands (Automatic)

| Command | Description |
|---------|-------------|
| `fetch-incidents` | Pulls new/updated AVE cards as XSOAR incidents |

### Manual Commands

| Command | Description | Example |
|---------|-------------|---------|
| `nail-ave-get-card` | Fetch a specific AVE card | `!nail-ave-get-card ave_id=AVE-2025-0001` |
| `nail-ave-search` | Search AVE database | `!nail-ave-search query="prompt injection"` |
| `nail-ave-list-cards` | List cards with filters | `!nail-ave-list-cards severity=critical category=prompt_injection` |
| `nail-ave-get-stats` | Get database statistics | `!nail-ave-get-stats` |
| `nail-ave-get-categories` | List all AVE categories | `!nail-ave-get-categories` |
| `nail-ave-enrich-indicator` | Enrich an indicator with AVE context | `!nail-ave-enrich-indicator value="LangChain"` |

### Command Output Example

```
!nail-ave-get-card ave_id=AVE-2025-0001

╔══════════════════════════════════════════════════════╗
║ AVE-2025-0001                                        ║
║ Prompt Injection via Indirect Context                ║
╠══════════════════════════════════════════════════════╣
║ Severity:   CRITICAL                                 ║
║ AVSS Score: 7.8                                      ║
║ Category:   prompt_injection                         ║
║ Status:     published                                ║
║ Published:  2025-03-15                               ║
╠══════════════════════════════════════════════════════╣
║ Summary:                                             ║
║ Indirect prompt injection through external data      ║
║ sources consumed by agentic systems...               ║
╠══════════════════════════════════════════════════════╣
║ Defences:                                            ║
║ • Input sanitisation on all external data            ║
║ • Instruction hierarchy enforcement                  ║
║ • Tool-call guardrails                               ║
║ • Output validation                                  ║
╠══════════════════════════════════════════════════════╣
║ MITRE: T1059    CWE: CWE-77                          ║
╚══════════════════════════════════════════════════════╝
```

## Playbooks

### Playbook 1: NAIL AVE — Triage & Assess

```yaml
name: NAIL AVE — Triage & Assess
description: Triage incoming AVE vulnerability cards and assess organisational impact.
starttaskid: "0"
tasks:
  "0":
    id: "0"
    taskid: start
    type: start
    nexttasks:
      "#none#": ["1"]
  "1":
    id: "1"
    taskid: enrich-card
    type: regular
    task:
      name: Enrich AVE Card
      script: nail-ave-get-card
      args:
        ave_id: ${incident.ave_id}
    nexttasks:
      "#none#": ["2"]
  "2":
    id: "2"
    taskid: check-severity
    type: condition
    task:
      name: Check Severity
    conditions:
      - label: Critical
        condition:
          - - left: { value: ${incident.severity} }
              operator: isEqualString
              right: { value: "critical" }
        nexttaskid: "3a"
      - label: High
        condition:
          - - left: { value: ${incident.severity} }
              operator: isEqualString
              right: { value: "high" }
        nexttaskid: "3b"
    defaultnexttaskid: "3c"
  "3a":
    id: "3a"
    taskid: critical-response
    type: playbook
    task:
      name: Execute Critical Response
      playbookName: NAIL AVE — Critical Response
  "3b":
    id: "3b"
    taskid: high-response
    type: regular
    task:
      name: Create Investigation
      script: createNewIncident
      args:
        type: Investigation
        name: "Investigate ${incident.ave_id}"
  "3c":
    id: "3c"
    taskid: standard-response
    type: regular
    task:
      name: Add to Vulnerability Queue
      script: setIncident
      args:
        owner: ai-security-team
```

### Playbook 2: NAIL AVE — Critical Response

```yaml
name: NAIL AVE — Critical Response
description: Immediate response for critical AVE vulnerabilities.
tasks:
  - name: Page AI Security Team
    type: notification
    config:
      channel: pagerduty
      severity: P1
      message: "🚨 Critical AVE: ${incident.ave_id} — ${incident.name}"

  - name: Identify Affected Systems
    type: manual
    description: |
      Check which systems in our environment use the affected
      agent frameworks or components.

  - name: Query CMDB for Agent Hosts
    type: regular
    script: ServiceNowQueryTable
    args:
      table: cmdb_ci_server
      query: "u_agent_frameworks LIKE '%${incident.affected_frameworks}%'"

  - name: Implement Emergency Mitigations
    type: manual
    description: |
      Apply the defences listed in the AVE card:
      ${incident.defences}

  - name: Create Change Request
    type: regular
    script: ServiceNowCreateTicket
    args:
      type: change_request
      short_description: "Remediate ${incident.ave_id}"
      priority: 1

  - name: Schedule 24hr Follow-Up
    type: timer
    args:
      duration: 24h
```

### Playbook 3: NAIL AVE — Supply Chain Alert

```yaml
name: NAIL AVE — Supply Chain Alert
description: Handle AVE cards in the supply_chain category.
tasks:
  - name: Extract Affected Components
    type: regular
    script: nail-ave-get-card
    args:
      ave_id: ${incident.ave_id}

  - name: Cross-Reference AI-SBOM
    type: regular
    description: Check AIBOM for affected dependencies.
    script: executeCommand
    args:
      command: "nail-ave-enrich-indicator"
      value: "${incident.affected_components}"

  - name: Scan Package Registries
    type: regular
    script: Snyk-ScanPackage
    args:
      package: "${incident.affected_components}"

  - name: Generate Dependency Report
    type: regular
    script: GenerateReport
    args:
      template: supply-chain-impact

  - name: Notify Procurement / Vendor Management
    type: notification
    config:
      channel: email
      recipients: vendor-management@company.com
```

## Indicator Enrichment

The integration enriches framework-related indicators:

```
Indicator: "LangChain"
Type: Software

Enrichment from NAIL AVE:
├── Total AVE cards affecting LangChain: 8
├── Critical: 2, High: 4, Medium: 2
├── Most recent: AVE-2025-0042 (2025-07-02)
├── Top categories: prompt_injection (3), tool_use (3), supply_chain (2)
└── Recommended defences: [list]
```

## Dashboard Widgets

| Widget | Type | Data |
|--------|------|------|
| Open AVE Incidents | Counter | Unresolved NAIL AVE incidents |
| Severity Breakdown | Pie chart | Incidents by severity |
| Category Trend | Line chart | New incidents by category over time |
| Mean Time to Resolve | Counter | Average resolution time for AVE incidents |
| Framework Exposure | Bar chart | Incidents per agent framework |
| Top Unresolved | Table | Highest AVSS score unresolved incidents |

## Requirements

- Cortex XSOAR 6.x+ (or XSOAR Cloud)
- NAIL AVE API access
- Network access to `api.nailinstitute.org`
- Optional: ServiceNow integration (for change requests)
- Optional: Snyk integration (for supply chain scanning)

## Support

- **Docs**: This README
- **Issues**: GitHub issues on `ave-database`
- **Slack**: `#vendor-integrations`
- **Email**: vendor-integrations@nailinstitute.org
