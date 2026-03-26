# Microsoft Sentinel Integration for NAIL AVE Database

## Overview

Ingest NAIL AVE agentic AI vulnerability data into Microsoft Sentinel for
correlation with existing security alerts, automated investigation, and
compliance reporting.

## Architecture

```
NAIL AVE API ──► Azure Logic App / Function
                        │
                 ┌──────▼──────────┐
                 │  Log Analytics   │
                 │  Workspace       │
                 │  Table: NAIL_AVE │
                 └──────┬──────────┘
                        │
              ┌─────────┼─────────┐
              │         │         │
         ┌────▼──┐ ┌───▼───┐ ┌──▼─────────┐
         │  KQL  │ │Analyt.│ │  Workbooks  │
         │Search │ │ Rules │ │(Dashboards) │
         └───────┘ └───────┘ └────────────┘
```

## Quick Start

### Option A: Azure Logic App (No-Code)

1. **Create Logic App**
   - Azure Portal > Logic Apps > Create
   - Trigger: Recurrence (every 1 hour)

2. **Add HTTP Action**
   ```
   Method: GET
   URI: https://api.nailinstitute.org/api/v1/cards
   Headers: Accept: application/json
   ```

3. **Add "Send Data" Action** (Azure Log Analytics Data Collector)
   - Workspace ID: `<your-workspace-id>`
   - Primary Key: `<your-workspace-key>`
   - Custom Log Name: `NAIL_AVE`
   - JSON body: `@body('HTTP')`

### Option B: Azure Function (Code)

Deploy the provided Azure Function for more control:

```bash
cd sentinel-function/
func azure functionapp publish <your-function-app>
```

See `sentinel-function/` directory for the complete Azure Function implementation.

### Option C: Data Connector (Coming Soon)

A native Sentinel Data Connector is planned for 2025-Q4.

## KQL Queries

### All AVE Cards
```kql
NAIL_AVE_CL
| project AVE_ID = ave_id_s, Name = name_s, Category = category_s,
          Severity = severity_s, Published = date_published_s
| sort by Published desc
```

### Critical Vulnerabilities
```kql
NAIL_AVE_CL
| where severity_s == "critical"
| project AVE_ID = ave_id_s, Name = name_s, Category = category_s,
          Summary = summary_s, AVSS = avss_score_base_d
| sort by AVSS desc
```

### AVE Cards Matching Your Agent Frameworks
```kql
let myFrameworks = dynamic(["LangChain", "AutoGen", "CrewAI"]);
NAIL_AVE_CL
| mv-expand framework = parse_json(environment_agent_frameworks_s)
| where framework in (myFrameworks)
| project AVE_ID = ave_id_s, Name = name_s, Severity = severity_s,
          Framework = tostring(framework)
```

### New Cards in Last 24 Hours
```kql
NAIL_AVE_CL
| where TimeGenerated > ago(24h)
| project AVE_ID = ave_id_s, Name = name_s, Severity = severity_s, Summary = summary_s
```

### Category Distribution
```kql
NAIL_AVE_CL
| summarize count() by category_s
| render piechart
```

### AVSS Score Trend
```kql
NAIL_AVE_CL
| summarize avg(avss_score_base_d) by bin(todatetime(date_published_s), 30d)
| render timechart
```

## Analytics Rules

### Rule: New Critical AVE Card

```kql
NAIL_AVE_CL
| where TimeGenerated > ago(1h)
| where severity_s == "critical"
| project AVE_ID = ave_id_s, Name = name_s, Summary = summary_s
```

- **Frequency**: Every 1 hour
- **Severity**: High
- **Tactics**: Initial Access, Execution
- **Entity Mapping**: Map `ave_id_s` to custom entity

### Rule: AVE Card Matches Deployed Agent Framework

```kql
let deployedFrameworks = dynamic(["LangChain", "AutoGen"]);
NAIL_AVE_CL
| where TimeGenerated > ago(24h)
| mv-expand framework = parse_json(environment_agent_frameworks_s)
| where framework in (deployedFrameworks)
| project AVE_ID = ave_id_s, Name = name_s, Severity = severity_s,
          Framework = tostring(framework), Defences = defences_s
```

- **Frequency**: Every 24 hours
- **Severity**: Medium
- **Automated Response**: Create incident, assign to AI Security team

## Workbook (Dashboard)

Import the provided workbook template from `workbook.json`:
1. Sentinel > Workbooks > Add Workbook > Advanced Editor
2. Paste contents of `workbook.json`
3. Save

### Dashboard Panels
- Total AVE cards by severity (donut chart)
- New cards timeline (time chart)
- Category distribution (bar chart)
- Top 10 highest AVSS scores (table)
- Framework coverage matrix (heatmap)

## Requirements

- Microsoft Sentinel workspace (any tier)
- Log Analytics workspace with custom logs enabled
- Azure Logic App or Function App for ingestion
- Network access to `api.nailinstitute.org`

## Cost Estimate

| Component | Estimated Cost |
|-----------|---------------|
| Data ingestion | ~$2.76/GB (Sentinel analytics tier) |
| AVE data volume | ~1-5 MB/month (minimal) |
| Logic App runs | ~$0.01/run × 720 runs/mo = ~$7.20/mo |
| **Total estimate** | **< $10/month** |

## Support

- **Docs**: This README
- **Issues**: GitHub issues on `ave-database`
- **Slack**: `#vendor-integrations`
- **Email**: vendor-integrations@nailinstitute.org
