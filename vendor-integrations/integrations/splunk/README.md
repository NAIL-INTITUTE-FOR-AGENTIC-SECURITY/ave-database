# Splunk Integration for NAIL AVE Database

## Overview

Ingest, search, and alert on NAIL AVE agentic AI vulnerability data directly
within your Splunk deployment.

## Architecture

```
NAIL AVE API ──► Splunk HTTP Event Collector (HEC)
                        │
                 ┌──────▼──────┐
                 │  index=nail  │
                 │  sourcetype= │
                 │  nail:ave    │
                 └──────┬──────┘
                        │
              ┌─────────┼─────────┐
              │         │         │
         ┌────▼──┐ ┌───▼───┐ ┌──▼─────┐
         │Search │ │Alerts │ │Dashboard│
         └───────┘ └───────┘ └────────┘
```

## Quick Start

### 1. Create an Index

```
# In Splunk Web: Settings > Indexes > New Index
# Or via CLI:
splunk add index nail
```

### 2. Configure HEC Token

```
# Settings > Data Inputs > HTTP Event Collector > New Token
# Name: nail-ave-ingestion
# Index: nail
# Sourcetype: nail:ave
```

### 3. Ingest AVE Data

Use the provided ingestion script:

```bash
# Install dependencies
pip install requests

# Run the ingestion script
python splunk_ingest.py \
  --hec-url https://your-splunk:8088 \
  --hec-token YOUR_HEC_TOKEN \
  --nail-api https://api.nailinstitute.org/api/v1
```

### 4. Search AVE Data

```spl
index=nail sourcetype="nail:ave"
| table ave_id, name, category, severity, date_published
| sort -date_published
```

## Sample Searches

### All Critical AVE Cards
```spl
index=nail sourcetype="nail:ave" severity="critical"
| table ave_id, name, category, mechanism
```

### AVE Cards by Category (Timechart)
```spl
index=nail sourcetype="nail:ave"
| timechart count by category
```

### New AVE Cards in Last 7 Days
```spl
index=nail sourcetype="nail:ave" date_published > relative_time(now(), "-7d")
| table ave_id, name, severity, summary
```

### Match AVE Cards to Your Agent Stack
```spl
index=nail sourcetype="nail:ave"
| where match(environment.agent_frameworks, "LangChain|AutoGen|CrewAI")
| table ave_id, name, severity, defences
```

### AVSS Score Distribution
```spl
index=nail sourcetype="nail:ave"
| stats avg(avss_score.base) as avg_score, max(avss_score.base) as max_score by category
| sort -avg_score
```

## Alerts

### Alert: New Critical AVE Card Published
```spl
index=nail sourcetype="nail:ave" severity="critical"
| where _time > relative_time(now(), "-1h")
| table ave_id, name, summary
```
- **Schedule**: Every 1 hour
- **Trigger**: Number of results > 0
- **Action**: Send email / PagerDuty / Slack

### Alert: AVE Card Matches Your Stack
```spl
index=nail sourcetype="nail:ave"
| where _time > relative_time(now(), "-24h")
| where match(environment.agent_frameworks, "YOUR_FRAMEWORK_HERE")
| table ave_id, name, severity, defences
```
- **Schedule**: Every 24 hours
- **Trigger**: Number of results > 0
- **Action**: Create incident ticket

## Dashboard (JSON)

A sample dashboard definition is provided in `dashboard.json`. Import via:
Splunk Web > Dashboards > Create New Dashboard > Source > paste JSON.

## Ingestion Script

See `splunk_ingest.py` for the full ingestion script that:
- Fetches AVE cards from the NAIL API
- Transforms to Splunk HEC format
- Sends via HTTP Event Collector
- Supports incremental ingestion (only new/updated cards)
- Configurable polling interval

## Requirements

- Splunk Enterprise 8.x+ or Splunk Cloud
- HTTP Event Collector enabled
- Network access to `api.nailinstitute.org`
- Python 3.9+ (for ingestion script)

## Support

- **Docs**: This README
- **Issues**: Open a GitHub issue on `ave-database`
- **Slack**: `#vendor-integrations`
- **Email**: vendor-integrations@nailinstitute.org
