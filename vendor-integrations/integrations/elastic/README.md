# Elastic Security Integration for NAIL AVE Database

## Overview

Ingest, search, and visualise NAIL AVE agentic AI vulnerability data within
Elastic Security (Elasticsearch + Kibana), enabling correlation with existing
detection rules, SIEM alerts, and threat-hunting workflows.

## Architecture

```
NAIL AVE API ──► Elastic Agent / Logstash / Python Script
                        │
                 ┌──────▼────────────┐
                 │  Elasticsearch     │
                 │  index: nail-ave-* │
                 │  ILM: hot→warm→cold│
                 └──────┬────────────┘
                        │
              ┌─────────┼─────────────┐
              │         │             │
         ┌────▼──┐ ┌───▼────┐  ┌────▼────────┐
         │  KQL  │ │Detect. │  │  Kibana      │
         │Search │ │ Rules  │  │  Dashboards  │
         └───────┘ └────────┘  └──────────────┘
```

## Quick Start

### Option A: Elastic Agent Custom Integration

1. **Create Fleet Integration Policy**
   - Kibana → Fleet → Integrations → Create custom integration
   - Name: `NAIL AVE Database`
   - Input: HTTP JSON input
   - URL: `https://api.nailinstitute.org/api/v1/cards`
   - Interval: `1h`
   - Index: `nail-ave-cards`

2. **Apply to Elastic Agent**
   - Fleet → Agent policies → Add integration
   - Select the NAIL AVE integration

### Option B: Logstash Pipeline

```ruby
# /etc/logstash/conf.d/nail-ave.conf

input {
  http_poller {
    urls => {
      nail_ave => {
        method => get
        url => "https://api.nailinstitute.org/api/v1/cards"
        headers => {
          "Accept" => "application/json"
        }
      }
    }
    schedule => { cron => "0 * * * *" }  # Every hour
    codec => "json"
  }
}

filter {
  split {
    field => "cards"
  }

  mutate {
    rename => {
      "[cards][ave_id]" => "ave_id"
      "[cards][name]" => "vulnerability_name"
      "[cards][category]" => "category"
      "[cards][severity]" => "severity"
      "[cards][status]" => "status"
      "[cards][summary]" => "summary"
      "[cards][mechanism]" => "mechanism"
      "[cards][avss_score][base]" => "avss_score"
      "[cards][date_published]" => "date_published"
    }
  }

  date {
    match => ["date_published", "ISO8601"]
    target => "@timestamp"
  }

  # Enrich with severity level for Elastic Common Schema
  if [severity] == "critical" {
    mutate { add_field => { "event.severity" => 1 } }
  } else if [severity] == "high" {
    mutate { add_field => { "event.severity" => 2 } }
  } else if [severity] == "medium" {
    mutate { add_field => { "event.severity" => 3 } }
  } else {
    mutate { add_field => { "event.severity" => 4 } }
  }
}

output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    index => "nail-ave-%{+YYYY.MM}"
    user => "elastic"
    password => "${ES_PASSWORD}"
    ssl_certificate_verification => true
  }
}
```

### Option C: Python Ingestion Script

```bash
pip install elasticsearch requests

python elastic_ingest.py \
  --es-url https://localhost:9200 \
  --es-user elastic \
  --es-pass YOUR_PASSWORD \
  --nail-api https://api.nailinstitute.org/api/v1
```

## Index Template

Apply the index template before first ingestion:

```json
{
  "index_patterns": ["nail-ave-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.lifecycle.name": "nail-ave-ilm",
      "index.lifecycle.rollover_alias": "nail-ave"
    },
    "mappings": {
      "properties": {
        "ave_id":          { "type": "keyword" },
        "vulnerability_name": { "type": "text", "fields": { "keyword": { "type": "keyword" }}},
        "category":        { "type": "keyword" },
        "severity":        { "type": "keyword" },
        "status":          { "type": "keyword" },
        "summary":         { "type": "text" },
        "mechanism":       { "type": "text" },
        "avss_score":      { "type": "float" },
        "date_published":  { "type": "date" },
        "defences":        { "type": "text" },
        "cwe_mapping":     { "type": "keyword" },
        "mitre_mapping":   { "type": "keyword" },
        "environment.agent_frameworks": { "type": "keyword" },
        "event.severity":  { "type": "integer" }
      }
    }
  }
}
```

## KQL Queries (Kibana)

### All AVE Cards
```
ave_id: *
```

### Critical Vulnerabilities
```
severity: "critical"
```

### Cards Matching Your Agent Stack
```
environment.agent_frameworks: ("LangChain" OR "CrewAI" OR "AutoGen")
```

### New Cards in Last 7 Days
```
date_published >= now-7d
```

### Category: Prompt Injection
```
category: "prompt_injection" AND severity: ("critical" OR "high")
```

## ES|QL Queries (Elastic 8.11+)

```esql
FROM nail-ave-*
| WHERE severity == "critical"
| STATS count = COUNT(*) BY category
| SORT count DESC
```

```esql
FROM nail-ave-*
| WHERE date_published >= NOW() - 30 days
| KEEP ave_id, vulnerability_name, severity, avss_score
| SORT avss_score DESC
| LIMIT 20
```

## Detection Rules

### Rule: New Critical AVE Card

```json
{
  "name": "NAIL AVE — New Critical Vulnerability",
  "description": "Alert when a new critical AVE card is published",
  "risk_score": 73,
  "severity": "high",
  "type": "query",
  "query": "severity: \"critical\" AND date_published >= now-1h",
  "index": ["nail-ave-*"],
  "interval": "1h",
  "actions": [
    {
      "action_type_id": ".slack",
      "params": { "message": "🚨 New critical AVE card: {{context.rule.name}}" }
    }
  ]
}
```

### Rule: AVE Card Affects Deployed Framework

```json
{
  "name": "NAIL AVE — Vulnerability in Deployed Framework",
  "description": "Alert when AVE card matches an agent framework in use",
  "risk_score": 50,
  "severity": "medium",
  "type": "query",
  "query": "environment.agent_frameworks: (\"LangChain\" OR \"AutoGen\") AND date_published >= now-24h",
  "index": ["nail-ave-*"],
  "interval": "24h"
}
```

### Rule: High AVSS Score Surge

```json
{
  "name": "NAIL AVE — High AVSS Score Cluster",
  "description": "Alert when multiple high-scoring cards appear in a short period",
  "risk_score": 65,
  "severity": "high",
  "type": "threshold",
  "query": "avss_score >= 7.0 AND date_published >= now-7d",
  "threshold": { "field": [], "value": 3, "cardinality": [] },
  "index": ["nail-ave-*"],
  "interval": "24h"
}
```

## Kibana Dashboard

Import the provided dashboard from `dashboard.ndjson`:

```bash
curl -X POST "https://localhost:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  --form file=@dashboard.ndjson
```

### Dashboard Panels

| Panel | Type | Description |
|-------|------|-------------|
| AVE Card Count by Severity | Donut chart | Severity distribution |
| New Cards Timeline | Area chart | Publication rate over time |
| Top Categories | Horizontal bar | Most common vulnerability categories |
| AVSS Score Distribution | Histogram | Score frequency distribution |
| Framework Exposure Matrix | Heatmap | Categories × frameworks |
| Latest Critical Cards | Table | Most recent critical vulnerabilities |
| AVSS Trend | Line chart | Average AVSS score over time |

## Index Lifecycle Management (ILM)

```json
{
  "policy": {
    "phases": {
      "hot":   { "actions": { "rollover": { "max_size": "10gb", "max_age": "30d" }}},
      "warm":  { "min_age": "30d", "actions": { "shrink": { "number_of_shards": 1 }}},
      "cold":  { "min_age": "90d", "actions": { "searchable_snapshot": { "snapshot_repository": "nail-snapshots" }}},
      "delete": { "min_age": "365d", "actions": { "delete": {} }}
    }
  }
}
```

## Elastic Common Schema (ECS) Mapping

| AVE Field | ECS Field | Notes |
|-----------|-----------|-------|
| `ave_id` | `vulnerability.id` | Primary identifier |
| `name` | `vulnerability.description` | Vulnerability name |
| `severity` | `vulnerability.severity` | critical/high/medium/low |
| `avss_score` | `vulnerability.score.base` | AVSS numeric score |
| `category` | `vulnerability.category` | AVE category |
| `mechanism` | `threat.technique.name` | Attack mechanism |
| `mitre_mapping` | `threat.technique.id` | MITRE ATT&CK ID |
| `defences` | `vulnerability.remediation` | Defence recommendations |

## Requirements

- Elasticsearch 8.x+ (or Elastic Cloud)
- Kibana 8.x+
- Logstash 8.x+ (if using Logstash pipeline)
- Elastic Agent (if using Fleet integration)
- Network access to `api.nailinstitute.org`

## Support

- **Docs**: This README
- **Issues**: GitHub issues on `ave-database`
- **Slack**: `#vendor-integrations`
- **Email**: vendor-integrations@nailinstitute.org
