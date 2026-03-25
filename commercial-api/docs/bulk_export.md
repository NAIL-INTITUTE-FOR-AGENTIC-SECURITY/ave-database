# 📦 Bulk Export Guide

> Available on Professional and Enterprise plans.

## Overview

The bulk export API lets you download the entire AVE database or filtered
subsets in multiple formats for offline analysis, compliance reporting,
or integration with your security tools.

## Supported Formats

| Format | Extension | Description | Plans |
|--------|-----------|-------------|-------|
| JSON | `.json` | Full AVE card objects | Pro+ |
| CSV | `.csv` | Flat tabular format | Pro+ |
| YAML | `.yaml` | Human-readable format | Enterprise |
| SARIF | `.sarif` | Static analysis format | Enterprise |

## Creating an Export

Exports are asynchronous — you create a job and poll for completion.

```bash
# Create export job
curl -X POST https://api.nailinstitute.org/v2/cards/export \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "csv",
    "filters": {
      "severity": ["critical", "high"],
      "category": ["prompt_injection", "tool_misuse"]
    }
  }'

# Response
{
  "job_id": "exp_abc123",
  "status": "queued",
  "created_at": "2026-03-25T12:00:00Z"
}
```

## Checking Status

```bash
curl https://api.nailinstitute.org/v2/cards/export/exp_abc123 \
  -H "Authorization: Bearer YOUR_KEY"

# Response (completed)
{
  "job_id": "exp_abc123",
  "status": "completed",
  "format": "csv",
  "created_at": "2026-03-25T12:00:00Z",
  "completed_at": "2026-03-25T12:00:15Z",
  "download_url": "https://api.nailinstitute.org/v2/cards/export/exp_abc123/download",
  "expires_at": "2026-03-26T12:00:00Z",
  "record_count": 23,
  "file_size_bytes": 45678
}
```

## Downloading

```bash
curl -L -o critical_cards.csv \
  https://api.nailinstitute.org/v2/cards/export/exp_abc123/download \
  -H "Authorization: Bearer YOUR_KEY"
```

## Filter Options

| Filter | Type | Description |
|--------|------|-------------|
| `category` | string[] | Filter by AVE categories |
| `severity` | string[] | Filter by severity levels |
| `status` | string[] | Filter by card status |
| `since` | datetime | Cards added/updated since |
| `include_fields` | string[] | Only include specified fields |

## Export Limits

| Plan | Max Records | Max File Size | Concurrent Jobs | Download Expiry |
|------|:-----------:|:-------------:|:---------------:|:---------------:|
| Professional | 10,000 | 50 MB | 3 | 24 hours |
| Enterprise | Unlimited | 500 MB | 10 | 7 days |

## Incremental Sync

For keeping a local copy in sync, use the diff endpoint instead:

```bash
curl "https://api.nailinstitute.org/v2/cards/diff?since=2026-03-01T00:00:00Z" \
  -H "Authorization: Bearer YOUR_KEY"
```

This returns only cards that were added, updated, or deprecated since the
given timestamp — much more efficient than full exports.
