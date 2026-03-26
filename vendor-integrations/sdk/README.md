# NAIL AVE Integration SDK

Build custom integrations between the NAIL AVE Database and any security platform.

## Overview

The Integration SDK provides:
- **Python client** for the NAIL AVE API
- **Data transformers** for common output formats
- **Webhook receiver** for push-based integrations
- **CLI tool** for testing and debugging

## Installation

```bash
pip install nail-ave-sdk
```

Or install from source:
```bash
git clone https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database.git
cd ave-database/vendor-integrations/sdk
pip install -e .
```

## Quick Start

### Python Client

```python
from nail_ave_sdk import AVEClient

# Initialize client
client = AVEClient(base_url="https://api.nailinstitute.org/api/v1")

# Fetch all cards
cards = client.get_cards()

# Filter by severity
critical = client.get_cards(severity="critical")

# Filter by category
injections = client.get_cards(category="prompt_injection")

# Get a specific card
card = client.get_card("AVE-2025-0001")

# Search
results = client.search("multi-agent trust delegation")

# Get cards updated since a timestamp
updated = client.get_cards(updated_since="2025-06-01T00:00:00Z")
```

### Data Transformers

```python
from nail_ave_sdk import AVEClient
from nail_ave_sdk.transformers import (
    to_stix_bundle,
    to_csv,
    to_sarif,
    to_cef,
    to_syslog,
)

client = AVEClient()
cards = client.get_cards()

# STIX 2.1 Bundle
stix = to_stix_bundle(cards)

# CSV
csv_data = to_csv(cards)

# SARIF (for developer tools)
sarif = to_sarif(cards)

# CEF (Common Event Format — for SIEM)
cef_lines = to_cef(cards)

# Syslog format
syslog_lines = to_syslog(cards)
```

### Webhook Receiver

```python
from nail_ave_sdk.webhook import WebhookReceiver

def on_new_card(card):
    print(f"New AVE card: {card['ave_id']} — {card['name']}")
    # Your custom logic here: create ticket, send alert, etc.

def on_updated_card(card):
    print(f"Updated AVE card: {card['ave_id']}")

receiver = WebhookReceiver(
    port=8080,
    secret="your-webhook-secret",
    on_new=on_new_card,
    on_updated=on_updated_card,
)
receiver.start()
```

### CLI Tool

```bash
# List all cards
nail-ave list

# Get a specific card
nail-ave get AVE-2025-0001

# Search
nail-ave search "prompt injection"

# Export to STIX
nail-ave export --format stix --output ave-bundle.json

# Export critical cards to CSV
nail-ave list --severity critical --format csv > critical-aves.csv

# Watch for new cards (polling)
nail-ave watch --interval 300 --on-new "curl -X POST https://your-webhook/..."
```

## API Reference

### AVEClient

| Method | Description | Parameters |
|--------|-------------|------------|
| `get_cards(**filters)` | Fetch cards with optional filters | `severity`, `category`, `status`, `updated_since` |
| `get_card(ave_id)` | Fetch a single card | `ave_id` (str) |
| `search(query)` | Full-text search | `query` (str) |
| `get_categories()` | List all categories | — |
| `get_stats()` | Get database statistics | — |
| `health()` | Check API health | — |

### Transformers

| Function | Output Format | Use Case |
|----------|---------------|----------|
| `to_stix_bundle()` | STIX 2.1 JSON | Threat intelligence platforms |
| `to_csv()` | CSV string | Spreadsheets, data analysis |
| `to_sarif()` | SARIF JSON | Developer tools (VS Code, GitHub) |
| `to_cef()` | CEF strings | SIEM ingestion |
| `to_syslog()` | Syslog strings | Log management |
| `to_json_lines()` | JSON Lines | Stream processing |

## Building a Custom Integration

### Step 1: Fetch Data
```python
client = AVEClient()
cards = client.get_cards(severity="critical")
```

### Step 2: Transform
```python
# Transform to your platform's format
for card in cards:
    event = {
        "id": card["ave_id"],
        "title": card["name"],
        "severity": map_severity(card["severity"]),
        "description": card["summary"],
        # ... map to your platform's schema
    }
```

### Step 3: Send
```python
# Send to your platform
your_platform.create_alert(event)
```

### Step 4: Track State
```python
from nail_ave_sdk.state import StateTracker

tracker = StateTracker("my-integration")
last_sync = tracker.get_last_sync()
cards = client.get_cards(updated_since=last_sync)
# ... process cards
tracker.set_last_sync()
```

## Examples

See the `examples/` directory:
- `examples/slack_alerter.py` — Send new AVE cards to Slack
- `examples/jira_creator.py` — Create Jira tickets for critical cards
- `examples/email_digest.py` — Daily email digest of new cards
- `examples/custom_siem.py` — Generic SIEM integration template

## Contributing

We welcome new integration adapters! See [CONTRIBUTING.md](../../CONTRIBUTING.md)
for guidelines on submitting vendor integrations.

## License

Apache 2.0
