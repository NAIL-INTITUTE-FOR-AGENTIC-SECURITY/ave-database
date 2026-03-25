# NAIL Institute Python SDK

> Official Python client for the NAIL Institute AVE API.

## Installation

```bash
pip install nail-api
```

## Quick Start

```python
from nail_api import NailClient

client = NailClient(api_key="your-api-key")

# List all critical vulnerabilities
cards = client.cards.list(severity="critical")
for card in cards:
    print(f"{card.ave_id}: {card.name}")

# Get a specific card
card = client.cards.get("AVE-2024-001")
print(card.summary)

# Search
results = client.cards.search("prompt injection", category="prompt_injection")

# Bulk export (Pro+)
job = client.export.create(format="csv", filters={"severity": "critical"})
job.wait()  # Blocks until export completes
job.download("critical_cards.csv")

# Webhooks (Pro+)
webhook = client.webhooks.create(
    url="https://your-app.com/hooks",
    events=["ave.new", "ave.updated"]
)

# Risk scoring (Enterprise)
score = client.risk.score(
    system={"name": "MyAgent", "industry": "finance", "agent_count": 5}
)
print(f"Risk Grade: {score.grade}")
```

## Package Status

**Status**: Planned — SDK will be published to PyPI upon commercial API launch.

## API Reference

See the [OpenAPI specification](../openapi/openapi-v2.yaml) for full endpoint documentation.
