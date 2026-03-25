# 🔔 NAIL Institute — Webhook Documentation

> Real-time event notifications for Pro and Enterprise API plans.

## Overview

Webhooks allow your application to receive real-time notifications
when events occur in the AVE database. Instead of polling the API,
you can subscribe to specific events and receive HTTP POST callbacks.

## Events

| Event | Description | Tier |
|-------|-------------|------|
| `ave.new` | New AVE card published | Pro+ |
| `ave.updated` | Existing card updated | Pro+ |
| `ave.deprecated` | Card deprecated | Pro+ |
| `advisory.published` | Security advisory published | Pro+ |
| `certification.issued` | New certification issued | Enterprise |

## Setup

```python
from nail_api import NailClient

client = NailClient(api_key="your-key")

webhook = client.webhooks.create(
    url="https://your-app.com/hooks/nail",
    events=["ave.new", "ave.updated"],
)
print(f"Webhook ID: {webhook.id}")
print(f"Signing Secret: {webhook.secret}")  # Save this!
```

## Payload Format

All webhook payloads follow this structure:

```json
{
  "id": "evt_abc123",
  "event": "ave.new",
  "timestamp": "2026-03-25T12:00:00Z",
  "data": { ... }
}
```

## Signature Verification

All payloads are signed with HMAC-SHA256. Verify the signature
to ensure the webhook came from NAIL:

```python
import hmac
import hashlib

def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)

# In your webhook handler:
signature = request.headers["X-NAIL-Signature"]
is_valid = verify_signature(request.body, signature, webhook_secret)
```

## Retry Policy

| Attempt | Delay |
|---------|-------|
| 1st retry | 1 minute |
| 2nd retry | 5 minutes |
| 3rd retry | 30 minutes |
| 4th retry | 2 hours |
| 5th retry | 12 hours |

After 5 failed attempts, the webhook is marked as `failing` and
you'll receive an email notification. After 72 hours of failures,
the webhook is automatically disabled.

## Response Requirements

- Return `2xx` status within 10 seconds
- Non-2xx responses trigger a retry
- Timeouts (>10s) trigger a retry
- Duplicate delivery is possible — use `id` for idempotency

## Payload Schemas

See the `schemas/` directory for JSON Schema definitions of each event type.
