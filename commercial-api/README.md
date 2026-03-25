# 💰 NAIL Institute — Commercial API Platform

> Enterprise-grade API access with tiered plans, SLAs, webhooks,
> and bulk export capabilities.

## Overview

The NAIL Commercial API extends the existing public API with enterprise
features for organisations that need guaranteed availability, higher
throughput, real-time notifications, and advanced data access.

## API Tiers

| Feature | Community (Free) | Professional | Enterprise |
|---------|:----------------:|:------------:|:----------:|
| **Rate Limit** | 100 req/hr | 10,000 req/hr | Unlimited |
| **AVE Card Access** | ✅ Full | ✅ Full | ✅ Full |
| **Search & Filter** | ✅ Basic | ✅ Advanced | ✅ Advanced + Custom |
| **Bulk Export** | ❌ | ✅ JSON/CSV | ✅ All formats |
| **Webhooks** | ❌ | 5 endpoints | Unlimited |
| **AVSS Scoring API** | ❌ | ✅ | ✅ + Custom models |
| **Certification API** | ❌ | ✅ Read-only | ✅ Full access |
| **Insurance Risk API** | ❌ | ❌ | ✅ |
| **Regulatory Mapping** | ❌ | ✅ Read-only | ✅ + Custom mappings |
| **SLA** | Best effort | 99.5% uptime | 99.9% uptime |
| **Support** | Community | Email (48h) | Dedicated (4h) |
| **API Keys** | 1 | 5 | Unlimited |
| **Analytics Dashboard** | ❌ | ✅ Basic | ✅ Advanced |
| **SSO/SAML** | ❌ | ❌ | ✅ |
| **Custom Domain** | ❌ | ❌ | ✅ |
| **Price** | Free | $299/mo | Custom |

## Directory Structure

```
commercial-api/
├── README.md                  ← This file
├── openapi/
│   └── openapi-v2.yaml        ← OpenAPI 3.1 specification
├── config/
│   ├── tiers.yaml             ← Tier definitions and limits
│   ├── pricing.yaml           ← Pricing models and billing
│   └── sla.yaml               ← SLA definitions
├── webhooks/
│   ├── README.md              ← Webhook documentation
│   └── schemas/               ← Webhook payload schemas
│       ├── ave.new.json
│       ├── ave.updated.json
│       ├── ave.deprecated.json
│       ├── advisory.published.json
│       └── certification.issued.json
├── sdk/
│   ├── python/                ← Python SDK stub
│   │   ├── README.md
│   │   └── nail_api/__init__.py
│   └── typescript/            ← TypeScript SDK stub
│       ├── README.md
│       └── src/index.ts
├── examples/
│   ├── python_quickstart.py
│   └── curl_examples.sh
└── docs/
    ├── authentication.md
    ├── rate_limiting.md
    ├── bulk_export.md
    └── migration_guide.md
```

## Quick Start

### Community (Free)
```bash
# Get an API key
curl -X POST https://api.nailinstitute.org/v2/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "plan": "community"}'

# Fetch an AVE card
curl https://api.nailinstitute.org/v2/cards/AVE-2024-001 \
  -H "Authorization: Bearer YOUR_API_KEY"
```

### Professional / Enterprise
```python
from nail_api import NailClient

client = NailClient(api_key="your-key")

# Search cards
results = client.cards.search(category="prompt_injection", severity="critical")

# Set up webhooks
client.webhooks.create(
    url="https://your-app.com/hooks/nail",
    events=["ave.new", "ave.updated", "advisory.published"]
)

# Bulk export
export = client.export.create(format="csv", filters={"severity": "critical"})
```

## API Endpoints (v2)

See the full [OpenAPI specification](openapi/openapi-v2.yaml) for details.

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v2/auth/register` | Create account and API key |
| POST | `/v2/auth/keys` | Generate additional API keys |
| DELETE | `/v2/auth/keys/{key_id}` | Revoke an API key |
| GET | `/v2/auth/usage` | View usage statistics |

### Cards (Enhanced)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v2/cards` | List/search cards with advanced filters |
| GET | `/v2/cards/{ave_id}` | Get card details |
| GET | `/v2/cards/bulk` | Bulk fetch (Pro+) |
| POST | `/v2/cards/export` | Async bulk export (Pro+) |
| GET | `/v2/cards/diff` | Changes since timestamp |

### Webhooks (Pro+)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v2/webhooks` | List webhooks |
| POST | `/v2/webhooks` | Create webhook |
| PATCH | `/v2/webhooks/{id}` | Update webhook |
| DELETE | `/v2/webhooks/{id}` | Delete webhook |
| POST | `/v2/webhooks/{id}/test` | Send test event |

### Enterprise
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v2/risk/score` | Calculate risk score |
| POST | `/v2/compliance/map` | Map to regulatory framework |
| GET | `/v2/certification/verify/{cert_id}` | Verify certification |
| POST | `/v2/analytics/query` | Custom analytics query |

## Links

- [Authentication Guide](docs/authentication.md)
- [Rate Limiting](docs/rate_limiting.md)
- [Bulk Export Guide](docs/bulk_export.md)
- [Migration from v1](docs/migration_guide.md)
- [Webhook Documentation](webhooks/README.md)

---

*NAIL Institute — Neuravant AI Limited*
