# 🔄 Migration Guide: v1 → v2

## Overview

API v2 introduces tiered access, webhooks, bulk export, and enterprise
features while maintaining backward compatibility for core card operations.

## Breaking Changes

### URL Base Path
```
# v1 (deprecated)
https://api.nailinstitute.org/v1/cards

# v2
https://api.nailinstitute.org/v2/cards
```

### Authentication
```
# v1 — no authentication required for public endpoints
curl https://api.nailinstitute.org/v1/cards

# v2 — all endpoints require API key
curl https://api.nailinstitute.org/v2/cards \
  -H "Authorization: Bearer YOUR_API_KEY"
```

### Pagination
```json
// v1 — offset-based
{"cards": [...], "total": 50, "offset": 0, "limit": 20}

// v2 — page-based with standard headers
{"cards": [...], "pagination": {"page": 1, "per_page": 20, "total": 50, "total_pages": 3}}
```

### Response Envelope
```json
// v1 — array response
[{"ave_id": "AVE-2024-001", ...}]

// v2 — envelope with metadata
{"cards": [{"ave_id": "AVE-2024-001", ...}], "pagination": {...}}
```

## Migration Steps

### 1. Register for API Key
All v2 requests require authentication. Register for free:
```bash
curl -X POST https://api.nailinstitute.org/v2/auth/register \
  -d '{"email": "you@example.com"}'
```

### 2. Update Base URL
Change `v1` → `v2` in all API calls.

### 3. Add Authorization Header
Add `Authorization: Bearer YOUR_KEY` to all requests.

### 4. Update Response Parsing
Card list responses are now wrapped in `{"cards": [...]}`.

### 5. Update Pagination Logic
Switch from `offset`/`limit` to `page`/`per_page`.

## v1 Deprecation Timeline

| Date | Action |
|------|--------|
| March 2026 | v2 launched |
| June 2026 | v1 deprecated (warning headers added) |
| September 2026 | v1 rate limits reduced to 10 req/hr |
| December 2026 | v1 shut down |

## Need Help?

- Email: api@nailinstitute.org
- GitHub Discussions: [API category](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database/discussions)
