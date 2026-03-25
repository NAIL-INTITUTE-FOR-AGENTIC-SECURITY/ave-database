# 🔐 Authentication Guide

## API Keys

All NAIL API requests require authentication via Bearer token.

### Getting Your API Key

**Community (Free)**:
```bash
curl -X POST https://api.nailinstitute.org/v2/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "plan": "community"}'
```

**Professional / Enterprise**: Contact sales@nailinstitute.org or sign up
at https://nailinstitute.org/api/pricing

### Using Your API Key

Include the key in the `Authorization` header:

```
Authorization: Bearer nail_live_abc123xyz789
```

### Key Format

| Environment | Prefix | Example |
|------------|--------|---------|
| Production | `nail_live_` | `nail_live_abc123xyz789` |
| Staging | `nail_test_` | `nail_test_abc123xyz789` |

### Managing Multiple Keys

Pro and Enterprise plans support multiple API keys with scoped permissions:

```bash
# Create a read-only key for CI/CD
curl -X POST https://api.nailinstitute.org/v2/auth/keys \
  -H "Authorization: Bearer nail_live_PRIMARY_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ci-pipeline",
    "scopes": ["read"],
    "expires_at": "2027-01-01T00:00:00Z"
  }'
```

### Available Scopes

| Scope | Description | Plans |
|-------|-------------|-------|
| `read` | Read cards, search, stats | All |
| `export` | Bulk export | Pro+ |
| `webhook` | Manage webhooks | Pro+ |
| `write` | Submit cards (when available) | Enterprise |
| `admin` | Manage keys, view usage | All |

### Key Rotation

We recommend rotating API keys every 90 days:

1. Create a new key with the same scopes
2. Update your applications to use the new key
3. Verify the new key works
4. Revoke the old key

### Security Best Practices

- **Never** commit API keys to version control
- Use environment variables: `NAIL_API_KEY`
- Use scoped keys with minimum required permissions
- Set expiration dates on keys
- Monitor usage via the `/auth/usage` endpoint
- Rotate keys regularly (90-day recommendation)
