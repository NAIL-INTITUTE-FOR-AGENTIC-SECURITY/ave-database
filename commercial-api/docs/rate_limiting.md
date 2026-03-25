# ⏱️ Rate Limiting

## Limits by Plan

| Plan | Requests/Hour | Requests/Day | Burst |
|------|:------------:|:----------:|:-----:|
| Community | 100 | 1,000 | 10 |
| Professional | 10,000 | 100,000 | 100 |
| Enterprise | Unlimited | Unlimited | Unlimited |

## Response Headers

Every API response includes rate limit headers:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests in current window |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |
| `X-RateLimit-Plan` | Your current plan tier |

## Rate Limit Exceeded

When you exceed your rate limit, you'll receive a `429 Too Many Requests`:

```json
{
  "error": "rate_limit_exceeded",
  "message": "Rate limit exceeded. Please wait before making more requests.",
  "status": 429,
  "detail": "100 requests per hour limit reached",
  "retry_after": 1742
}
```

The `Retry-After` header tells you how many seconds to wait.

## Best Practices

1. **Cache responses** — AVE cards don't change frequently
2. **Use bulk endpoints** — Fetch multiple cards in one request (Pro+)
3. **Use webhooks** — Get push notifications instead of polling (Pro+)
4. **Use the diff endpoint** — Only fetch changes since last sync
5. **Implement exponential backoff** — For retry logic
6. **Monitor your usage** — Check `/auth/usage` regularly

## Rate Limit Increase

If you need higher limits:
- **Professional** → Contact support for temporary increases
- **Enterprise** → Custom limits included in your plan
