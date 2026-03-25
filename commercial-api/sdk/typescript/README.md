# NAIL Institute TypeScript SDK

> Official TypeScript/JavaScript client for the NAIL Institute AVE API.

## Installation

```bash
npm install @nail-institute/api
```

## Quick Start

```typescript
import { NailClient } from '@nail-institute/api';

const client = new NailClient({ apiKey: 'your-api-key' });

// List all critical vulnerabilities
const cards = await client.cards.list({ severity: 'critical' });
cards.forEach(card => console.log(`${card.aveId}: ${card.name}`));

// Get a specific card
const card = await client.cards.get('AVE-2024-001');
console.log(card.summary);

// Webhooks (Pro+)
const webhook = await client.webhooks.create({
  url: 'https://your-app.com/hooks',
  events: ['ave.new', 'ave.updated'],
});
```

## Package Status

**Status**: Planned — SDK will be published to npm upon commercial API launch.

## API Reference

See the [OpenAPI specification](../openapi/openapi-v2.yaml) for full endpoint documentation.
