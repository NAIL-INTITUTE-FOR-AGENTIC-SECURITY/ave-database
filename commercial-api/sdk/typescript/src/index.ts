/**
 * NAIL Institute AVE API — TypeScript SDK
 *
 * Official TypeScript client for the NAIL Institute Agentic Vulnerability
 * Enumeration (AVE) API.
 *
 * @example
 * ```typescript
 * import { NailClient } from '@nail-institute/api';
 * const client = new NailClient({ apiKey: 'your-key' });
 * const cards = await client.cards.list({ severity: 'critical' });
 * ```
 *
 * @packageDocumentation
 */

export interface NailClientOptions {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
}

export interface AveCard {
  ave_id: string;
  name: string;
  aliases: string[];
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: string;
  summary: string;
  mechanism: string;
  blast_radius: string;
  prerequisite: string;
  date_published: string;
  cwe_mapping: string;
  mitre_mapping: string;
  references: string[];
  related_aves: string[];
  avss_score: Record<string, unknown>;
  contributor: string;
}

export interface CardListOptions {
  q?: string;
  category?: string;
  severity?: string;
  status?: string;
  since?: string;
  sort?: string;
  order?: 'asc' | 'desc';
  page?: number;
  per_page?: number;
}

export interface WebhookConfig {
  url: string;
  events: string[];
  active?: boolean;
}

export interface Webhook extends WebhookConfig {
  id: string;
  secret: string;
  created_at: string;
}

export class NailClient {
  private apiKey: string;
  private baseUrl: string;
  private timeout: number;

  public cards: CardsClient;
  public webhooks: WebhooksClient;
  public export: ExportClient;
  public risk: RiskClient;

  constructor(options: NailClientOptions) {
    this.apiKey = options.apiKey;
    this.baseUrl = options.baseUrl || 'https://api.nailinstitute.org/v2';
    this.timeout = options.timeout || 30000;

    this.cards = new CardsClient(this);
    this.webhooks = new WebhooksClient(this);
    this.export = new ExportClient(this);
    this.risk = new RiskClient(this);
  }
}

// Stub implementations — full SDK coming soon
class CardsClient {
  constructor(private client: NailClient) {}
  async list(options?: CardListOptions): Promise<AveCard[]> { throw new Error('Full SDK coming soon'); }
  async get(aveId: string): Promise<AveCard> { throw new Error('Full SDK coming soon'); }
  async search(query: string, options?: CardListOptions): Promise<AveCard[]> { throw new Error('Full SDK coming soon'); }
}

class WebhooksClient {
  constructor(private client: NailClient) {}
  async list(): Promise<Webhook[]> { throw new Error('Full SDK coming soon'); }
  async create(config: WebhookConfig): Promise<Webhook> { throw new Error('Full SDK coming soon'); }
  async delete(id: string): Promise<void> { throw new Error('Full SDK coming soon'); }
}

class ExportClient {
  constructor(private client: NailClient) {}
  async create(options: { format: string; filters?: Record<string, unknown> }): Promise<unknown> { throw new Error('Full SDK coming soon'); }
}

class RiskClient {
  constructor(private client: NailClient) {}
  async score(system: Record<string, unknown>): Promise<unknown> { throw new Error('Full SDK coming soon'); }
}
