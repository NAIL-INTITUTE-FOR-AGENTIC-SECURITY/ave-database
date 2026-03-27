# Federated Threat Intelligence Exchange

> Phase 20 · Service 3 of 5 · Port **9402**

Privacy-preserving collaborative threat intelligence sharing across organisational boundaries with differential privacy, secure aggregation, contribution scoring, and trust-tiered access control.

## Core Capabilities

### 1. Organisation Registry

- Multi-tenant organisation enrollment with trust tier (founding/verified/standard/provisional)
- Per-org sharing policies: what categories they share, minimum aggregation threshold, retention limits
- Bilateral and multilateral sharing agreements with expiry
- Contribution reputation scoring based on volume, quality, and timeliness

### 2. Intelligence Submission

- Structured threat indicator submission: IoCs, TTPs, threat actor profiles, vulnerability reports
- 18 AVE category tagging with severity and confidence
- Provenance tracking: original source, submission chain, corroboration count
- Embargo support: time-locked indicators released after configurable delay

### 3. Differential Privacy Engine

- ε-differential privacy with configurable epsilon (default 1.0) and delta (default 1e-5)
- Laplace noise injection for numeric aggregations (counts, averages, distributions)
- Randomised response for categorical data
- Privacy budget tracking per organisation per query with automatic exhaustion alerts
- Composition theorem enforcement: sequential queries consume cumulative budget

### 4. Secure Aggregation

- Federated count queries: "how many orgs observed this indicator?" without revealing which orgs
- Threshold aggregation: results only released when ≥K organisations contribute (default K=3)
- Category-level aggregate statistics without individual indicator exposure
- Cross-org trend detection with privacy-preserving time series

### 5. Trust-Tiered Access

- 4 trust tiers with escalating access: provisional (aggregates only), standard (+category breakdowns), verified (+detailed indicators), founding (+raw submissions)
- Tier-based query allowances and privacy budget allocations
- Automatic tier promotion based on contribution score thresholds
- Tier demotion on policy violations

### 6. Query & Analytics

- Federated queries with automatic privacy mechanism selection
- Indicator enrichment: cross-reference submitted indicators with global aggregate
- Trend analysis across the federation with differential privacy guarantees
- Contribution leaderboard (opt-in) with anonymisation option

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/organisations` | Register organisation |
| GET | `/v1/organisations` | List organisations |
| GET | `/v1/organisations/{org_id}` | Get organisation details |
| POST | `/v1/indicators` | Submit threat indicator |
| GET | `/v1/indicators` | Query indicators (privacy-filtered) |
| GET | `/v1/indicators/{indicator_id}` | Get indicator (tier-gated) |
| POST | `/v1/query/aggregate` | Federated aggregate query |
| POST | `/v1/query/trends` | Privacy-preserving trend query |
| GET | `/v1/privacy/budget/{org_id}` | Check privacy budget |
| POST | `/v1/agreements` | Create sharing agreement |
| GET | `/v1/agreements` | List agreements |
| GET | `/v1/reputation/{org_id}` | Get contribution reputation |
| GET | `/v1/analytics` | Exchange-wide analytics |
| GET | `/health` | Health check |

## Design Decisions

- **Privacy by default** — Every query passes through the differential privacy engine; raw data never leaves the submitter's trust boundary without aggregation
- **K-anonymity threshold** — Aggregate results suppressed when fewer than K organisations contribute, preventing inference attacks
- **Budget is finite** — Organisations must manage their privacy budget; once exhausted, queries are denied until budget resets
