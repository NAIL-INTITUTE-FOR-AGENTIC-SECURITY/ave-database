# 📊 Resilience Scorecard

**Phase 28 · Service 4 · Port 9918**

Quantitative resilience measurement across availability, recoverability, scalability, and degradation-handling dimensions with historical tracking.

## Capabilities

| Capability | Detail |
|---|---|
| **Service Registry** | 6 service types: `api`, `worker`, `database`, `cache`, `gateway`, `ml_service` with tier (platinum/gold/silver/bronze) and SLA targets |
| **4-Dimension Scoring** | Availability (uptime, error rates), Recoverability (MTTR, backup freshness), Scalability (auto-scale response, capacity headroom), Degradation Handling (graceful degradation, circuit breakers, fallback coverage) |
| **Measurement Ingestion** | Record observations per dimension with timestamp, measured value, and context |
| **Composite Score** | Weighted composite 0-100: availability 35% + recoverability 25% + scalability 20% + degradation_handling 20% |
| **Historical Tracking** | Score snapshots over time with trend analysis: improving / stable / declining per dimension |
| **Tier Compliance** | Auto-check service scores against tier-specific thresholds (platinum ≥ 90 / gold ≥ 75 / silver ≥ 60 / bronze ≥ 40) |
| **Gap Analysis** | Identify weakest dimensions per service with specific improvement recommendations |
| **Benchmarking** | Compare service resilience scores against fleet average and tier targets |
| **Certification** | Services meeting all tier thresholds for 30+ consecutive days earn resilience certification |
| **Analytics** | Fleet-wide resilience posture, dimension distributions, tier compliance rates, trend dashboard |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/services` | Register service |
| `GET` | `/v1/services` | List services with current scores |
| `GET` | `/v1/services/{sid}` | Get service detail with dimension breakdown |
| `POST` | `/v1/services/{sid}/measurements` | Record a measurement |
| `GET` | `/v1/services/{sid}/history` | Get score history |
| `GET` | `/v1/services/{sid}/gaps` | Get gap analysis |
| `GET` | `/v1/services/{sid}/certification` | Check certification status |
| `GET` | `/v1/benchmarks` | Fleet-wide benchmark comparison |
| `GET` | `/v1/tier-compliance` | Tier compliance report |
| `GET` | `/v1/analytics` | Resilience analytics |
