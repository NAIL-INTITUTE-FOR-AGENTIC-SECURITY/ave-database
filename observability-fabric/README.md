# Universal Observability Fabric

> **Phase 21 — Service 5 of 5 · Port `9504`**

Unified telemetry aggregation across all AVE phases with distributed tracing,
metric correlation, anomaly detection, SLO management, and alert routing.

---

## Key Capabilities

| Capability | Detail |
|------------|--------|
| **Telemetry Ingestion** | 4 signal types (`metrics` / `traces` / `logs` / `events`), structured payloads with source service, phase, and AVE category tagging, batch and single-item ingestion, automatic timestamp normalisation |
| **Distributed Tracing** | Trace registry with span hierarchy (parent/child), 4 span statuses (`ok` / `error` / `timeout` / `cancelled`), cross-service trace correlation via trace_id propagation, critical-path analysis |
| **Metric Correlation** | Time-series metric storage with labels, correlation engine detecting co-moving metrics across services, automatic grouping by phase/service/category |
| **Anomaly Detection** | 3 detection methods — `z_score` (statistical deviation), `iqr` (interquartile range), `threshold` (static bounds) — configurable per metric, anomaly severity scoring, automatic alert generation |
| **SLO Management** | SLO definitions with target percentage, measurement window, error budget tracking, burn-rate alerting (1h/6h/24h windows), SLO compliance history |
| **Alert Routing** | Alert rules with severity, routing channels (`slack` / `pagerduty` / `email` / `webhook` / `war_room`), deduplication window, escalation on repeated firing, acknowledgement + resolution tracking |

## AVE Integration

All 18 AVE categories are first-class telemetry dimensions — every metric,
trace, log, and event can be tagged with the relevant vulnerability category
for cross-phase security observability.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/telemetry/ingest` | Ingest telemetry signal |
| `GET` | `/v1/telemetry` | Query telemetry |
| `POST` | `/v1/traces` | Create trace |
| `POST` | `/v1/traces/{trace_id}/spans` | Add span to trace |
| `GET` | `/v1/traces/{trace_id}` | Get full trace |
| `GET` | `/v1/traces` | List traces |
| `POST` | `/v1/metrics` | Record metric |
| `GET` | `/v1/metrics` | Query metrics |
| `GET` | `/v1/metrics/correlate` | Run correlation analysis |
| `POST` | `/v1/anomalies/detect` | Run anomaly detection |
| `GET` | `/v1/anomalies` | List detected anomalies |
| `POST` | `/v1/slos` | Create SLO |
| `GET` | `/v1/slos` | List SLOs |
| `GET` | `/v1/slos/{slo_id}` | SLO detail with error budget |
| `POST` | `/v1/alerts/rules` | Create alert rule |
| `GET` | `/v1/alerts` | List fired alerts |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Running

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9504
```

> **Note:** In-memory stores for development. Production should use
> ClickHouse/TimescaleDB for metrics, Jaeger/Tempo for traces, Loki for logs.
