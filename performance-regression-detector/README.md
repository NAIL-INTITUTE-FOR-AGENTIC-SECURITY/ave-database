# 📉 Performance Regression Detector

**Phase 29 · Service 4 · Port 9923**

Continuous monitoring for gradual performance degradation in AI models, detecting subtle regressions before they impact security operations.

## Capabilities

| Capability | Detail |
|---|---|
| **Model Registry** | 6 model types: `classifier`, `detector`, `ranker`, `embedder`, `generator`, `ensemble` with version + deployment date + baseline metrics |
| **Metric Streams** | 8 tracked metrics: `accuracy`, `precision`, `recall`, `f1_score`, `latency_p50`, `latency_p99`, `throughput`, `error_rate` with configurable collection intervals |
| **Baseline Management** | Rolling baseline windows (7/14/30 day) with percentile-based thresholds (p5, p50, p95) |
| **Regression Detection** | 4 detection methods: `threshold_breach`, `trend_analysis` (slope), `distribution_shift` (KS-test inspired), `sudden_change` (z-score) |
| **Alert System** | 4 alert severities: `info`, `warning`, `critical`, `emergency` with configurable thresholds per metric |
| **Root Cause Hints** | Auto-generated hypotheses: data drift, model staleness, infrastructure degradation, dependency change, concept drift |
| **Comparison** | Side-by-side model version comparison across all metrics with statistical significance |
| **Trend Forecasting** | Extrapolate current degradation trends to predict when thresholds will be breached |
| **Remediation Tracking** | Track regression → investigation → fix → verification lifecycle |
| **Analytics** | Regressions detected, MTTR, most affected models, metric health distribution |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/models` | Register model |
| `GET` | `/v1/models` | List models |
| `GET` | `/v1/models/{mid}` | Get model detail with health status |
| `POST` | `/v1/models/{mid}/metrics` | Record metric observation |
| `GET` | `/v1/models/{mid}/baseline` | Get current baseline |
| `GET` | `/v1/models/{mid}/detect` | Run regression detection |
| `GET` | `/v1/models/{mid}/forecast` | Forecast metric trends |
| `GET` | `/v1/models/{mid}/compare/{other_mid}` | Compare two model versions |
| `GET` | `/v1/alerts` | List all alerts |
| `PATCH` | `/v1/alerts/{aid}/acknowledge` | Acknowledge an alert |
| `GET` | `/v1/analytics` | Regression analytics |
