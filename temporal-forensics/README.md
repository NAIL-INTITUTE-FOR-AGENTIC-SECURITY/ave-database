# Temporal Attack Forensics

> Time-series reconstruction engine for multi-stage attacks spanning hours/days
> across agent ecosystems, enabling retroactive causal analysis, temporal pattern
> recognition, and predictive timeline projection.

## Port: `9101`

## Overview

The Temporal Attack Forensics engine captures, indexes, and analyses security
events across time, reconstructing the full chronology of multi-stage attacks
that may span minutes to weeks across distributed agent ecosystems.  It builds
temporal attack graphs, identifies causal chains, recognises recurring temporal
patterns, and projects likely future attack timelines.

## Key Features

| Feature | Description |
|---------|-------------|
| **Event Ingestion** | Time-indexed event capture from any NAIL subsystem with nanosecond precision |
| **Timeline Reconstruction** | Automatic assembly of ordered event timelines for incidents with gap detection |
| **Temporal Attack Graph** | Directed acyclic graph linking causal events across agents and systems |
| **Pattern Library** | Catalogued temporal attack patterns (kill chain progression, slow-and-low, burst, oscillating, dormant-then-active) |
| **Pattern Matching** | Sliding-window pattern detection against the pattern library with fuzzy temporal matching |
| **Causal Chain Analysis** | Root cause identification via backward temporal traversal with confidence scoring |
| **Predictive Projection** | Forward timeline projection: given current attack stage, predict next likely events + timing |
| **Dwell Time Analysis** | Measures attacker dwell time per stage with comparison to known baselines |
| **Multi-Agent Correlation** | Cross-agent temporal correlation identifying coordinated attacks |
| **Forensic Report Generation** | Structured forensic reports with timeline visualisation data and evidence chain |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/events` | Ingest a security event |
| `GET` | `/v1/events` | Query events with time range and filters |
| `POST` | `/v1/timelines` | Reconstruct timeline for an incident |
| `GET` | `/v1/timelines` | List reconstructed timelines |
| `GET` | `/v1/timelines/{id}` | Timeline detail with full event sequence |
| `POST` | `/v1/causal/{timeline_id}` | Run causal chain analysis on a timeline |
| `GET` | `/v1/patterns` | List known temporal attack patterns |
| `POST` | `/v1/patterns` | Register a new temporal pattern |
| `POST` | `/v1/detect` | Detect patterns in a timeline |
| `POST` | `/v1/predict/{timeline_id}` | Project future attack timeline |
| `GET` | `/v1/dwell` | Dwell time analysis across incidents |
| `POST` | `/v1/correlate` | Cross-agent temporal correlation |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Architecture

```
Event Ingestion → Time-Indexed Store → Timeline Reconstruction
                                              ↓
                              Causal Analysis ←→ Pattern Matching
                                              ↓
                                    Predictive Projection
                                              ↓
                                     Forensic Reporting
```

## Production Notes

- **Event Store**: Production → Apache Kafka + ClickHouse for high-throughput time-series
- **Pattern Matching**: Production → temporal logic engine (e.g., TCTL model checking)
- **Prediction**: Production → LSTM/Transformer sequence models trained on historical attack data
- **Correlation**: Production → distributed tracing (OpenTelemetry) integration
