# Civilisational Risk Dashboard

> Macro-scale risk assessment aggregating signals from all NAIL subsystems into
> civilisational-level AI safety metrics, early warning indicators, and a policy
> recommendation engine for government/regulatory stakeholders.

## Port: `9103`

## Overview

The Civilisational Risk Dashboard operates at the highest abstraction layer,
aggregating intelligence from every NAIL subsystem into macro-scale AI safety
indicators.  It monitors systemic risk across sectors, geographies, and time
horizons, computes composite risk indices, issues early warnings when thresholds
are breached, and generates actionable policy recommendations for government
regulators, international bodies, and executive leadership.

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Sector Risk Indices** | Composite risk scores for 8 sectors: Finance, Healthcare, Defence, Critical Infrastructure, Education, Government, Transportation, Energy |
| **Geographic Risk Map** | Per-region risk aggregation across 6 regions (NA, EU, UK, APAC, LATAM, MEA) |
| **Systemic Risk Indicators** | 6 macro indicators: attack velocity, defence gap, coordination level, novel threat rate, cascading failure probability, recovery capacity |
| **Signal Aggregation** | Ingests signals from all NAIL subsystems (threat map, incidents, trust fabric, compliance, evolution engine, etc.) |
| **Early Warning System** | 4-tier alerting (advisory/elevated/severe/critical) with configurable thresholds per indicator |
| **Trend Analysis** | 30/90/365-day trend tracking with slope analysis and inflection point detection |
| **Policy Recommendation Engine** | Maps risk states to actionable policy recommendations with regulatory framework citations |
| **Scenario Modelling** | What-if scenario engine: "What happens if attack velocity doubles?" or "What if defence coverage drops 20%?" |
| **Executive Briefing Generator** | Auto-generated executive summaries suitable for board/government consumption |
| **Historical Comparison** | Compare current risk posture against historical baselines and peer benchmarks |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/signals` | Ingest a risk signal from any subsystem |
| `GET` | `/v1/signals` | Query signal history |
| `GET` | `/v1/indices` | Current composite risk indices (all sectors + regions) |
| `GET` | `/v1/indices/{sector}` | Sector-specific risk breakdown |
| `GET` | `/v1/indicators` | Systemic risk indicators |
| `GET` | `/v1/warnings` | Active early warnings |
| `POST` | `/v1/warnings/evaluate` | Force early warning evaluation |
| `GET` | `/v1/trends` | Trend analysis across all indicators |
| `POST` | `/v1/scenarios` | Run a what-if scenario |
| `GET` | `/v1/scenarios` | List scenario results |
| `POST` | `/v1/policy/recommend` | Generate policy recommendations for current state |
| `GET` | `/v1/policy/recommendations` | List generated recommendations |
| `POST` | `/v1/briefing` | Generate executive briefing |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Architecture

```
NAIL Subsystem Signals → Signal Aggregator → Indicator Engine
                                                    ↓
                                          ┌─────────┴─────────┐
                                          ↓                   ↓
                                   Sector Indices      Geographic Map
                                          ↓                   ↓
                                          └─────────┬─────────┘
                                                    ↓
                                          Early Warning System
                                                    ↓
                                     Policy Recommendation Engine
                                                    ↓
                                        Executive Briefing
```

## Production Notes

- **Signal Pipeline**: Production → Apache Kafka with Flink streaming analytics
- **Risk Models**: Production → Monte Carlo simulation + Bayesian networks for probabilistic risk
- **Policy Engine**: Production → RAG over regulatory corpus (EU AI Act, NIST, ISO, OECD AI Principles)
- **Briefing**: Production → LLM-generated summaries with human editorial review gate
- **Dashboard**: Production → Grafana + custom React frontend with real-time WebSocket updates
