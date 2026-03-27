# Recursive Self-Improvement Engine

> Meta-learning system that analyses the AVE platform's own detection/defence
> effectiveness and automatically proposes architectural improvements, new
> detection heuristics, and optimised configurations through self-reflective
> performance analysis.

## Port: `9100`

## Overview

The Recursive Self-Improvement Engine is the AVE platform's introspective
intelligence layer.  It continuously monitors detection accuracy, defence
efficacy, false-positive rates, and latency across every NAIL subsystem,
identifies degradation trends, and autonomously generates improvement proposals
— new heuristics, configuration tuning, architecture modifications — that are
evaluated, scored, and optionally auto-applied through a governed pipeline.

## Key Features

| Feature | Description |
|---------|-------------|
| **Subsystem Telemetry Ingest** | Collects performance metrics from every NAIL service (detection rate, FP rate, latency, coverage, efficacy) |
| **Performance Baseline Engine** | Maintains rolling baselines per subsystem with drift detection (z-score anomaly) |
| **Improvement Proposal Generator** | Produces 5 proposal types: heuristic refinement, config tuning, architecture change, coverage expansion, performance optimisation |
| **Proposal Evaluation Pipeline** | Simulated A/B scoring of proposals against baseline with expected improvement + risk assessment |
| **Auto-Apply Governor** | Configurable auto-apply threshold with mandatory human approval for high-risk changes |
| **Heuristic Library** | Versioned registry of detection heuristics with lineage tracking and rollback |
| **Self-Reflection Loop** | Meta-metric tracking: are the improvements themselves improving? Tracks improvement-of-improvement deltas |
| **Feedback Integration** | Closed-loop: applied proposals feed back new telemetry, triggering next improvement cycle |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/telemetry` | Ingest subsystem performance telemetry |
| `GET` | `/v1/telemetry` | Query telemetry history |
| `GET` | `/v1/baselines` | View current performance baselines |
| `POST` | `/v1/baselines/recalculate` | Force baseline recalculation |
| `GET` | `/v1/drift` | Detect performance drift across subsystems |
| `POST` | `/v1/proposals/generate` | Generate improvement proposals from current state |
| `GET` | `/v1/proposals` | List all proposals |
| `GET` | `/v1/proposals/{id}` | Proposal detail with evaluation results |
| `POST` | `/v1/proposals/{id}/evaluate` | Run simulated evaluation of a proposal |
| `POST` | `/v1/proposals/{id}/apply` | Apply a proposal (with approval gate) |
| `POST` | `/v1/proposals/{id}/rollback` | Rollback an applied proposal |
| `GET` | `/v1/heuristics` | List heuristic library |
| `POST` | `/v1/heuristics` | Register a new heuristic |
| `GET` | `/v1/meta` | Self-reflection metrics (improvement-of-improvement) |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Architecture

```
Subsystem Telemetry → Baseline Engine → Drift Detector
                                            ↓
                                    Proposal Generator
                                            ↓
                                   Evaluation Pipeline
                                            ↓
                                     Apply / Reject
                                            ↓
                                   Feedback → Loop
```

## Production Notes

- **Telemetry Storage**: Production → InfluxDB / TimescaleDB for time-series metrics
- **Proposal Evaluation**: Production → sandboxed A/B testing with shadow traffic
- **Auto-Apply**: Production → GitOps pipeline with PR generation + CI/CD integration
- **Self-Reflection**: Production → statistical process control (SPC) with control charts
