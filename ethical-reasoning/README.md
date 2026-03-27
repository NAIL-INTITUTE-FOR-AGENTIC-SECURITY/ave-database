# Ethical Reasoning Framework

> Formal ethical calculus engine for AI agent decision-making under adversarial
> conditions, implementing multiple ethical frameworks (deontological,
> consequentialist, virtue ethics) with conflict resolution and transparency
> reporting.

## Port: `9102`

## Overview

The Ethical Reasoning Framework provides a formal, auditable ethical evaluation
layer for AI agent decisions — especially under adversarial pressure.  When an
agent must choose between competing actions (e.g., block a suspicious user vs.
allow access, quarantine data vs. maintain availability), this engine evaluates
the decision through three ethical lenses, identifies conflicts, applies
configurable resolution strategies, and produces a transparent justification
suitable for regulatory audit.

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Framework Evaluation** | Three ethical frameworks: Deontological (rule/duty-based), Consequentialist (outcome-based), Virtue Ethics (character/principle-based) |
| **Dilemma Modelling** | Structured dilemma representation with stakeholders, actions, constraints, and potential outcomes |
| **Per-Framework Scoring** | Each framework independently scores every action option 0.0–1.0 with detailed reasoning |
| **Conflict Detection** | Identifies when frameworks disagree and classifies conflict severity |
| **Resolution Strategies** | 4 resolution modes: weighted average, priority hierarchy, unanimous agreement, Rawlsian maximin |
| **Principle Library** | Configurable ethical principles per framework with weight and priority |
| **Stakeholder Analysis** | Maps affected parties (users, agents, organisations, society) with impact scoring |
| **Transparency Reports** | Full audit trail: which frameworks evaluated what, where they agreed/disagreed, why the final verdict was chosen |
| **Precedent Tracking** | Archives resolved dilemmas as precedents for consistent future decisions |
| **Regulatory Alignment** | Maps ethical evaluations to EU AI Act transparency requirements |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/dilemmas` | Submit a new ethical dilemma for evaluation |
| `GET` | `/v1/dilemmas` | List all dilemmas |
| `GET` | `/v1/dilemmas/{id}` | Dilemma detail with full evaluation |
| `POST` | `/v1/evaluate/{dilemma_id}` | Run multi-framework evaluation |
| `POST` | `/v1/resolve/{dilemma_id}` | Apply conflict resolution strategy |
| `GET` | `/v1/frameworks` | List ethical frameworks and their principles |
| `POST` | `/v1/frameworks/{name}/principles` | Add/update principles for a framework |
| `GET` | `/v1/precedents` | List resolved precedents |
| `GET` | `/v1/precedents/{id}` | Precedent detail |
| `POST` | `/v1/stakeholders` | Register stakeholder profiles |
| `GET` | `/v1/stakeholders` | List stakeholders |
| `GET` | `/v1/transparency/{dilemma_id}` | Full transparency report |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Architecture

```
Dilemma Submission → Stakeholder Analysis
                          ↓
    ┌─────────────────────┼─────────────────────┐
    ↓                     ↓                     ↓
Deontological      Consequentialist        Virtue Ethics
  Evaluator          Evaluator              Evaluator
    ↓                     ↓                     ↓
    └─────────────────────┼─────────────────────┘
                          ↓
                  Conflict Detector
                          ↓
                  Resolution Engine
                          ↓
              Transparency Report + Precedent
```

## Production Notes

- **Ethical Models**: Production → fine-tuned LLM evaluators with constitutional AI constraints
- **Precedent Store**: Production → PostgreSQL with vector similarity for precedent retrieval
- **Regulatory Mapping**: Production → automated EU AI Act Article 13-15 compliance checking
- **Audit**: Production → immutable append-only ledger (blockchain or WORM storage)
