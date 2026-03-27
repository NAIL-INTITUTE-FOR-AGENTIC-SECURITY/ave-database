# 🧠 Neuro-Symbolic Threat Reasoning

> Hybrid neuro-symbolic engine combining neural pattern recognition
> with formal logic-based threat reasoning for explainable causal
> chain analysis across multi-agent attack graphs.

**Port:** `9000`

## Overview

The Neuro-Symbolic Threat Reasoning service bridges the gap between
statistical deep-learning pattern detectors and rigorous formal logic
systems.  Neural modules identify candidate threat patterns from raw
telemetry while symbolic modules construct formally-verifiable causal
chains, enabling counterfactual ("what-if") simulation and fully
explainable threat assessments.

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **Neural Pattern Detector** | Embedding-based similarity + anomaly scoring on raw threat signals |
| **Symbolic Reasoner** | First-order logic rule engine with forward/backward chaining |
| **Knowledge Base** | Typed fact store with predicates covering all 18 AVE categories |
| **Causal Chain Builder** | Constructs multi-step attack graphs from matched rules |
| **Counterfactual Simulator** | "What-if" analysis — remove/add facts and re-derive conclusions |
| **Explanation Generator** | Human-readable natural-language justifications for every conclusion |
| **Hybrid Fusion** | Combines neural confidence with symbolic proof strength |
| **Rule Management** | CRUD for symbolic rules with dependency tracking |

## Architecture

```
Raw telemetry → Neural Encoder → Candidate Patterns
                                       ↓
Candidate Patterns + Knowledge Base → Symbolic Reasoner → Causal Chains
                                       ↓
Causal Chains → Counterfactual Simulator → Explanation Generator → Output
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + KB stats |
| `POST` | `/v1/facts` | Assert a new fact into the knowledge base |
| `GET` | `/v1/facts` | Query facts with predicate/entity/category filters |
| `DELETE` | `/v1/facts/{fact_id}` | Retract a fact |
| `POST` | `/v1/rules` | Add a symbolic inference rule |
| `GET` | `/v1/rules` | List rules with category/priority filters |
| `GET` | `/v1/rules/{rule_id}` | Get rule detail |
| `POST` | `/v1/reason` | Run forward-chaining inference on current KB |
| `POST` | `/v1/explain/{conclusion_id}` | Generate explanation for a conclusion |
| `POST` | `/v1/counterfactual` | Run what-if analysis with modified facts |
| `POST` | `/v1/neural/encode` | Encode raw signal via neural module |
| `POST` | `/v1/neural/detect` | Detect patterns in encoded signals |
| `POST` | `/v1/fuse` | Hybrid fusion of neural + symbolic results |
| `GET` | `/v1/analytics` | Reasoning statistics and coverage |

## Production Notes

- Neural encoder — production deployment uses sentence-transformers + FAISS
- Symbolic engine — production uses Datalog / Answer Set Programming solver
- Knowledge base — production backed by Neo4j + PostgreSQL
- Rule store — production uses versioned rule repository with rollback

## Quick Start

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9000
# Docs → http://localhost:9000/docs
```
