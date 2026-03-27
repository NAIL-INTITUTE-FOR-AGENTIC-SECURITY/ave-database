# 🧬 Adversarial Evolution Engine

> Continuous co-evolutionary system where attack generators and
> defence generators evolve against each other through genetic
> programming, producing hardened defences and discovering novel
> vulnerability classes.

**Port:** `9003`

## Overview

The Adversarial Evolution Engine implements a digital arms race where
populations of attack programs and defence programs co-evolve through
selection, crossover, and mutation.  Attacks that bypass defences score
fitness points; defences that block attacks score fitness points.  Over
generations the system produces battle-hardened defences and
simultaneously discovers novel attack patterns that no human designed.

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **Genetic Programming** | Tree-based GP for both attack and defence program evolution |
| **Co-Evolution** | Competitive fitness: attacker fitness ∝ bypasses, defender fitness ∝ blocks |
| **Population Management** | Configurable population size, elitism rate, crossover/mutation rates |
| **Multi-Category Arenas** | Separate or combined evolution across 18 AVE categories |
| **Novelty Search** | Bonus fitness for discovering genuinely new attack/defence patterns |
| **Hall of Fame** | Archive of all-time best attackers and defenders per generation |
| **Lineage Tracking** | Full ancestry tree for every individual (parents, mutations, crossover points) |
| **Convergence Detection** | Auto-detect evolutionary stagnation and trigger hypermutation |
| **Defence Export** | Extract evolved defences as deployable guardrail configurations |

## Architecture

```
Initial Population → Evaluation Arena → Fitness Scoring
       ↑                                      ↓
  Offspring ← Crossover + Mutation ← Selection (Tournament)
       ↑                                      ↓
  Hall of Fame ← Best Individuals ← Convergence Check
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + evolution stats |
| `POST` | `/v1/populations` | Create a new population (attackers or defenders) |
| `GET` | `/v1/populations` | List populations with type/category filters |
| `GET` | `/v1/populations/{pop_id}` | Get population detail |
| `POST` | `/v1/evolve` | Run N generations of co-evolution |
| `GET` | `/v1/generations/{pop_id}` | Get generation history for a population |
| `GET` | `/v1/individuals/{individual_id}` | Get individual detail + lineage |
| `GET` | `/v1/hall-of-fame` | All-time best individuals |
| `POST` | `/v1/arena` | Evaluate one attacker vs one defender |
| `GET` | `/v1/arena/history` | Match history |
| `POST` | `/v1/export/{individual_id}` | Export individual as deployable config |
| `GET` | `/v1/novelty` | Novelty archive — genuinely new patterns |
| `GET` | `/v1/analytics` | Evolution metrics, fitness trends, diversity |

## Production Notes

- GP engine — production uses DEAP or custom Rust-based GP runtime
- Arena — production executes in sandboxed containers with timeout
- Export — production generates LangChain/CrewAI/AutoGen guardrail configs
- Storage — production uses PostgreSQL + S3 for individual program trees

## Quick Start

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9003
# Docs → http://localhost:9003/docs
```
