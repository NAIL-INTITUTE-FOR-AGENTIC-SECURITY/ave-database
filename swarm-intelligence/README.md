# Collective Intelligence Swarm

> Multi-agent swarm intelligence for collaborative threat hunting, defence coordination, and emergent strategy discovery.

**Port:** 9302

## Overview

The Collective Intelligence Swarm orchestrates fleets of specialised AI agents that collaborate to hunt threats, coordinate defences, and discover emergent strategies no single agent could find alone. Inspired by biological swarm behaviour (ant colony optimisation, bee waggle dances, flocking), agents share local observations through a shared signal layer, form dynamic task forces around detected threats, and collectively vote on response strategies with stigmergic reinforcement.

## Core Capabilities

### 1. Agent Fleet Management

- **6 agent specialisations**: scout (reconnaissance), sentinel (monitoring), hunter (active pursuit), analyst (deep investigation), coordinator (strategy synthesis), healer (remediation)
- Agent lifecycle: spawned → idle → assigned → active → cooling_down → retired
- Capability profiles: each agent has scored capabilities across 18 AVE categories (0.0–1.0)
- Energy/stamina model: agents consume energy per task, regenerate over time, retire when depleted
- Fleet scaling: dynamic spawn/retire based on threat load with configurable min/max fleet size

### 2. Swarm Signal Layer (Stigmergy)

- Pheromone-based communication: agents deposit typed signals (threat_detected, area_clear, help_needed, defence_active, pattern_found)
- Signal strength with exponential decay over time (configurable half-life)
- Spatial signal map: signals tagged to services/categories/regions for locality
- Signal aggregation: overlapping signals of same type reinforce (superposition)
- Gradient following: agents navigate toward strongest signal gradients

### 3. Task Force Formation

- Dynamic coalition assembly: when threat signals exceed threshold, auto-form a task force
- Role-based composition: each task force requires minimum scouts + hunters + analysts
- Capability matching: agents assigned based on best-fit to threat category
- Trust-weighted selection: higher-trust agents preferred for critical task forces
- Task force lifecycle: forming → hunting → analysing → responding → disbanded

### 4. Collective Decision-Making

- **3 voting protocols**: majority (>50%), supermajority (>66%), weighted consensus (capability × trust)
- Strategy proposals from any agent in a task force
- Quorum requirements: minimum participation threshold before vote counts
- Deliberation rounds with argument/counter-argument exchange
- Emergency override: coordinator agents can bypass voting under time pressure

### 5. Emergent Strategy Discovery

- Strategy archive: successful response strategies stored with fitness scores
- Cross-pollination: strategies from one threat domain tested against others
- Mutation and recombination of strategy components
- Novelty bonus: previously-unseen strategies get exploration credit
- Strategy lineage tracking: which strategies evolved from which predecessors

### 6. Swarm Metrics & Health

- Collective coverage: what % of AVE categories are actively monitored
- Response time: threat detection to task force formation latency
- Strategy diversity index (Shannon entropy across active strategies)
- Agent utilisation and energy distribution
- Coordination efficiency: ratio of successful to total task forces

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/agents` | Spawn a new agent |
| GET | `/v1/agents` | List fleet with status/specialisation filters |
| GET | `/v1/agents/{agent_id}` | Get agent detail with task history |
| POST | `/v1/agents/{agent_id}/assign` | Assign agent to a task force |
| POST | `/v1/signals` | Deposit a swarm signal |
| GET | `/v1/signals` | Query signal map with locality filters |
| GET | `/v1/signals/gradients` | Compute signal gradients |
| POST | `/v1/taskforces` | Form a new task force |
| GET | `/v1/taskforces` | List task forces |
| GET | `/v1/taskforces/{tf_id}` | Get task force detail |
| POST | `/v1/taskforces/{tf_id}/vote` | Submit strategy vote |
| GET | `/v1/taskforces/{tf_id}/decisions` | Get voting results |
| GET | `/v1/strategies` | List discovered strategies |
| GET | `/v1/strategies/{strategy_id}` | Get strategy lineage |
| POST | `/v1/strategies/cross-pollinate` | Test strategy in new domain |
| GET | `/v1/analytics` | Swarm-wide analytics |
| GET | `/health` | Health check |

## Design Decisions

- **Stigmergic communication** — Agents communicate indirectly through deposited signals, enabling massive scalability without N² direct messaging
- **Energy model prevents runaway** — Agents cannot operate indefinitely; energy constraints force fleet rotation and prevent single-agent dominance
- **Task forces are ephemeral** — Formed for a specific threat, disbanded after resolution; no permanent teams that could become stale
