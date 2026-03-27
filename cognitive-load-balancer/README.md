# Cognitive Load Balancer

> AI workload orchestrator dynamically distributing cognitive tasks across agent pools based on capability, trust, and resource availability.

**Port:** 9303

## Overview

The Cognitive Load Balancer is the resource scheduler for AI cognitive work. Just as a traditional load balancer distributes HTTP requests across servers, this engine distributes complex reasoning tasks — threat analysis, policy evaluation, incident triage, ethical deliberation — across pools of AI agents based on their capabilities, current load, trust scores, and specialisation. It prevents cognitive overload, ensures fair distribution, manages task priorities, and optimises for both throughput and quality.

## Core Capabilities

### 1. Agent Pool Management

- **5 pool tiers**: critical (dedicated to severity ≥0.9 tasks), high (≥0.7), standard (≥0.4), background (<0.4), overflow (elastic burst)
- Per-agent capacity model: max concurrent tasks, current load percentage, queue depth
- Capability matrix: each agent scored across 18 AVE categories + 6 cognitive skills (analysis, synthesis, evaluation, prediction, creativity, communication)
- Trust integration: agent trust scores from Global Trust Fabric feed into scheduling decisions
- Health monitoring: heartbeat-based liveness, performance degradation detection, auto-drain unhealthy agents

### 2. Task Submission & Classification

- **8 task types**: threat_analysis, incident_triage, policy_evaluation, ethical_deliberation, pattern_recognition, report_generation, strategy_synthesis, compliance_audit
- Auto-classification of incoming tasks by type, required capabilities, estimated complexity (1–10), and priority
- Task decomposition: complex tasks split into sub-tasks with dependency DAG
- Deadline-aware scheduling: tasks with SLA requirements get priority boost
- Idempotency keys for duplicate task prevention

### 3. Scheduling Algorithms

- **4 scheduling strategies**: capability_weighted (best-fit by skill match), least_loaded (balance by current utilisation), priority_preemptive (high-priority tasks can preempt lower), affinity_based (route similar tasks to same agent for cache locality)
- Composite scoring: `score = capability_match × 0.4 + (1 - load) × 0.3 + trust × 0.2 + affinity × 0.1`
- Queue management with priority-based ordering and starvation prevention (age boost)
- Work-stealing: idle agents pull tasks from overloaded neighbours
- Circuit breaking: if an agent's error rate exceeds threshold, stop routing to it

### 4. Load Shedding & Backpressure

- 3-tier load shedding: when global load > 80%, shed background tasks; > 90%, shed standard; > 95%, shed high
- Backpressure signalling to upstream producers (return 429 with retry-after)
- Priority-based queue eviction: lowest-priority, oldest tasks dropped first
- Overflow pool auto-scaling with configurable min/max
- Degraded mode: reduce task quality requirements to maintain throughput

### 5. Performance Tracking

- Per-agent metrics: throughput (tasks/min), latency (p50/p95/p99), error rate, quality score
- Per-task-type metrics: avg completion time, success rate, retry rate
- Capacity planning: trend-based forecasting of future load
- SLA compliance tracking: % of tasks completed within deadline
- Cost accounting: cognitive compute units consumed per task/agent/pool

### 6. Fairness & Anti-Starvation

- Fair-share scheduling: no single task type can consume >40% of capacity
- Agent rotation: prevent burn-in by rotating high-load agents to cooldown
- Task aging: tasks waiting >N seconds get progressive priority boost
- Minimum guaranteed capacity per task type
- Audit trail of all scheduling decisions for bias detection

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/pools` | Create an agent pool |
| GET | `/v1/pools` | List pools with utilisation |
| GET | `/v1/pools/{pool_id}` | Pool detail with agent list |
| POST | `/v1/agents` | Register an agent in a pool |
| GET | `/v1/agents` | List agents with load/health |
| GET | `/v1/agents/{agent_id}` | Agent detail with task history |
| POST | `/v1/tasks` | Submit a task for scheduling |
| GET | `/v1/tasks` | List/filter tasks |
| GET | `/v1/tasks/{task_id}` | Task detail with scheduling trace |
| POST | `/v1/tasks/{task_id}/complete` | Mark task completed with result |
| GET | `/v1/schedule/decide` | Dry-run scheduling decision |
| GET | `/v1/load` | Global load overview |
| GET | `/v1/sla` | SLA compliance report |
| GET | `/v1/fairness` | Fairness metrics |
| GET | `/v1/analytics` | Load balancer analytics |
| GET | `/health` | Health check |

## Design Decisions

- **Composite scoring, not single-dimension** — Balancing capability match, load, trust, and affinity prevents pathological scheduling
- **Load shedding is explicit** — Rather than silently degrading, the system communicates backpressure clearly
- **Fairness is a first-class concern** — Anti-starvation and fair-share prevent any single task type from monopolising resources
