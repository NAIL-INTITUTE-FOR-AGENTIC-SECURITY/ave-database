# Autonomous Policy Engine

> Self-adaptive security policy management with rule synthesis, conflict detection, impact simulation, and progressive enforcement.

**Port:** 9301

## Overview

The Autonomous Policy Engine governs security posture across the entire NAIL AVE platform. Policies are expressed as structured rules with conditions, actions, and scopes, and the engine continuously evaluates them against live signals. New rules can be synthesised from observed threat patterns, conflicts between overlapping rules are automatically detected and resolved, and enforcement is progressively rolled out with impact simulation before full activation.

## Core Capabilities

### 1. Policy Registry

- **6 policy types**: access_control, rate_limit, content_filter, isolation, escalation, compliance
- Structured rule format: conditions (field/operator/value predicates), actions (allow/deny/throttle/quarantine/alert/escalate), scopes (services/categories/agents/roles)
- 4-tier priority system: critical (1000), high (750), medium (500), low (250)
- Policy versioning with full diff history
- Enable/disable/archive lifecycle with effective date windows

### 2. Rule Synthesis Engine

- Auto-generate candidate policies from recurring incident patterns
- Threat-signal-driven synthesis: when ≥N incidents match a pattern, propose a defensive rule
- Template library with parameterised rule skeletons for each policy type
- Confidence scoring for synthesised rules based on supporting evidence count
- Human-in-the-loop approval gate for all synthesised rules before activation

### 3. Conflict Detection & Resolution

- **6 conflict types**: contradiction (allow vs deny same scope), subsumption (one rule fully covers another), priority inversion (lower-priority rule overrides higher), scope overlap (partial intersection), temporal conflict (overlapping effective windows), circular dependency
- Pairwise conflict analysis across all active policies
- Automatic resolution strategies: priority-wins, most-specific-wins, most-restrictive-wins, newest-wins
- Conflict report with severity classification and recommended resolution

### 4. Impact Simulation

- What-if analysis: simulate policy activation against historical traffic/incident data
- Projected metrics: requests affected, false positive rate, coverage gap, blast radius
- Side-by-side comparison: current policy set vs proposed change
- Shadow mode: policy evaluates but does not enforce, collecting telemetry
- Rollback impact assessment: what would happen if a policy were removed

### 5. Progressive Enforcement

- 4-phase rollout: shadow (observe only) → canary (5% enforcement) → partial (50%) → full (100%)
- Per-phase health gates: if error rate or false positive rate exceeds threshold, auto-pause
- Enforcement state tracking with phase transition timestamps
- Gradual scope expansion: start with dev → staging → production
- Emergency kill switch: instantly disable any policy

### 6. Compliance Mapping

- Map policies to regulatory requirements: EU AI Act, NIST AI RMF, ISO 27001, SOC 2
- Coverage matrix: which regulations are satisfied by which policies
- Gap detection: regulatory requirements without corresponding policies
- Audit trail: every policy evaluation, enforcement decision, and override logged

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/policies` | Create a policy |
| GET | `/v1/policies` | List/filter policies |
| GET | `/v1/policies/{policy_id}` | Get policy detail with history |
| PUT | `/v1/policies/{policy_id}` | Update a policy |
| DELETE | `/v1/policies/{policy_id}` | Archive a policy |
| POST | `/v1/policies/{policy_id}/evaluate` | Evaluate policy against a request |
| POST | `/v1/synthesis/generate` | Synthesise candidate policies from signals |
| GET | `/v1/synthesis/candidates` | List pending synthesised candidates |
| POST | `/v1/synthesis/candidates/{id}/approve` | Approve a synthesised policy |
| GET | `/v1/conflicts` | Detect all conflicts in active policy set |
| GET | `/v1/conflicts/{policy_id}` | Conflicts for a specific policy |
| POST | `/v1/simulate` | Simulate policy impact |
| POST | `/v1/enforcement/{policy_id}/advance` | Advance enforcement phase |
| GET | `/v1/enforcement` | List enforcement states |
| GET | `/v1/compliance` | Compliance coverage matrix |
| GET | `/v1/analytics` | Policy engine analytics |
| GET | `/health` | Health check |

## Design Decisions

- **Condition predicates as structured objects** — Not free-form strings; enables programmatic conflict detection and synthesis
- **Progressive enforcement is mandatory** — No policy goes from draft to 100% without passing through shadow/canary phases
- **Synthesis requires approval** — Auto-generated rules are always candidates until human-approved, preventing autonomous policy creep
