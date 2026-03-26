# AVE 2.0 Schema

Next-generation AVE card schema extending v1.0.0 with enhanced fields
for multi-agent scenarios, temporal vulnerability patterns, composite
vulnerabilities, and richer provenance metadata.

## Overview

AVE 2.0 is a **backwards-compatible** extension of the v1.0.0 schema.
All existing v1 cards remain valid. New fields are optional additions
that enable richer vulnerability descriptions for complex agentic
AI scenarios.

## Key Changes from v1.0.0

### New Capabilities

| Feature | v1.0.0 | v2.0.0 |
|---------|--------|--------|
| Multi-agent topology | `environment.multi_agent: bool` | Full `multi_agent` object with roles, topology, propagation |
| Temporal patterns | Not supported | `temporal` object: latency, persistence, trigger conditions |
| Composite vulnerabilities | `related_aves: string[]` | `composites` object: chains, amplification, prerequisites |
| Attack graph | Not supported | `attack_graph` with kill-chain stages and branching paths |
| Provenance | `_meta` only | `provenance` object: discovery method, reproducibility, confidence |
| Affected components | Flat `environment` | `affected_components` array with granular component targeting |
| Counterfactual analysis | Not supported | `counterfactual` object: what-if scenarios, boundary conditions |
| Regulatory impact | Not supported | `regulatory_impact` mapping to EU AI Act, NIST, ISO requirements |

### Schema Compatibility

- **v1 → v2**: All v1 cards are valid v2 cards (new fields are optional)
- **v2 → v1**: v2 cards can be downgraded by stripping new fields
- **Migration tool**: `scripts/migrate_v1_to_v2.py` adds empty v2 fields

## Directory Structure

```
schema-v2/
├── README.md                      ← This file
├── spec/
│   ├── AVE-RFC-0002.md            ← Formal v2.0.0 specification
│   └── ave-card-v2.schema.json    ← Normative JSON Schema (Draft-07)
├── migration/
│   ├── migration_guide.md         ← v1 → v2 migration guide
│   ├── migrate_v1_to_v2.py        ← Automated migration script
│   └── compatibility_matrix.yaml  ← Field-level compatibility mapping
├── examples/
│   ├── multi_agent_example.json   ← Multi-agent vulnerability card
│   ├── temporal_example.json      ← Temporal pattern card
│   └── composite_example.json     ← Composite vulnerability card
└── validation/
    ├── validate_v2.py             ← v2 schema validator
    └── test_v2_schema.py          ← Validator test suite
```

## Quick Reference — New Fields

```json
{
  "// v1 fields remain unchanged": "...",

  "multi_agent": {
    "topology": "hierarchical | flat | swarm | pipeline | hub_spoke",
    "agent_count_min": 2,
    "agent_count_max": null,
    "roles_affected": ["orchestrator", "worker"],
    "propagation_pattern": "lateral | vertical | broadcast | cascading",
    "isolation_bypass": true,
    "cross_framework": false
  },

  "temporal": {
    "latency_class": "immediate | delayed | sleeper | progressive",
    "persistence": "ephemeral | session | persistent | permanent",
    "trigger_type": "immediate | conditional | time_based | event_based",
    "trigger_condition": "description of trigger",
    "observation_window_hours": 168,
    "recurrence": "one_shot | periodic | escalating"
  },

  "composites": {
    "chain": ["AVE-2025-0001", "AVE-2025-0003"],
    "relationship": "prerequisite | amplifier | enabler | co_requisite",
    "combined_severity_delta": 2.5,
    "notes": "description of composite interaction"
  },

  "attack_graph": {
    "kill_chain": ["reconnaissance", "initial_access", "execution", "impact"],
    "entry_points": ["user_input", "tool_response"],
    "branching_factor": 3,
    "shortest_path_steps": 2
  },

  "provenance": {
    "discovery_method": "manual | automated | red_team | incident | research",
    "reproducibility": "deterministic | probabilistic | environment_dependent",
    "confidence": 0.95,
    "independent_confirmations": 2,
    "first_seen_in_wild": false
  },

  "affected_components": [
    {
      "component": "memory_store",
      "vendor": "LangChain",
      "version_range": ">=0.1.0 <0.3.0",
      "cpe": null
    }
  ],

  "counterfactual": {
    "boundary_conditions": ["requires internet access", "model must support tool calling"],
    "what_if_mitigated": "Agent operates normally with <2% performance overhead",
    "residual_risk": "Partial bypass possible with adaptive adversary"
  },

  "regulatory_impact": {
    "eu_ai_act": { "risk_level": "high", "articles": ["Article 9", "Article 15"] },
    "nist_ai_rmf": { "functions": ["GOVERN", "MAP", "MEASURE"], "categories": ["GV-1.1", "MP-2.3"] },
    "iso_42001": { "clauses": ["6.1.2", "8.4"] }
  }
}
```
