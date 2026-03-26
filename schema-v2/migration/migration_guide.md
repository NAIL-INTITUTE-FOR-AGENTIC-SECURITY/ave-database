# Migration Guide: AVE v1.0.0 → v2.0.0

## Overview

AVE v2.0.0 is a **backwards-compatible** extension of v1.0.0. All
existing v1 cards are valid v2 cards. This guide covers:

1. What changed between v1 and v2
2. How to migrate existing cards
3. How to populate new v2 fields
4. Tooling and automation

---

## What Changed

### New Optional Fields (8 Groups)

| Field Group | Purpose | When to Populate |
|-------------|---------|-----------------|
| `multi_agent` | Agent topology and propagation | When vulnerability involves 2+ agents |
| `temporal` | Time-dependent characteristics | When timing affects exploitation |
| `composites` | Vulnerability chains | When AVEs combine for greater impact |
| `attack_graph` | Kill-chain modelling | When multi-step exploitation exists |
| `provenance` | Discovery metadata | Always recommended for v2 cards |
| `affected_components` | Specific components | When vendor/version info is known |
| `counterfactual` | Boundary conditions | When conditions are well-understood |
| `regulatory_impact` | Regulatory mapping | When regulatory relevance is known |

### Extended Enumerations

| Enumeration | v1 Values | v2 Additions |
|------------|-----------|-------------|
| `category` | 13 values | +7: multi_agent_collusion, temporal_exploitation, composite, supply_chain, model_extraction, emergent_behaviour, environmental_manipulation |
| `status` | 8 values | +1: superseded |

### AVSS Score Extensions

| New Sub-Score | Range | Default |
|--------------|-------|---------|
| `multi_agent_modifier` | 0.0–2.0 | 1.0 (neutral) |
| `temporal_modifier` | 0.0–2.0 | 1.0 (neutral) |
| `composite_modifier` | 0.0–2.0 | 1.0 (neutral) |
| `environmental_modifier` | 0.0–2.0 | 1.0 (neutral) |

### `_meta` Extensions

| New Field | Purpose |
|-----------|---------|
| `migrated_from` | Source schema version |
| `migration_date` | When card was migrated |
| `v2_fields_populated` | Which v2 field groups have data |

---

## Migration Steps

### Step 1: Automated Migration

Run the migration script to update all v1 cards:

```bash
cd public-repo
python schema-v2/migration/migrate_v1_to_v2.py \
  --input ave-database/cards/ \
  --output ave-database/cards/ \
  --in-place
```

This script:
- Updates `_meta.schema_version` from `"1.0.0"` to `"2.0.0"`
- Adds `_meta.migrated_from: "1.0.0"`
- Adds `_meta.migration_date` with current timestamp
- Sets `_meta.v2_fields_populated: []`
- Does NOT add v2 field groups (they remain absent = valid)

### Step 2: Validate

```bash
python schema-v2/validation/validate_v2.py \
  --cards ave-database/cards/ \
  --schema schema-v2/spec/ave-card-v2.schema.json
```

### Step 3: Enrich (Optional)

For cards where v2 data is known, add fields manually or via
enrichment scripts:

```bash
# Add multi_agent data to cards with environment.multi_agent: true
python schema-v2/migration/migrate_v1_to_v2.py \
  --input ave-database/cards/ \
  --enrich-multi-agent
```

---

## Populating v2 Fields

### `multi_agent` — When to Add

Add when `environment.multi_agent: true` in the v1 card.

```json
{
  "multi_agent": {
    "topology": "hierarchical",
    "agent_count_min": 2,
    "agent_count_max": 5,
    "roles_affected": ["orchestrator", "worker"],
    "propagation_pattern": "vertical",
    "isolation_bypass": true,
    "cross_framework": false,
    "communication_vector": "shared_memory"
  }
}
```

### `temporal` — When to Add

Add when the vulnerability has time-dependent characteristics
(sleeper payloads, delayed effects, progressive degradation).

```json
{
  "temporal": {
    "latency_class": "sleeper",
    "persistence": "persistent",
    "trigger_type": "conditional",
    "trigger_condition": "Agent retrieves poisoned memory after 3+ rounds",
    "observation_window_hours": 168,
    "recurrence": "one_shot",
    "mean_time_to_manifest": 3600,
    "detection_lag": 7200
  }
}
```

### `provenance` — Always Recommended

```json
{
  "provenance": {
    "discovery_method": "manual_testing",
    "reproducibility": "deterministic",
    "confidence": 0.95,
    "independent_confirmations": 1,
    "first_seen_in_wild": false,
    "reporter_type": "researcher"
  }
}
```

### `regulatory_impact` — When Regulatory Relevance Is Known

```json
{
  "regulatory_impact": {
    "eu_ai_act": {
      "risk_level": "high",
      "articles": ["Article 9", "Article 15"],
      "obligations": ["Risk management system", "Accuracy and robustness"]
    },
    "nist_ai_rmf": {
      "functions": ["MAP", "MEASURE"],
      "categories": ["MP-2.3", "MS-2.6"]
    }
  }
}
```

---

## Compatibility Matrix

| Tool | v1 Cards | v2 Cards (v1 only fields) | v2 Cards (with v2 fields) |
|------|----------|--------------------------|--------------------------|
| v1 Validator | ✅ | ✅ | ❌ (rejects unknown fields) |
| v2 Validator | ✅ | ✅ | ✅ |
| v1 API | ✅ | ✅ | ⚠️ (ignores v2 fields) |
| v2 API | ✅ | ✅ | ✅ |
| CLI `show` | ✅ | ✅ | ✅ (v2 sections shown if present) |
| VS Code Extension | ✅ | ✅ | ✅ (v2 panels added) |

---

## Rollback

If issues arise, revert to v1:

```bash
# Revert schema_version in _meta
python schema-v2/migration/migrate_v1_to_v2.py \
  --input ave-database/cards/ \
  --rollback

# Validate against v1 schema
python -c "import json, jsonschema; ..."
```

The rollback strips:
- `_meta.schema_version` → `"1.0.0"`
- `_meta.migrated_from` → removed
- `_meta.migration_date` → removed
- `_meta.v2_fields_populated` → removed
- All v2 field groups → removed

---

## Timeline

| Milestone | Date | Action |
|-----------|------|--------|
| v2 Draft Published | 2026-03-26 | RFC-0002 published for review |
| Comment Period | 2026-03-26 – 2026-04-25 | 30-day community review |
| Board Vote | 2026-05-01 | Advisory Board votes on adoption |
| v2 Tooling Ready | 2026-05-15 | Validator, migration, API v2 endpoints |
| Migration Window | 2026-06-01 – 2026-07-01 | Existing cards migrated |
| v2 Default | 2026-07-01 | New cards default to v2 schema |
| v1 Deprecated | 2026-12-31 | v1 schema read-only, no new v1 cards |
