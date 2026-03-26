# AVE Schema Changelog

All notable changes to the AVE card schema are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] — 2025-07-01

### Summary

AVE Schema v2.0.0 is a **backwards-compatible extension** of v1.0.0. All v1
cards are valid v2 cards. New fields are optional and designed for the multi-agent,
temporal, and composite vulnerability landscape that has emerged since v1's release.

### Added

- **`multi_agent`** (object, optional) — Multi-agent topology and propagation metadata
  - `topology` — enum: hierarchical | mesh | pipeline | hub_spoke | federated
  - `agent_count_min` — minimum agents required
  - `roles_affected` — list of agent roles involved
  - `propagation_pattern` — how the vulnerability spreads across agents
  - `isolation_bypass` — whether the vulnerability crosses isolation boundaries
  - `communication_channels` — channels exploited
  - `trust_boundaries_violated` — trust boundary names

- **`temporal`** (object, optional) — Time-dependent exploitation characteristics
  - `latency_class` — enum: milliseconds | seconds | minutes | hours | days
  - `persistence` — enum: ephemeral | session | persistent | permanent
  - `trigger_type` — what initiates the exploit temporally
  - `time_to_exploit` — ISO 8601 duration
  - `time_to_detect` — ISO 8601 duration
  - `recurrence_pattern` — repetition description

- **`composites`** (object, optional) — Composite vulnerability relationships
  - `chain` — list of AVE IDs that combine
  - `relationship` — enum: amplifies | enables | requires | mitigates
  - `combined_severity_delta` — severity change when combined
  - `composition_notes` — free-text explanation

- **`attack_graph`** (object, optional) — Kill-chain style attack graph
  - `kill_chain` — ordered array of attack steps
  - `entry_points` — list of initial access methods
  - `complexity` — enum: low | medium | high | expert
  - `automation_potential` — enum: none | low | medium | high | full

- **`provenance`** (object, optional) — Discovery and verification metadata
  - `discovery_method` — enum: red_team_exercise | bug_bounty | academic_research | incident_response | automated_scan | community_report
  - `reproducibility` — enum: deterministic | probabilistic | non_deterministic | environment_specific
  - `confidence` — enum: low | medium | high | confirmed
  - `independent_confirmations` — integer count
  - `reproduction_environments` — list of environments tested
  - `peer_review_status` — enum: not_reviewed | under_review | reviewed | contested

- **`affected_components`** (array, optional) — Affected vendor components
  - Each item: `component`, `vendor`, `versions_affected`, `versions_fixed`, `cpe`

- **`counterfactual`** (object, optional) — "What-if" analysis
  - `boundary_conditions` — list of conditions for exploit/mitigation
  - `what_if_mitigated` — narrative of impact if mitigated
  - `residual_risk` — remaining risk after mitigation

- **`regulatory_impact`** (object, optional) — Regulatory compliance mapping
  - `eu_ai_act` — EU AI Act classification and article references
  - `nist_ai_rmf` — NIST AI RMF function and profile mapping
  - `iso_42001` — ISO 42001 control mapping

- **7 new categories**: `multi_agent_collusion`, `temporal_exploitation`, `composite`, `supply_chain`, `model_extraction`, `emergent_behaviour`, `environmental_manipulation`

- **1 new status**: `superseded`

- **AVSS v2 modifiers** (optional sub-objects of `avss_score`):
  - `agentic_modifier` — autonomy_level, tool_access_scope, human_oversight_gap, delegation_depth_factor
  - `temporal_modifier` — exploit_maturity, remediation_level, report_confidence
  - `composite_modifier` — chain_amplification, prerequisite_difficulty
  - `environmental_modifier` — deployment_prevalence, target_value, collateral_damage

- **`_meta` extensions**: `migrated_from`, `migration_date`, `v2_fields_populated`

### Changed

- `category` enum: added 7 new values (non-breaking — existing values unchanged)
- `status` enum: added `superseded` value (non-breaking)
- `avss_score`: extended with optional modifier sub-objects (non-breaking)
- `_meta`: extended with optional fields (non-breaking)

### Migration

- **No breaking changes** — all v1 cards validate against v2 schema
- Migration tool: `schema-v2/migration/migrate_v1_to_v2.py`
- Migration guide: `schema-v2/migration/migration_guide.md`
- Compatibility matrix: `schema-v2/migration/compatibility_matrix.yaml`
- Dual-support period: 6 months (until 2026-01-01)

---

## [1.0.0] — 2025-01-15

### Summary

Initial AVE card schema. 24 top-level fields, 17 required. JSON Schema Draft-07.

### Fields

- `ave_id` (string, required) — Unique identifier, format: AVE-YYYY-NNNN
- `name` (string, required) — Human-readable vulnerability name
- `aliases` (array, required) — Alternative names
- `category` (string, required) — 13 categories from `prompt_injection` to `monitoring_evasion`
- `severity` (string, required) — critical | high | medium | low | informational
- `status` (string, required) — published | draft | deprecated | under-review | proven | proven_mitigated | not_proven | theoretical
- `summary` (string, required) — Brief description
- `mechanism` (string, required) — Technical exploitation mechanism
- `blast_radius` (string, required) — Scope of impact
- `prerequisite` (string, required) — Conditions required for exploitation
- `environment` (object, required) — Deployment context
- `evidence` (array, required) — Supporting evidence
- `defences` (array, required) — Mitigation strategies
- `date_discovered` (string, required) — ISO 8601 date
- `date_published` (string, required) — ISO 8601 date
- `cwe_mapping` (string, required) — CWE identifier
- `mitre_mapping` (string, required) — MITRE ATT&CK technique
- `references` (array, optional) — URLs
- `related_aves` (array, optional) — Related AVE IDs
- `avss_score` (object, optional) — base, exploitability, impact
- `poc` (string, optional) — Proof of concept
- `timeline` (array, optional) — Event timeline
- `_meta` (object, optional) — schema_version, created, last_updated, source
- `contributor` (string, optional) — Attribution

### Specification

- RFC: `schema/AVE-RFC-0001.md`
- JSON Schema: `schema/ave-card-v1.schema.json`
- `$id`: `https://nailinstitute.org/schemas/ave-card-v1.0.0.json`
- `additionalProperties`: false (strict mode)
