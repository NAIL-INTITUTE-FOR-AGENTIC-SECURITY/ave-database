# AVE-RFC-0002: AVE Card Format Specification v2.0.0

| Field | Value |
|-------|-------|
| **RFC** | AVE-RFC-0002 |
| **Title** | AVE Card Format Specification v2.0.0 |
| **Status** | Draft |
| **Version** | 2.0.0 |
| **Supersedes** | AVE-RFC-0001 (v1.0.0) |
| **Author** | NAIL Institute |
| **Created** | 2026-03-26 |
| **Category** | Standards Track |

---

## 1. Abstract

This RFC defines version 2.0.0 of the Agentic Vulnerability Enumeration
(AVE) card format. It extends the v1.0.0 schema (AVE-RFC-0001) with
eight new optional field groups to support multi-agent vulnerability
scenarios, temporal attack patterns, composite vulnerability chains,
attack graphs, provenance tracking, affected component enumeration,
counterfactual analysis, and regulatory impact mapping.

All v1.0.0 cards remain valid under this specification. New fields
are OPTIONAL and do not affect the validity of existing entries.

---

## 2. Motivation

The v1.0.0 schema was designed for individual agent vulnerabilities
in controlled environments. As the agentic AI landscape matures,
the following gaps have emerged:

1. **Multi-agent complexity** — v1 records `multi_agent: true/false`
   but cannot describe agent roles, topologies, or propagation paths
   across agent boundaries.

2. **Temporal dynamics** — Sleeper payloads, progressive degradation,
   and time-delayed attacks cannot be characterised in v1.

3. **Composite vulnerabilities** — Vulnerability chains where AVE-A
   enables AVE-B (or where combining AVEs amplifies severity) have
   no formal representation.

4. **Attack modelling** — No kill-chain or attack-graph support for
   understanding multi-step exploitation paths.

5. **Provenance** — Discovery method, reproducibility, and confidence
   levels are not captured, limiting research utility.

6. **Component targeting** — v1's flat `environment` cannot express
   which specific components (memory stores, tool interfaces, model
   APIs) are affected at granular version levels.

7. **Regulatory mapping** — EU AI Act, NIST AI RMF, and ISO 42001
   compliance requirements cannot be linked to specific AVEs.

---

## 3. Specification — Existing Fields (Unchanged)

All fields defined in AVE-RFC-0001 §3–§15 remain unchanged. The
following 24 top-level fields retain their v1.0.0 definitions:

**Required (17):** `ave_id`, `name`, `aliases`, `category`, `severity`,
`status`, `summary`, `mechanism`, `blast_radius`, `prerequisite`,
`environment`, `evidence`, `defences`, `date_discovered`,
`date_published`, `cwe_mapping`, `mitre_mapping`

**Optional (7):** `references`, `related_aves`, `avss_score`, `poc`,
`timeline`, `_meta`, `contributor`

### 3.1 Category Enumeration (Extended)

The following categories are ADDED to the v1.0.0 set:

| Category | Description |
|----------|-------------|
| `multi_agent_collusion` | Coordinated malicious behaviour between agents |
| `temporal_exploitation` | Time-dependent or delayed vulnerability triggers |
| `composite` | Vulnerabilities requiring multiple AVEs in combination |
| `supply_chain` | Vulnerabilities in agent dependencies, plugins, or tools |
| `model_extraction` | Extraction of model weights, training data, or capabilities |
| `emergent_behaviour` | Unintended behaviours arising from agent interactions |
| `environmental_manipulation` | Attacks targeting the agent's operating environment |

**Full v2 category set**: All 13 v1 categories + 7 new = **20 categories**.

### 3.2 Status Values (Extended)

One new status is added:

| Status | Description |
|--------|-------------|
| `superseded` | Replaced by a newer, more specific AVE entry |

---

## 4. Specification — New Fields

All new fields are OPTIONAL. Their absence does not invalidate a card.

### 4.1 `multi_agent` (Object)

Describes vulnerability behaviour in multi-agent systems.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `topology` | string (enum) | Yes | Agent arrangement: `hierarchical`, `flat`, `swarm`, `pipeline`, `hub_spoke`, `mesh` |
| `agent_count_min` | integer | Yes | Minimum agents needed to trigger (≥ 2) |
| `agent_count_max` | integer | No | Maximum agents affected (null = unbounded) |
| `roles_affected` | string[] | Yes | Agent roles involved: `orchestrator`, `worker`, `validator`, `tool_agent`, `memory_agent`, `gateway`, `monitor` |
| `propagation_pattern` | string (enum) | Yes | How the vulnerability spreads: `lateral`, `vertical`, `broadcast`, `cascading`, `contained` |
| `isolation_bypass` | boolean | Yes | Whether the vulnerability crosses agent isolation boundaries |
| `cross_framework` | boolean | No | Whether the vulnerability spans different agent frameworks |
| `communication_vector` | string (enum) | No | Communication channel exploited: `shared_memory`, `message_passing`, `tool_output`, `environment`, `side_channel` |

### 4.2 `temporal` (Object)

Describes time-dependent vulnerability characteristics.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `latency_class` | string (enum) | Yes | Time profile: `immediate` (< 1s), `delayed` (1s–1hr), `sleeper` (1hr–7d), `progressive` (gradually worsening) |
| `persistence` | string (enum) | Yes | Duration: `ephemeral` (single turn), `session` (single session), `persistent` (across sessions), `permanent` (survives reset) |
| `trigger_type` | string (enum) | Yes | What initiates: `immediate`, `conditional`, `time_based`, `event_based`, `stochastic` |
| `trigger_condition` | string | No | Human-readable description of trigger condition |
| `observation_window_hours` | number | No | Recommended observation period to detect (in hours) |
| `recurrence` | string (enum) | No | Pattern: `one_shot`, `periodic`, `escalating`, `adaptive` |
| `mean_time_to_manifest` | number | No | Average seconds from injection to observable effect |
| `detection_lag` | number | No | Average seconds between manifestation and detection |

### 4.3 `composites` (Object)

Describes relationships between vulnerabilities that combine or chain.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `chain` | string[] | Yes | Ordered list of AVE IDs in the chain |
| `relationship` | string (enum) | Yes | How AVEs relate: `prerequisite` (A enables B), `amplifier` (A increases B severity), `enabler` (A makes B easier), `co_requisite` (both needed simultaneously) |
| `combined_severity_delta` | number | No | Severity increase when combined vs individual (±0.0–10.0) |
| `chain_probability` | number | No | Likelihood of full chain execution (0.0–1.0) |
| `weakest_link` | string | No | AVE ID of the easiest-to-mitigate link |
| `notes` | string | No | Description of composite interaction |

### 4.4 `attack_graph` (Object)

Describes the multi-step exploitation path.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kill_chain` | string[] | Yes | Ordered stages: `reconnaissance`, `weaponisation`, `delivery`, `initial_access`, `execution`, `persistence`, `privilege_escalation`, `lateral_movement`, `exfiltration`, `impact` |
| `entry_points` | string[] | Yes | Attack surface: `user_input`, `tool_response`, `memory_read`, `api_call`, `environment_variable`, `model_output`, `inter_agent_message` |
| `branching_factor` | integer | No | Average number of exploitation choices per stage |
| `shortest_path_steps` | integer | No | Minimum steps from entry to impact |
| `longest_path_steps` | integer | No | Maximum steps (worst-case scenario) |
| `requires_human` | boolean | No | Whether a human must participate in the chain |
| `automation_level` | string (enum) | No | `fully_automated`, `semi_automated`, `manual` |

### 4.5 `provenance` (Object)

Describes how the vulnerability was discovered and validated.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `discovery_method` | string (enum) | Yes | How found: `manual_testing`, `automated_fuzzing`, `red_team`, `incident_response`, `academic_research`, `community_report`, `automated_scanning` |
| `reproducibility` | string (enum) | Yes | Reliability: `deterministic` (always), `high_probability` (>80%), `probabilistic` (20–80%), `environment_dependent`, `rare` (<20%) |
| `confidence` | number | Yes | Confidence level 0.0–1.0 |
| `independent_confirmations` | integer | No | Number of independent teams confirming |
| `first_seen_in_wild` | boolean | No | Whether observed in real-world (not lab) conditions |
| `discovery_date` | string (date) | No | When first identified (may differ from `date_discovered`) |
| `reporter_type` | string (enum) | No | Who reported: `researcher`, `vendor`, `operator`, `automated_system`, `anonymous` |
| `cvss_equivalent` | number | No | Approximate CVSS 3.1 equivalent score for cross-referencing |

### 4.6 `affected_components` (Array of Objects)

Lists specific software components affected.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `component` | string | Yes | Component type: `memory_store`, `tool_interface`, `model_api`, `orchestrator`, `planner`, `retrieval_engine`, `communication_bus`, `monitoring`, `auth_module` |
| `vendor` | string | Yes | Framework/vendor name |
| `product` | string | No | Specific product name |
| `version_range` | string | No | Affected versions (semver range syntax) |
| `cpe` | string | No | CPE 2.3 identifier if available |
| `fixed_in` | string | No | Version where vulnerability is resolved |
| `workaround_available` | boolean | No | Whether a workaround exists without upgrading |

### 4.7 `counterfactual` (Object)

Describes boundary conditions and what-if scenarios.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `boundary_conditions` | string[] | Yes | Conditions required for exploitation |
| `what_if_mitigated` | string | Yes | Expected outcome if properly mitigated |
| `residual_risk` | string | No | Remaining risk after mitigation |
| `false_positive_rate` | number | No | Rate of detection false positives (0.0–1.0) |
| `false_negative_rate` | number | No | Rate of detection false negatives (0.0–1.0) |
| `environmental_factors` | string[] | No | External factors affecting exploitability |

### 4.8 `regulatory_impact` (Object)

Maps the vulnerability to regulatory frameworks.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `eu_ai_act` | object | No | `{ risk_level, articles[], obligations[] }` |
| `nist_ai_rmf` | object | No | `{ functions[], categories[], subcategories[] }` |
| `iso_42001` | object | No | `{ clauses[], controls[] }` |
| `iso_27001` | object | No | `{ clauses[], controls[] }` |
| `sector_specific` | object[] | No | Array of `{ regulation, jurisdiction, requirements[] }` |

---

## 5. `_meta` Extensions

The `_meta` object gains the following optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | **MUST** be `"2.0.0"` for v2 cards |
| `migrated_from` | string | Source schema version if migrated (e.g., `"1.0.0"`) |
| `migration_date` | string (datetime) | When migration occurred |
| `v2_fields_populated` | string[] | List of v2 field groups with data |

---

## 6. AVSS Score Extensions

The `avss_score` object gains optional sub-scores:

| Field | Type | Description |
|-------|------|-------------|
| `multi_agent_modifier` | number | Score modifier for multi-agent scenarios (0.0–2.0, 1.0 = neutral) |
| `temporal_modifier` | number | Score modifier for temporal patterns (0.0–2.0) |
| `composite_modifier` | number | Score modifier when part of chain (0.0–2.0) |
| `environmental_modifier` | number | Deployment-specific modifier (0.0–2.0) |

**Extended formula:**

$$\text{AVSS}_{v2} = \text{Base} \times \text{Agentic} \times \text{Temporal} \times \min(\text{MultiAgent} \times \text{Composite} \times \text{Environmental},\ 10.0)$$

Score is capped at 10.0.

---

## 7. Validation Requirements

### 7.1 Mandatory Checks (v1 + v2)

All 12 v1.0.0 mandatory validation checks remain unchanged.

### 7.2 Additional v2 Checks

| # | Check | Severity |
|---|-------|----------|
| V2-01 | If `multi_agent` present, `agent_count_min` ≥ 2 | ERROR |
| V2-02 | If `composites` present, all `chain` AVE IDs must be valid format | ERROR |
| V2-03 | If `provenance.confidence` present, must be 0.0–1.0 | ERROR |
| V2-04 | If `affected_components` present, each must have `component` + `vendor` | ERROR |
| V2-05 | If `temporal` present, `latency_class` must be valid enum | ERROR |
| V2-06 | If `attack_graph` present, `kill_chain` must have ≥ 1 stage | ERROR |
| V2-07 | If `regulatory_impact.eu_ai_act` present, `risk_level` must be valid | ERROR |
| V2-08 | If `_meta.schema_version` is `"2.0.0"`, v2 validation applies | INFO |
| V2-09 | `composites.combined_severity_delta` should be -10.0 to +10.0 | WARNING |
| V2-10 | `avss_score` modifiers should be 0.0–2.0 | WARNING |

---

## 8. File Format

Unchanged from v1.0.0:
- Primary: `.json` (machine-readable)
- Companion: `.md` (human-readable)
- Encoding: UTF-8
- Line endings: LF

v2 companion `.md` files SHOULD include additional sections for
populated v2 fields (Multi-Agent Details, Temporal Profile,
Attack Graph, Regulatory Impact).

---

## 9. Backwards Compatibility

| Scenario | Behaviour |
|----------|-----------|
| v1 card validated against v2 schema | ✅ VALID — new fields are optional |
| v2 card validated against v1 schema | ❌ INVALID — extra fields rejected by `additionalProperties: false` |
| v2 card with `_meta.schema_version: "1.0.0"` | ⚠️ WARNING — mismatch |
| v1 card migrated to v2 | New fields added with null/empty defaults |

Tools MUST check `_meta.schema_version` to determine which validation
rules to apply.

---

## 10. Security Considerations

- New fields (`affected_components.version_range`, `attack_graph`)
  may reveal exploitation details. The existing 3-tier access model
  (public/partner/enterprise) applies to all v2 fields.
- `provenance.first_seen_in_wild` should be redacted in public tier
  for vulnerabilities in active exploitation.
- `regulatory_impact` is always public tier (non-sensitive).

---

## 11. References

- [AVE-RFC-0001] AVE Card Format Specification v1.0.0
- [JSON Schema Draft-07] https://json-schema.org/draft-07/schema
- [MITRE ATT&CK] https://attack.mitre.org/
- [MITRE ATLAS] https://atlas.mitre.org/
- [EU AI Act] Regulation (EU) 2024/1689
- [NIST AI RMF] NIST AI 100-1
- [ISO/IEC 42001:2023] AI Management System Standard
- [CPE 2.3] NIST IR 7695

---

## 12. Changelog

| Version | Date | Change |
|---------|------|--------|
| 2.0.0-draft | 2026-03-26 | Initial v2 draft — 8 new field groups |
