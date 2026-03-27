# Cross-Org Policy Harmoniser

**Phase 24 — Service 3 of 5 · Port `9802`**

Policy alignment engine that reconciles security policies across
organisational boundaries with conflict detection, resolution
strategies, and harmonised policy generation.

---

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **Policy Registry** | Register policies from multiple organisations with domain (access_control/data_handling/incident_response/encryption/retention/ai_governance/network_security/identity_management), enforcement level (mandatory/recommended/advisory/informational), applicable jurisdictions |
| **Policy Rules** | Define granular rules within policies with subject/action/resource/condition/effect (allow/deny/require/restrict/audit), priority weighting |
| **Conflict Detection** | Automatic pairwise conflict analysis across organisations; 5 conflict types (direct_contradiction/scope_overlap/precedence_ambiguity/jurisdiction_clash/enforcement_mismatch); severity scoring |
| **Resolution Strategies** | 4 strategies: strictest_wins (highest enforcement) / most_permissive / weighted_merge (priority-weighted) / manual_review; auto-apply or queue for human review |
| **Harmonisation Sessions** | Create sessions selecting organisations + domains + strategy; run harmonisation to detect conflicts, apply resolutions, produce unified policy set |
| **Harmonised Output** | Merged rule set with provenance tracking (which org contributed each rule), conflict resolution audit trail |
| **Gap Analysis** | Identify domains where participating orgs lack coverage; produce gap report with recommendations |
| **Version Tracking** | Full version history on policies; diff between versions |
| **Analytics** | Policy coverage by domain/org, conflict rates, resolution strategy effectiveness, gap distribution |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + stats |
| `POST` | `/v1/policies` | Register policy |
| `GET` | `/v1/policies` | List policies (filter by org/domain/enforcement) |
| `GET` | `/v1/policies/{id}` | Get policy detail |
| `POST` | `/v1/policies/{id}/rules` | Add rule to policy |
| `GET` | `/v1/policies/{id}/rules` | List policy rules |
| `POST` | `/v1/harmonise` | Create & run harmonisation session |
| `GET` | `/v1/sessions` | List harmonisation sessions |
| `GET` | `/v1/sessions/{id}` | Get session detail with conflicts + resolutions |
| `GET` | `/v1/sessions/{id}/gaps` | Gap analysis for session |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Running Locally

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9802 --reload
```

> **Production note:** Replace in-memory stores with graph database for policy relationship modelling and integrate with OPA (Open Policy Agent) for enforcement.
