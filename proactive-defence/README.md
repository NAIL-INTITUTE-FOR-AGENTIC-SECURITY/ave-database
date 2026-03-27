# Proactive Defence Orchestrator

**Phase 27 — Service 4 of 5 · Port `9913`**

Anticipatory defence system that deploys countermeasures before attacks
manifest based on threat intelligence signals, behavioural indicators,
and predictive risk models.

---

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **Signal Ingestion** | Collect intelligence signals: signal_type (threat_intel/anomaly_detection/behaviour_indicator/vulnerability_disclosure/dark_web_mention/geopolitical_event), source, confidence 0-1, relevance_score 0-1 |
| **Threat Correlation** | Correlate multiple signals into threat hypotheses: hypothesis_name, contributing_signals, combined_confidence, attack_type prediction, target_assets, estimated_time_to_attack |
| **Countermeasure Library** | Pre-defined countermeasures: cm_type (firewall_rule/access_restriction/rate_limit/isolation/backup_trigger/monitoring_increase/credential_rotation/patch_acceleration/deception_deploy), deployment_time_minutes, risk_of_disruption (low/medium/high), reversible flag |
| **Deployment Engine** | Deploy countermeasures per hypothesis: deployment_state (queued→deploying→active→monitoring→withdrawn), target_scope (specific_asset/subnet/organisation_wide), auto-withdraw after TTL |
| **Playbook Automation** | Pre-built response playbooks: playbook maps signal patterns → ordered countermeasure sequences; trigger conditions with confidence threshold |
| **Impact Assessment** | Pre-deployment impact analysis: affected_services, estimated_downtime, user_impact_level (none/minor/moderate/significant), approval_required for high-impact |
| **Effectiveness Tracking** | Post-deployment metrics: attacks_prevented (based on subsequent observation), false_positive_rate, disruption_caused, time_to_deploy |
| **Signal Fusion** | Weighted combination of multiple signals: temporal proximity bonus, source diversity bonus, corroboration multiplier |
| **Analytics** | Signals by type/source, hypotheses by confidence, countermeasures deployed/active/withdrawn, effectiveness rates, response time distribution |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + stats |
| `POST` | `/v1/signals` | Ingest signal |
| `GET` | `/v1/signals` | List signals |
| `POST` | `/v1/hypotheses` | Create threat hypothesis |
| `GET` | `/v1/hypotheses` | List hypotheses |
| `GET` | `/v1/hypotheses/{id}` | Get hypothesis detail |
| `POST` | `/v1/countermeasures` | Register countermeasure |
| `GET` | `/v1/countermeasures` | List countermeasures |
| `POST` | `/v1/hypotheses/{id}/deploy` | Deploy countermeasure for hypothesis |
| `POST` | `/v1/deployments/{id}/withdraw` | Withdraw countermeasure |
| `POST` | `/v1/hypotheses/{id}/impact` | Pre-deployment impact assessment |
| `GET` | `/v1/effectiveness` | Effectiveness metrics |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Running Locally

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9913 --reload
```

> **Production note:** Replace simulated deployments with real infrastructure integration (WAF/SIEM/SOAR); add STIX/TAXII feed ingestion for automated signal collection.
