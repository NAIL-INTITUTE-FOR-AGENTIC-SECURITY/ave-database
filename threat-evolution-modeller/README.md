# Threat Evolution Modeller

**Phase 27 — Service 2 of 5 · Port `9911`**

Tracks threat actor TTPs over time, models capability evolution, predicts
emerging attack vectors before they materialise, and provides strategic
intelligence on adversary trajectory.

---

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **Threat Actor Registry** | Register actors with actor_type (nation_state/organised_crime/hacktivist/insider/script_kiddie/apt_group), sophistication_level (1-10), known_ttps, target_sectors, active_since |
| **TTP Tracking** | Record TTP observations per actor: tactic (MITRE ATT&CK aligned), technique, procedure detail, first_seen/last_seen, frequency, effectiveness_rating 0-1 |
| **Capability Timeline** | Per-actor chronological capability log: capability_type (tooling/infrastructure/tradecraft/social_engineering/zero_day/supply_chain), maturity_level (experimental/developing/operational/advanced), observed_date |
| **Evolution Modelling** | Compute actor evolution trajectory: capability_velocity (new capabilities per quarter), sophistication_trend (rising/stable/declining), predicted_next_capabilities based on progression patterns |
| **Attack Vector Prediction** | Predict emerging vectors: combine actor capability trends + vulnerability landscape + target exposure → vector_name, probability 0-1, estimated_time_to_materialise, confidence |
| **Campaign Tracking** | Link actor observations into campaigns: campaign_name, actor_id, ttps_used, targets, timeline, status (active/dormant/concluded) |
| **Threat Landscape** | Aggregate view: active actors by type, dominant TTPs, emerging vectors, sector-specific threat levels |
| **Early Warning** | Alerts when actor capability growth intersects with organisation's exposure profile; configurable warning threshold |
| **Analytics** | Actor distribution, TTP frequency, evolution velocity, prediction accuracy, campaign activity |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + stats |
| `POST` | `/v1/actors` | Register threat actor |
| `GET` | `/v1/actors` | List actors (filter by type/sophistication) |
| `GET` | `/v1/actors/{id}` | Get actor detail + TTPs + evolution |
| `POST` | `/v1/actors/{id}/ttps` | Record TTP observation |
| `POST` | `/v1/actors/{id}/capabilities` | Log capability |
| `GET` | `/v1/actors/{id}/evolution` | Get evolution trajectory |
| `POST` | `/v1/actors/{id}/predict` | Predict next capabilities |
| `POST` | `/v1/campaigns` | Create campaign |
| `GET` | `/v1/campaigns` | List campaigns |
| `GET` | `/v1/landscape` | Threat landscape overview |
| `GET` | `/v1/predictions` | Emerging vector predictions |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Running Locally

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9911 --reload
```

> **Production note:** Replace simulated predictions with ML models trained on MITRE ATT&CK data; integrate with threat intel feeds (STIX/TAXII).
