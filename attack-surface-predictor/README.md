# Attack Surface Predictor

**Phase 27 — Service 1 of 5 · Port `9910`**

ML-driven attack surface analysis that models how system changes expand or
contract the attack surface, with predictive risk scoring, change-impact
forecasting, and continuous surface monitoring.

---

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **Asset Registry** | Register assets with asset_type (service/api/database/storage/network/compute/model), exposure_level (public/internal/restricted/isolated), technology_stack, dependencies list |
| **Surface Mapping** | Auto-map attack surface: entry_points (ports/endpoints/protocols), data_flows, trust_boundaries; composite surface_area score 0-1000 based on exposure × complexity × connectivity |
| **Change Ingestion** | Ingest system changes with change_type (deploy/config_change/dependency_update/infra_scale/feature_toggle/access_grant/decommission), affected_assets, change_magnitude (minor/moderate/major/critical) |
| **Impact Prediction** | Per-change surface delta prediction: surface_before → surface_after, delta_percentage, new_entry_points exposed, trust_boundaries crossed, risk_score_delta |
| **Risk Scoring** | Multi-factor risk: exposure (30%) + vulnerability_density (25%) + connectivity (20%) + data_sensitivity (15%) + change_velocity (10%); score 0-100 with trend |
| **Trend Forecasting** | 7/30/90-day surface area forecast using exponential smoothing on change history; breach probability estimate based on surface growth rate |
| **Hotspot Detection** | Identify assets with highest risk acceleration; cluster analysis for correlated risk growth |
| **Reduction Recommendations** | Auto-generated recommendations: reduce_exposure / harden_entry_point / isolate_asset / decomission_unused / restrict_access; effort estimate per recommendation |
| **Analytics** | Surface area distribution, risk score trends, change impact history, hotspot map, forecast accuracy |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + stats |
| `POST` | `/v1/assets` | Register asset |
| `GET` | `/v1/assets` | List assets (filter by type/exposure) |
| `GET` | `/v1/assets/{id}` | Get asset detail + surface metrics |
| `POST` | `/v1/changes` | Ingest system change |
| `GET` | `/v1/changes` | List changes |
| `POST` | `/v1/changes/{id}/predict` | Predict change impact |
| `GET` | `/v1/surface` | Current surface overview |
| `GET` | `/v1/surface/forecast` | Surface area forecast |
| `GET` | `/v1/hotspots` | Risk hotspots |
| `GET` | `/v1/recommendations` | Reduction recommendations |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Running Locally

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9910 --reload
```

> **Production note:** Replace simulated predictions with real infrastructure scanning (Shodan/Nmap integration) and ML-based surface modelling.
