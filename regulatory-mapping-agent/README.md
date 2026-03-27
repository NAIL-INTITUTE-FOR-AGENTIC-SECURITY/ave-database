# Regulatory Mapping Agent

**Phase 31 · Service 4 of 5 · Port 9933**

Dynamically maps platform operations to regulatory frameworks (GDPR, NIST, ISO 27001, etc.) and identifies compliance gaps in real-time.

## Quick Start

```bash
pip install fastapi uvicorn
uvicorn server:app --host 0.0.0.0 --port 9933
```

## Capabilities

| Capability | Description |
|---|---|
| Framework Registry | Register regulatory frameworks (8 types: gdpr / nist_csf / iso_27001 / soc2 / hipaa / pci_dss / ai_act / ccpa) with version, jurisdiction, effective date, and control catalogue |
| Control Catalogue | Define controls per framework with control_id, title, description, category, and criticality (low / medium / high / critical) |
| Operation Registry | Register platform operations (7 types: data_collection / data_processing / automated_decision / model_training / threat_response / access_control / incident_handling) with data types involved, jurisdictions, and AI involvement flag |
| Mapping Engine | Auto-map operations to applicable framework controls based on operation type, data types, jurisdictions, and AI involvement; confidence scoring per mapping |
| Gap Analysis | Identify operations with no mapped controls (uncovered) or controls with no implementing operations (unimplemented); risk-scored by control criticality |
| Jurisdiction Resolver | Given operation jurisdictions, determine which frameworks apply; handle multi-jurisdiction operations with overlapping requirements |
| Change Impact Assessment | When framework version changes, identify affected operations and mappings; generate re-certification checklist |
| Compliance Scoring | Per-framework compliance score: mapped_and_implemented / total_applicable_controls × 100; breakdown by control category |
| Real-Time Alerts | Flag new operations that lack regulatory mapping; alert when compliance score drops below threshold |
| Analytics | Frameworks registered, operations mapped, gap count, compliance scores, jurisdiction coverage |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/frameworks` | Register regulatory framework |
| `GET` | `/v1/frameworks` | List frameworks |
| `GET` | `/v1/frameworks/{id}` | Framework detail with controls |
| `POST` | `/v1/frameworks/{id}/controls` | Add control to framework |
| `POST` | `/v1/operations` | Register platform operation |
| `GET` | `/v1/operations` | List operations |
| `GET` | `/v1/operations/{id}` | Operation detail with mappings |
| `POST` | `/v1/map` | Run mapping engine |
| `GET` | `/v1/gaps` | Gap analysis |
| `GET` | `/v1/frameworks/{id}/compliance` | Framework compliance score |
| `GET` | `/v1/jurisdictions/{code}` | Jurisdiction framework resolver |
| `POST` | `/v1/frameworks/{id}/assess-change` | Change impact assessment |
| `GET` | `/v1/analytics` | Regulatory mapping analytics |

## Design Notes

- In-memory stores — production would use graph database for relationship mapping
- Auto-mapping uses rule-based matching on operation type + data types + jurisdiction
- Gap analysis is bidirectional: uncovered operations AND unimplemented controls
- Multi-jurisdiction operations may map to multiple frameworks simultaneously
