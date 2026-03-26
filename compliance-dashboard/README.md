# AVE Compliance Dashboard

Real-time web dashboard showing organisational compliance posture against the AVE taxonomy, regulatory mappings, and defence coverage.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Compliance Dashboard                       │
│                                                              │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ Posture  │  │  Regulatory  │  │   Defence Coverage     │ │
│  │ Overview │  │  Mapping     │  │   Heat Map             │ │
│  └─────┬────┘  └──────┬───────┘  └──────────┬─────────────┘ │
│        │               │                     │               │
│  ┌─────┴───────────────┴─────────────────────┴─────────────┐ │
│  │              Compliance Engine (FastAPI)                 │ │
│  │                                                         │ │
│  │  ┌─────────────┐ ┌──────────────┐ ┌──────────────────┐ │ │
│  │  │ Assessment  │ │  Regulatory  │ │  Gap Analysis    │ │ │
│  │  │ Engine      │ │  Mapper      │ │  Engine          │ │ │
│  │  └─────────────┘ └──────────────┘ └──────────────────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
│                            │                                 │
│  ┌─────────────────────────┴───────────────────────────────┐ │
│  │                   Data Sources                          │ │
│  │  AVE Database │ Defence Orchestration │ Threat Intel    │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Compliance Frameworks Supported

| Framework | Coverage | Mapping Status |
|-----------|----------|----------------|
| NIST AI RMF | Full | 42 control mappings |
| EU AI Act | Full | 38 requirement mappings |
| ISO/IEC 42001 | Full | 35 clause mappings |
| OWASP LLM Top 10 | Full | 10 category mappings |
| MITRE ATLAS | Full | 28 technique mappings |
| SOC 2 Type II (AI) | Partial | 15 criteria mappings |
| PCI DSS 4.0 (AI) | Partial | 12 requirement mappings |

## Features

### 1. Organisation Posture Overview
- **Compliance Score**: Aggregate score (0-100) across all frameworks
- **Category Coverage**: Per-AVE-category defence coverage percentages
- **Trend Tracking**: 30/60/90-day compliance trend lines
- **Risk Heat Map**: Visual grid of category × framework risk levels

### 2. Regulatory Mapping Engine
- Bi-directional mapping: AVE category → regulatory requirement
- Control gap identification with remediation guidance
- Evidence collection tracking for audit readiness
- Automated compliance report generation (PDF/JSON)

### 3. Defence Coverage Analysis
- Real-time defence deployment status per category
- Coverage gap identification with severity scoring
- Defence effectiveness metrics from DOP integration
- Recommended defence configurations per compliance framework

### 4. Audit Trail & Reporting
- Immutable audit log of all compliance assessments
- Scheduled compliance snapshots (daily/weekly/monthly)
- Custom report builder with template support
- Executive summary generation with KPI dashboards

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/v1/compliance/posture` | Overall compliance posture |
| `GET` | `/v1/compliance/posture/{org_id}` | Organisation-specific posture |
| `GET` | `/v1/compliance/frameworks` | Supported compliance frameworks |
| `GET` | `/v1/compliance/framework/{framework_id}/mapping` | AVE→framework control mapping |
| `GET` | `/v1/compliance/gaps` | Defence coverage gaps |
| `GET` | `/v1/compliance/gaps/{category}` | Category-specific gaps |
| `POST` | `/v1/compliance/assess` | Trigger compliance assessment |
| `GET` | `/v1/compliance/reports` | List generated reports |
| `POST` | `/v1/compliance/reports/generate` | Generate compliance report |
| `GET` | `/v1/compliance/audit-log` | Audit trail entries |
| `GET` | `/v1/compliance/trends` | Historical compliance trends |

## Compliance Scoring

```
Overall Score = Σ (Framework_Weight × Framework_Score)

Framework_Score = Σ (Control_Weight × Control_Status)
  where Control_Status ∈ {1.0 (compliant), 0.5 (partial), 0.0 (non-compliant)}

Category_Coverage = Active_Defences / Required_Defences × 100
```

## Running

```bash
cd compliance-dashboard
pip install fastapi uvicorn pydantic
uvicorn server:app --port 8601
```

## Integration Points

- **AVE Database API** → Vulnerability data and category taxonomy
- **Defence Orchestration Platform** → Active defence status and effectiveness
- **Threat Intel (STIX/TAXII)** → Threat landscape context
- **Knowledge Graph** → Relationship mappings for control coverage
- **Predictive Engine** → Forward-looking risk for compliance planning
