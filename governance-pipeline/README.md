# ⚙️ Governance-as-Code Pipeline

> CI/CD integration that enforces governance policies as code gates, blocking
> deployments that violate risk appetite or compliance requirements.

**Phase 14 · Item 5 · Port 8804**

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                      GOVERNANCE-AS-CODE PIPELINE                          │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ Policy   │ Gate     │ Scan     │ Compli-  │ Report   │ Webhook             │
│ Parser   │ Evaluator│ Engine   │ ance     │ Generator│ Integrator          │
│ (GaC DSL)│          │          │ Checker  │          │                     │
├──────────┴──────────┴──────────┴──────────┴──────────┴─────────────────────┤
│                      CI/CD INTEGRATION LAYER                              │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ GitHub   │ GitLab   │ Jenkins  │ Azure    │ Generic  │ Manual              │
│ Actions  │ CI       │          │ DevOps   │ Webhook  │ Trigger             │
└──────────┴──────────┴──────────┴──────────┴──────────┴─────────────────────┘
```

## Concepts

| Concept | Description |
|---------|-------------|
| **GaC Policy** | Governance rule written in declarative DSL with pass/fail conditions |
| **Gate** | CI/CD checkpoint that must pass before deployment proceeds |
| **Scan** | Automated analysis of deployment artefact against GaC policies |
| **Verdict** | Pass / Fail / Warn result for each gate evaluation |
| **Pipeline Run** | A complete evaluation of all gates for a deployment |

## Key Features

1. **Declarative Policy DSL** — Define governance rules as code (YAML/JSON)
2. **Multi-Gate Pipeline** — Chain multiple governance gates in sequence
3. **CI/CD Webhooks** — Native integration with GitHub Actions, GitLab CI, Jenkins, Azure DevOps
4. **Risk Appetite Check** — Block deployments exceeding org risk tolerance
5. **Compliance Scan** — Validate against NIST AI RMF, EU AI Act, ISO 42001, OWASP LLM
6. **AVE Coverage Gate** — Ensure minimum defence coverage per AVE category
7. **Verdicts & Reports** — Detailed pass/fail reports with remediation guidance
8. **Manual Override** — Authorised escalation path for emergency deployments

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/policies` | Create a GaC policy |
| `GET` | `/v1/policies` | List GaC policies |
| `GET` | `/v1/policies/{id}` | Policy details |
| `POST` | `/v1/gates` | Create a gate definition |
| `GET` | `/v1/gates` | List gates |
| `POST` | `/v1/pipelines` | Create a governance pipeline |
| `GET` | `/v1/pipelines` | List pipelines |
| `GET` | `/v1/pipelines/{id}` | Pipeline details |
| `POST` | `/v1/pipelines/{id}/run` | Execute a pipeline run |
| `GET` | `/v1/runs` | List pipeline runs |
| `GET` | `/v1/runs/{id}` | Run details with verdicts |
| `POST` | `/v1/runs/{id}/override` | Manual override for a failed gate |
| `POST` | `/v1/webhook` | CI/CD webhook receiver |
| `GET` | `/v1/analytics` | Pipeline analytics |

## Running

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 8804 --reload
```

Docs at http://localhost:8804/docs
