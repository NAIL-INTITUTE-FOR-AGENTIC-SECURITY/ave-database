# Inter-Agency Compliance Bridge

**Phase 24 — Service 5 of 5 · Port `9804`**

Automated compliance evidence sharing across regulatory boundaries with
audit trail federation, mutual recognition agreements, and cross-jurisdiction
equivalence mapping.

---

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **Agency Registry** | Register regulatory agencies with jurisdiction, domain (data_protection/ai_safety/financial_services/healthcare/critical_infrastructure/telecom/energy/general), authority level (primary/secondary/advisory) |
| **Compliance Frameworks** | Define frameworks with requirements; map requirements to control categories (technical/administrative/physical/procedural); track version per framework |
| **Evidence Packages** | Submit compliance evidence with evidence_type (audit_report/certification/test_result/policy_document/incident_report/assessment/attestation), classification (public/restricted/confidential), SHA-256 integrity hash, submitting organisation + target agency |
| **Evidence Lifecycle** | 5-state workflow: submitted → under_review → accepted → rejected → expired; reviewer notes; expiry tracking |
| **Mutual Recognition Agreements** | Bilateral or multilateral agreements between agencies recognising each other's frameworks/certifications; scope definition with framework_ids + evidence_types + validity_period |
| **Equivalence Mapping** | Map requirements across frameworks (Framework A Req 1 ↔ Framework B Req 3) with equivalence_strength (full/partial/conditional) + mapping rationale; auto-discover transitive equivalences |
| **Cross-Jurisdiction Audit Trail** | Federated audit log across agencies; every evidence submission, review, acceptance, rejection, and recognition event logged with agency attribution |
| **Compliance Passport** | Generate a compliance passport for an organisation aggregating all accepted evidence across agencies + recognised equivalences into a single portable credential |
| **Analytics** | Evidence volume by type/status/agency, framework coverage, MRA network density, equivalence mapping coverage, avg review time |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + stats |
| `POST` | `/v1/agencies` | Register agency |
| `GET` | `/v1/agencies` | List agencies |
| `POST` | `/v1/frameworks` | Create compliance framework |
| `GET` | `/v1/frameworks` | List frameworks |
| `POST` | `/v1/frameworks/{id}/requirements` | Add requirement |
| `POST` | `/v1/evidence` | Submit evidence package |
| `GET` | `/v1/evidence` | List evidence (filter by org/agency/status) |
| `PATCH` | `/v1/evidence/{id}/review` | Review evidence (accept/reject) |
| `POST` | `/v1/agreements` | Create mutual recognition agreement |
| `GET` | `/v1/agreements` | List MRAs |
| `POST` | `/v1/equivalences` | Create requirement equivalence mapping |
| `GET` | `/v1/equivalences` | List equivalence mappings |
| `GET` | `/v1/passport/{org}` | Generate compliance passport |
| `GET` | `/v1/audit-trail` | Federated audit trail |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Running Locally

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9804 --reload
```

> **Production note:** Replace in-memory stores with distributed ledger for tamper-proof audit trails and add PKI-based agency authentication.
