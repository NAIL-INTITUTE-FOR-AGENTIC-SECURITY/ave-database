# AI Ethics Tribunal

> **Phase 21 — Service 3 of 5 · Port `9502`**

Multi-stakeholder ethical review board with case submission, structured
deliberation workflows, precedent tracking, binding resolution enforcement,
and recusal/conflict-of-interest management.

---

## Key Capabilities

| Capability | Detail |
|------------|--------|
| **Tribunal Panel** | Panellist registry with 5 roles (`chief_justice` / `justice` / `advocate` / `technical_expert` / `public_representative`), expertise domains, term limits, recusal tracking, conflict-of-interest declarations |
| **Case Management** | 7-stage pipeline (`filed` → `screening` → `panel_assigned` → `deliberation` → `voting` → `resolution` → `enforcement`), 8 case categories (`bias_discrimination` / `privacy_violation` / `autonomy_override` / `safety_harm` / `transparency_failure` / `accountability_gap` / `consent_violation` / `environmental_impact`), severity and urgency scoring |
| **Deliberation Workflow** | Structured argument submission (supporting/opposing/amicus), evidence attachment, rebuttal rounds, time-boxed deliberation periods, mandatory minimum deliberation before vote |
| **Voting & Resolution** | 3 voting methods (`simple_majority` / `supermajority` / `unanimous`), quorum enforcement (default 60%), dissenting opinion capture, binding/advisory resolution types, remediation orders |
| **Precedent System** | Resolution indexing by category + principle, precedent search with relevance scoring, stare decisis weight in future deliberations, precedent override requiring supermajority |
| **Enforcement** | Resolution tracking with compliance deadlines, escalation for non-compliance, periodic compliance audits, public transparency reports |

## AVE Integration

18 AVE categories map to ethical dimensions — `alignment_subversion` triggers
autonomy-override cases, `goal_hijacking` raises accountability-gap reviews,
`output_manipulation` feeds bias-discrimination assessments.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/panellists` | Register panellist |
| `GET` | `/v1/panellists` | List panellists |
| `POST` | `/v1/cases` | File a case |
| `GET` | `/v1/cases` | List cases |
| `GET` | `/v1/cases/{case_id}` | Case detail |
| `POST` | `/v1/cases/{case_id}/arguments` | Submit argument |
| `POST` | `/v1/cases/{case_id}/vote` | Cast vote |
| `GET` | `/v1/cases/{case_id}/resolution` | Get resolution |
| `POST` | `/v1/cases/{case_id}/enforce` | Initiate enforcement |
| `GET` | `/v1/precedents` | Search precedents |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Running

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9502
```

> **Note:** In-memory stores for development. Production should persist
> cases and precedents in an immutable audit-grade database.
