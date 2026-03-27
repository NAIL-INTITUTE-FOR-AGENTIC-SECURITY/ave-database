# Autonomous Compliance Auditor

> Phase 20 · Service 5 of 5 · Port **9404**

Continuous compliance monitoring and audit report generation across global regulatory frameworks with evidence collection, control mapping, gap analysis, remediation tracking, and audit-ready reporting.

## Core Capabilities

### 1. Regulatory Framework Registry

- **6 frameworks**: EU AI Act, NIST AI RMF 1.0, ISO 27001:2022, ISO 42001:2023, SOC 2 Type II, OWASP Top 10 for LLM
- Per-framework: articles/controls, requirement text, applicability criteria, effective dates
- Cross-framework control mapping: identify equivalent requirements across frameworks
- Framework versioning with change tracking

### 2. Control Library

- Standardised controls mapped to one or more framework requirements
- 5 control domains: governance, technical, operational, human_oversight, transparency
- Per-control: implementation status (not_started/in_progress/implemented/verified/non_applicable), owner, evidence requirements
- Automated control inheritance: implementing one control satisfies mapped requirements across frameworks

### 3. Evidence Collection

- Structured evidence submission: documents, configurations, logs, attestations, screenshots
- Evidence linking: map evidence to specific controls and requirements
- Evidence freshness tracking: stale evidence alerts when older than configurable threshold (default 90 days)
- Chain of custody: who submitted, when, hash integrity verification

### 4. Continuous Monitoring

- Automated compliance checks against NAIL platform services
- 5 check types: configuration audit, policy review, access control verification, log completeness, encryption status
- Check scheduling: continuous (every 6 hours), daily, weekly, on-demand
- Finding severity: critical, high, medium, low, informational
- Auto-remediation suggestions for common findings

### 5. Gap Analysis

- Per-framework compliance score (0-100%) based on control implementation status
- Gap identification: unimplemented or unverified controls
- Risk-ranked gap prioritisation based on control criticality and framework enforcement timeline
- Remediation effort estimation (hours) per gap

### 6. Audit Reporting

- On-demand audit report generation per framework
- Report sections: executive summary, scope, methodology, findings, evidence matrix, remediation plan
- 3 report formats: detailed (internal), summary (board), regulatory (submission-ready)
- Historical report archive with diff between audit periods
- Auditor notes and sign-off tracking

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/frameworks` | List regulatory frameworks |
| GET | `/v1/frameworks/{framework_id}` | Get framework with requirements |
| GET | `/v1/controls` | List controls |
| POST | `/v1/controls` | Create/update control |
| GET | `/v1/controls/{control_id}` | Get control with evidence |
| POST | `/v1/evidence` | Submit evidence |
| GET | `/v1/evidence` | List evidence |
| POST | `/v1/checks/run` | Trigger compliance check |
| GET | `/v1/checks` | List check results |
| GET | `/v1/gaps/{framework_id}` | Gap analysis for framework |
| POST | `/v1/reports/generate` | Generate audit report |
| GET | `/v1/reports` | List reports |
| GET | `/v1/reports/{report_id}` | Get report |
| GET | `/v1/analytics` | Auditor-wide analytics |
| GET | `/health` | Health check |

## Design Decisions

- **Framework-agnostic control library** — Controls are the unit of work; frameworks map to controls, not the other way around
- **Evidence is immutable** — Once submitted, evidence cannot be modified, only superseded; full chain of custody
- **Compliance scores are conservative** — Only "verified" controls count toward compliance percentage; "implemented but unverified" does not
