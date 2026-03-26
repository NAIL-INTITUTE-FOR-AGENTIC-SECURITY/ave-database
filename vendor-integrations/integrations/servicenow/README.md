# ServiceNow Integration for NAIL AVE Database

## Overview

Import NAIL AVE agentic AI vulnerability data into ServiceNow for GRC
(Governance, Risk, Compliance), vulnerability management, and ITSM workflows.

## Use Cases

| Use Case | ServiceNow Module | Description |
|----------|-------------------|-------------|
| Vulnerability tracking | Vulnerability Response | Import AVE cards as vulnerability records |
| Risk assessment | GRC Risk Management | Map agentic AI risks to enterprise risk register |
| Compliance | GRC Compliance | Track AI regulation coverage (EU AI Act, NIST) |
| Change management | ITSM Change | Auto-create change requests for mitigations |
| Incident correlation | Security Incident Response | Link AVE IDs to security incidents |

## Architecture

```
NAIL AVE API ──► ServiceNow Integration Hub / Scripted REST
                        │
              ┌─────────┼────────────┐
              │         │            │
         ┌────▼────┐ ┌─▼──────┐ ┌──▼────────┐
         │Vuln     │ │GRC Risk│ │ CMDB CI   │
         │Response │ │Register│ │ (Agents)  │
         └─────────┘ └────────┘ └───────────┘
```

## Quick Start

### 1. Create Custom Table

Create the `x_nail_ave_card` table to store AVE data:

| Field | Type | Label |
|-------|------|-------|
| `u_ave_id` | String (20) | AVE ID |
| `u_name` | String (200) | Vulnerability Name |
| `u_category` | Choice | Category |
| `u_severity` | Choice | Severity |
| `u_status` | Choice | Status |
| `u_summary` | String (4000) | Summary |
| `u_mechanism` | String (4000) | Mechanism |
| `u_blast_radius` | String (1000) | Blast Radius |
| `u_avss_base` | Decimal | AVSS Base Score |
| `u_date_published` | Date | Date Published |
| `u_cwe_mapping` | String (20) | CWE Mapping |
| `u_mitre_mapping` | String (20) | MITRE Mapping |
| `u_defences` | String (4000) | Defences (JSON) |
| `u_raw_json` | String (65000) | Raw AVE Card JSON |

### 2. Create Scripted REST API (Inbound Webhook)

Create a Scripted REST API to receive AVE data:

```javascript
// Scripted REST API: NAIL AVE Webhook
(function process(/*RESTAPIRequest*/ request, /*RESTAPIResponse*/ response) {

    var body = request.body.data;
    var cards = body.cards || [body];

    var count = 0;
    for (var i = 0; i < cards.length; i++) {
        var card = cards[i];

        // Check if card already exists
        var existing = new GlideRecord('x_nail_ave_card');
        existing.addQuery('u_ave_id', card.ave_id);
        existing.query();

        var gr;
        if (existing.next()) {
            gr = existing; // Update existing
        } else {
            gr = new GlideRecord('x_nail_ave_card');
            gr.initialize();
        }

        gr.u_ave_id = card.ave_id;
        gr.u_name = card.name;
        gr.u_category = card.category;
        gr.u_severity = card.severity;
        gr.u_status = card.status;
        gr.u_summary = card.summary;
        gr.u_mechanism = card.mechanism;
        gr.u_blast_radius = card.blast_radius;
        gr.u_avss_base = card.avss_score ? card.avss_score.base : 0;
        gr.u_date_published = card.date_published;
        gr.u_cwe_mapping = card.cwe_mapping;
        gr.u_mitre_mapping = card.mitre_mapping;
        gr.u_defences = JSON.stringify(card.defences);
        gr.u_raw_json = JSON.stringify(card);

        if (existing.hasNext()) {
            gr.update();
        } else {
            gr.insert();
        }
        count++;
    }

    response.setStatus(200);
    response.setBody({
        status: 'success',
        cards_processed: count
    });

})(request, response);
```

### 3. Create Scheduled Import

Use a Scheduled Script Execution to poll the NAIL API:

```javascript
// Scheduled Script: NAIL AVE Import (runs hourly)
var restMessage = new sn_ws.RESTMessageV2();
restMessage.setHttpMethod('GET');
restMessage.setEndpoint('https://api.nailinstitute.org/api/v1/cards');
restMessage.setRequestHeader('Accept', 'application/json');

var resp = restMessage.execute();
var httpStatus = resp.getStatusCode();

if (httpStatus == 200) {
    var body = JSON.parse(resp.getBody());
    var cards = body.cards || body;

    for (var i = 0; i < cards.length; i++) {
        // ... same insert/update logic as above
    }

    gs.info('NAIL AVE Import: Processed ' + cards.length + ' cards');
} else {
    gs.error('NAIL AVE Import failed: HTTP ' + httpStatus);
}
```

## GRC Integration

### Risk Register Mapping

Map AVE categories to your enterprise risk register:

| AVE Category | Risk Category | Risk Level |
|-------------|---------------|-----------|
| prompt_injection | AI System Integrity | High |
| goal_hijacking | AI System Integrity | High |
| unsafe_code_execution | Application Security | Critical |
| privilege_escalation | Access Control | Critical |
| information_leakage | Data Protection | High |
| resource_abuse | Operational | Medium |
| denial_of_service | Availability | Medium |
| supply_chain | Third-Party Risk | High |
| memory_poisoning | Data Integrity | High |
| trust_boundary_violation | Access Control | High |
| coordination_failure | Operational | Medium |
| emergent_behaviour | AI System Integrity | High |
| monitoring_evasion | Detection & Response | High |

### Compliance Mapping

| Regulation | AVE Relevance | ServiceNow Module |
|-----------|---------------|-------------------|
| EU AI Act | All categories | GRC Compliance |
| NIST AI RMF | All categories | GRC Risk |
| ISO 42001 | All categories | GRC Compliance |
| SOC 2 Type II | Security categories | GRC Audit |
| GDPR | Information leakage | GRC Privacy |

## Vulnerability Response Integration

Automatically create Vulnerability Response items from critical AVE cards:

```javascript
// Business Rule: Auto-create VR item for critical AVE cards
(function executeRule(current, previous) {

    if (current.u_severity == 'critical') {
        var vr = new GlideRecord('sn_vul_vulnerable_item');
        vr.initialize();
        vr.vulnerability = current.u_name;
        vr.source = 'NAIL AVE Database';
        vr.severity = '1'; // Critical
        vr.state = 'open';
        vr.description = current.u_summary + '\n\nMechanism: ' + current.u_mechanism;
        vr.remediation = current.u_defences;
        vr.insert();

        gs.info('Created VR item for ' + current.u_ave_id);
    }

})(current, previous);
```

## Requirements

- ServiceNow San Diego+ (recommended: Washington DC or later)
- Vulnerability Response plugin (for VR integration)
- GRC module (for risk/compliance integration)
- Integration Hub or Scripted REST (for API connectivity)
- Network access to `api.nailinstitute.org`

## Support

- **Docs**: This README
- **Issues**: GitHub issues on `ave-database`
- **Slack**: `#vendor-integrations`
- **Email**: vendor-integrations@nailinstitute.org
