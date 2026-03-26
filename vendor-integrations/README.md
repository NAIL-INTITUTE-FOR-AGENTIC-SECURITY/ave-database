# NAIL Institute — Vendor Integration Programme

Enabling security tools and platforms to consume, correlate, and act on AVE
vulnerability intelligence natively.

## Mission

Make agentic AI vulnerability data from the NAIL AVE database seamlessly
available in the security tools that organisations already use — SIEM, SOAR,
GRC, vulnerability management, and developer tooling.

## Why Integrate?

| Benefit | Description |
|---------|-------------|
| **Real-time intelligence** | Push AVE updates directly into security operations |
| **Correlation** | Map agentic AI vulnerabilities to existing alerts and incidents |
| **Compliance** | Demonstrate coverage of AI-specific risks in GRC frameworks |
| **Automation** | Trigger playbooks when new AVE cards match your agent stack |
| **Visibility** | Surface agentic AI risk alongside traditional vulnerabilities |

## Integration Catalogue

### Available Integrations

| Platform | Type | Status | Docs |
|----------|------|--------|------|
| [Splunk](integrations/splunk/) | SIEM | Reference | [Guide](integrations/splunk/README.md) |
| [Microsoft Sentinel](integrations/sentinel/) | SIEM | Reference | [Guide](integrations/sentinel/README.md) |
| [ServiceNow](integrations/servicenow/) | GRC / ITSM | Reference | [Guide](integrations/servicenow/README.md) |

### Planned Integrations

| Platform | Type | Target |
|----------|------|--------|
| Elastic Security | SIEM | 2025-Q4 |
| CrowdStrike Falcon | EDR | 2025-Q4 |
| Palo Alto XSOAR | SOAR | 2025-Q4 |
| Tenable.io | Vuln Management | 2026-Q1 |
| Jira (Atlassian) | Issue Tracking | 2026-Q1 |
| Snyk | Developer Security | 2026-Q1 |

### Build Your Own

Use the [Integration SDK](sdk/) to build custom integrations with any platform.

## Architecture

```
┌─────────────────────────────────────────────┐
│              NAIL AVE Database               │
│  (JSON, API, RSS/Atom, STIX/TAXII)          │
└──────────────────┬──────────────────────────┘
                   │
        ┌──────────┼──────────┐
        │          │          │
   ┌────▼───┐ ┌───▼────┐ ┌───▼─────┐
   │  API   │ │  Feed  │ │  STIX   │
   │(REST)  │ │(RSS/   │ │(TAXII   │
   │        │ │ Atom)  │ │ Server) │
   └───┬────┘ └───┬────┘ └───┬─────┘
       │          │          │
   ┌───▼──────────▼──────────▼───┐
   │    Integration Adapters      │
   │  ┌────────┐ ┌─────────┐    │
   │  │Splunk  │ │Sentinel │    │
   │  │App     │ │Connector│    │
   │  └────────┘ └─────────┘    │
   │  ┌──────────┐ ┌────────┐  │
   │  │ServiceNow│ │ Custom │  │
   │  │App       │ │ (SDK)  │  │
   │  └──────────┘ └────────┘  │
   └─────────────────────────────┘
```

## Data Formats

| Format | Use Case | Endpoint |
|--------|----------|----------|
| **JSON** | Direct API consumption | `GET /api/v1/cards` |
| **RSS/Atom** | Feed readers, simple alerting | `/feeds/rss.xml` |
| **STIX 2.1** | Threat intelligence platforms | `/api/v1/stix/bundle` |
| **CSV** | Spreadsheet / data analysis | `GET /api/v1/cards?format=csv` |
| **SARIF** | Developer tools (VS Code, GitHub) | Planned |

## Vendor Partnership

### Becoming an Integration Partner

1. **Express Interest**: vendor-integrations@nailinstitute.org
2. **Technical Scoping**: Joint architecture review
3. **Development**: Build integration using SDK + NAIL API
4. **Certification**: NAIL reviews and certifies the integration
5. **Launch**: Co-announcement, listing in integration catalogue

### Certification Levels

| Level | Requirements |
|-------|-------------|
| **Compatible** | Consumes AVE data correctly, basic display |
| **Certified** | Above + full schema support, correlation, automated updates |
| **Premier** | Above + co-developed, joint roadmap, dedicated support channel |

## Contact

- **Email**: vendor-integrations@nailinstitute.org
- **Slack**: `#vendor-integrations`
- **Programme Lead**: TBD
