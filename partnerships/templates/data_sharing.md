# Data Sharing Agreement
# NAIL Institute × [Partner Organisation]

---

## DATA SHARING AGREEMENT

**Agreement Reference**: DSA-[YYYY]-[NNN]
**Effective Date**: [Date]
**Parties**: NAIL Institute and [Partner Organisation]
**Parent MOU Reference**: MOU-[YYYY]-[NNN]

---

### 1. PURPOSE

This Data Sharing Agreement ("DSA") governs the exchange of data
between the Parties for the purpose of advancing agentic AI security
through the AVE standard.

### 2. DATA CATEGORIES

The following categories of data may be shared under this agreement:

| Category | Direction | Classification | Format |
|----------|-----------|---------------|--------|
| AVE vulnerability reports | Bidirectional | Public after disclosure | AVE JSON |
| Anonymised incident data | [Partner] → NAIL | Confidential | JSON/CSV |
| Benchmark results | Bidirectional | Public | AVE Benchmark JSON |
| Threat intelligence | NAIL → [Partner] | Confidential (48h) | AVE Advisory |
| Model evaluation data | Bidirectional | Confidential | Custom |
| Certification results | NAIL → [Partner] | Public | Certificate JSON |

### 3. DATA HANDLING REQUIREMENTS

#### 3.1 Classification Levels

- **Public**: May be shared freely after applicable embargo periods
- **Confidential**: Restricted to named individuals, encrypted in transit
  and at rest, deleted after retention period
- **Restricted**: Additional controls apply (see Section 3.4)

#### 3.2 Transmission

- All data SHALL be transmitted via encrypted channels (TLS 1.3+)
- API-based transfer preferred (NAIL API with partner credentials)
- File transfers via SFTP or encrypted email (PGP/S-MIME)
- USB or physical media NOT permitted

#### 3.3 Storage

- Confidential data SHALL be encrypted at rest (AES-256)
- Access limited to named personnel on approved access list
- Storage in jurisdictions compliant with applicable law
- Regular access audits (quarterly minimum)

#### 3.4 Restricted Data

Restricted data requires additional controls:
- Separate encrypted storage environment
- Two-person access control
- Activity logging with tamper-evident audit trail
- 30-day maximum retention unless renewed

### 4. PERSONAL DATA

4.1 The Parties SHALL minimise collection of personal data.

4.2 Where personal data is included (e.g., researcher names in
attribution), applicable data protection regulations apply:
- **GDPR** (EU/UK): Data Processing Agreement in Annex A
- **CCPA** (US): California privacy requirements apply
- **Other**: Jurisdiction-specific requirements as applicable

4.3 Neither Party shall transfer personal data to a third party
without prior written consent.

### 5. VULNERABILITY DISCLOSURE

5.1 Vulnerability data shared before public disclosure is subject
to the NAIL Institute Responsible Disclosure Policy:
- **Standard embargo**: 90 days from report to publication
- **Extended embargo**: Up to 180 days for critical infrastructure
- **Emergency disclosure**: Advisory Board may authorise early
  disclosure for actively exploited vulnerabilities

5.2 The receiving Party SHALL NOT:
- Disclose embargoed vulnerabilities to third parties
- Use embargoed data for commercial advantage
- File patents based on embargoed vulnerability information

### 6. ANONYMISATION REQUIREMENTS

6.1 Incident data MUST be anonymised before sharing:
- Remove organisation names and identifiers
- Remove individual names and contact details
- Generalise timestamps to weekly granularity
- Aggregate data where sample size < 5
- Remove unique deployment configurations

6.2 NAIL will provide anonymisation tools and guidelines.

### 7. DATA QUALITY

7.1 Shared data SHOULD conform to AVE schema specifications.

7.2 The providing Party warrants that:
- Data is collected in compliance with applicable law
- Data is accurate to the best of their knowledge
- Data provenance can be documented on request

7.3 Neither Party guarantees fitness for purpose of shared data.

### 8. RETENTION AND DELETION

| Data Category | Retention Period | Deletion Method |
|---------------|-----------------|-----------------|
| Public AVE data | Indefinite | N/A (open data) |
| Confidential incident data | 2 years | Cryptographic erasure |
| Restricted data | 30 days (renewable) | Cryptographic erasure |
| Benchmark results | 3 years | Standard deletion |
| Certification results | Duration of certification | Standard deletion |

8.1 Upon termination, confidential data SHALL be deleted within
30 days and deletion confirmed in writing.

### 9. BREACH NOTIFICATION

9.1 Data breaches involving shared data SHALL be reported to the
other Party within 24 hours of discovery.

9.2 Notification SHALL include:
- Nature of the breach
- Data categories affected
- Estimated scope
- Mitigation actions taken
- Contact for further information

### 10. AUDIT RIGHTS

10.1 Either Party may request an audit of the other's data handling
practices with 30 days written notice.

10.2 Audits SHALL be conducted by mutually agreed independent auditors.

10.3 Audit costs borne by the requesting Party unless material
non-compliance is found.

### 11. TERM

This DSA is effective for the duration of the parent MOU unless
terminated earlier by either Party with 30 days written notice.

---

**AGREED by the Parties:**

For **NAIL Institute**:

Signature: _________________________
Name: [Name]
Title: [Title]
Date: [Date]

For **[Partner Organisation]**:

Signature: _________________________
Name: [Name]
Title: [Title]
Date: [Date]

---

### ANNEX A: GDPR Data Processing Agreement

[Standard Contractual Clauses — to be appended where applicable]

### ANNEX B: Approved Access List

| Name | Organisation | Role | Data Access Level | Approved Date |
|------|-------------|------|-------------------|---------------|
| | | | | |

### ANNEX C: Technical Specifications

- **API Endpoint**: `https://api.nailinstitute.org/v2/partner/`
- **Authentication**: OAuth 2.0 with client credentials
- **Rate Limits**: Per partnership tier
- **Data Format**: JSON (AVE schema)
- **Encryption**: TLS 1.3 in transit, AES-256 at rest
