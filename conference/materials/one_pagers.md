# 📄 Conference One-Pagers

Printable handouts for conference attendees. Each one-pager is designed
to be a single A4/Letter sheet (front and back).

---

## One-Pager 1: What Is AVE?

### Front

**AGENTIC VULNERABILITY ENUMERATION (AVE)**
*The CVE for AI Agents*

**The Problem**
Autonomous AI agents (AutoGPT, LangChain, CrewAI, etc.) introduce
novel security risks that traditional vulnerability databases don't
cover. Prompt injection, tool misuse, memory poisoning, and
multi-agent collusion fall outside CVE/CWE/NVD scope.

**The Solution**
AVE is an open, community-driven database of agentic AI vulnerabilities
with:
- 📋 **50+ catalogued vulnerabilities** across 14 categories
- 🔬 **Controlled experiments** validating each vulnerability
- 📊 **AVSS scoring** — a severity system designed for AI agents
- 🗺️ **MITRE ATT&CK mappings** for every entry
- 🆓 **100% open source** under CC BY 4.0

**Categories**
| Category | Count | Example |
|----------|-------|---------|
| Prompt Injection | 5 | Direct / Indirect / Multi-turn |
| Tool Misuse | 4 | Excessive permission, function abuse |
| Memory Poisoning | 4 | Context window manipulation |
| Multi-Agent | 4 | Collusion, cascade failure |
| Identity & Auth | 3 | Credential theft, impersonation |
| ... and 9 more | 30+ | See full database |

### Back

**How to Use AVE**
1. Browse: `nailinstitute.org`
2. API: `api.nailinstitute.org/v2/aves`
3. Search: by category, severity, MITRE mapping
4. Contribute: GitHub Pull Request

**Who's Using AVE?**
- Security teams assessing AI agent deployments
- AI developers building safer autonomous systems
- Compliance officers mapping AI risks
- Researchers studying emergent AI behaviours

**Get Involved**
- ⭐ Star: github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database
- 📧 Email: contact@nailinstitute.org
- 🐦 Twitter: @NAILInstitute

**QR Code**: [Link to nailinstitute.org]

---

## One-Pager 2: AVSS Scoring System

### Front

**AGENTIC VULNERABILITY SEVERITY SCORING (AVSS)**
*Beyond CVSS: Scoring Built for AI Agents*

**Why Not CVSS?**
CVSS was designed for software vulnerabilities. AI agent risks involve:
- Non-deterministic behaviour
- Cross-system propagation through tool use
- Context-dependent severity
- Human-in-the-loop variability

**AVSS Dimensions**

| Dimension | Range | Measures |
|-----------|-------|----------|
| Exploitability | 0–10 | How easy to trigger |
| Impact | 0–10 | Damage when exploited |
| Autonomy Impact | 0–10 | Effect on agent independence |
| Reversibility | 0–10 | Ease of recovery |
| Scope | 0–10 | Blast radius across systems |

**Composite Score**: Weighted average → 0.0–10.0

### Back

**Severity Bands**

| Score | Label | Response |
|-------|-------|----------|
| 9.0–10.0 | Critical | Immediate mitigation required |
| 7.0–8.9 | High | Mitigate within 24 hours |
| 4.0–6.9 | Medium | Mitigate within 7 days |
| 0.1–3.9 | Low | Address in next release |
| 0.0 | Info | Informational only |

**Example Scoring: AVE-2025-0001 (Direct Prompt Injection)**
- Exploitability: 8.5 (simple text input)
- Impact: 7.0 (full agent control)
- Autonomy Impact: 9.0 (complete override)
- Reversibility: 6.0 (restart agent)
- Scope: 5.5 (single agent boundary)
- **Composite: 7.2 (High)**

---

## One-Pager 3: Certification Programme

### Front

**NAIL CERTIFICATION PROGRAMME**
*Validate Your Agentic AI Security Expertise*

**Three Levels**

🟢 **NAIL Associate** (NCA)
- 1-day course + online exam
- Foundations of agentic AI security
- Cost: $500 | Valid: 2 years

🟡 **NAIL Assessor** (NCAP)
- 3-day intensive + practical exam
- Conduct vulnerability assessments
- Cost: $2,500 | Valid: 2 years

🔴 **NAIL Master** (NCMP)
- Portfolio + oral examination
- Lead security programmes
- Cost: $5,000 | Valid: 3 years

### Back

**Certification Benefits**
- ✅ Industry-recognised credential
- ✅ Listed in NAIL Assessor Registry
- ✅ Access to private community channels
- ✅ Continuing education resources
- ✅ Digital badge + physical certificate

**For Organisations**
- Demonstrate AI security competence to clients
- Meet emerging regulatory requirements
- Reduce risk in agentic AI deployments
- Access enterprise assessment tools

**Next Training Dates**
Visit `nailinstitute.org/training` for upcoming sessions.

---

## One-Pager 4: Enterprise Value Proposition

### Front

**SECURE YOUR AI AGENTS WITH NAIL**
*Before They Secure Themselves*

**The Risk**
By 2026, 80% of enterprises will deploy autonomous AI agents.
Today, fewer than 5% have a security framework for them.

**What We Provide**

| Service | Description |
|---------|-------------|
| AVE Database | Comprehensive vulnerability intelligence |
| AVSS Scoring | Risk quantification for AI agents |
| Certification | Validate team capabilities |
| API Access | Integrate into your security toolchain |
| Assessment | Expert-led vulnerability assessments |
| Insurance | Actuarial risk models for AI agent coverage |

### Back

**Engagement Models**

💼 **Professional API** — $99/month
- 1,000 requests/hour
- Webhook notifications
- Email support

🏢 **Enterprise API** — $499/month
- 10,000 requests/hour
- Custom integrations
- Dedicated support + SLA

🤝 **Strategic Partnership**
- Custom API limits
- Joint research
- Co-branding opportunities

**ROI Indicators**
- 60% faster AI vulnerability triage
- Regulatory compliance readiness (EU AI Act, NIST)
- Insurance premium reduction with certified assessments

**Contact**: enterprise@nailinstitute.org

---

## Print Specifications

| Property | Value |
|----------|-------|
| Paper size | A4 / US Letter |
| Orientation | Portrait |
| Colour | Full colour (CMYK) |
| Paper weight | 170 gsm (glossy or matte) |
| Bleed | 3 mm |
| Font | Inter (headings), Source Sans Pro (body) |
| QR codes | Generated via qr-code-generator.com |
| Print run | 200–500 per conference |
