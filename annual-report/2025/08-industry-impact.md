# Chapter 8: Industry Impact

> Sector-specific findings, real-world incident patterns, and how
> different industries are affected by agentic AI vulnerabilities.

---

## Overview

Agentic AI is being deployed across every industry vertical, but the
vulnerability profile — and the consequences of exploitation — vary
dramatically by sector. This chapter analyses industry-specific patterns
from AVE cards, incident reports, and the practitioner survey.

---

## Industry Adoption and Risk Profile

| Industry | Agent Deployment Maturity | Primary Use Cases | Risk Level |
|----------|--------------------------|-------------------|-----------|
| **Financial Services** | High | Trading, fraud detection, compliance, customer service | Critical |
| **Technology** | High | Code generation, DevOps, security operations | High |
| **Healthcare** | Medium | Triage, clinical decision support, administrative | Critical |
| **Government / Defence** | Medium | Intelligence analysis, decision support | Critical |
| **Legal** | Medium | Document review, research, contract analysis | High |
| **Manufacturing** | Low–Medium | Quality control, supply chain, predictive maintenance | Medium |
| **Education** | Low–Medium | Tutoring, assessment, research assistance | Medium |
| **Retail / E-commerce** | Medium | Customer service, recommendation, inventory | Medium |

---

## Sector Deep-Dives

### Financial Services

**Deployment Scale**: 61% of surveyed financial institutions deploy agentic AI
in at least one production process.

**Primary Vulnerabilities**:

| Risk | AVE Categories | Impact |
|------|---------------|--------|
| Trading agent manipulation | Goal Hijacking, Prompt Injection | Unauthorised trades, market manipulation |
| Customer data exfiltration | Information Leakage, Tool-Use Risks | Regulatory breach, customer harm |
| Compliance agent bypass | Monitoring Evasion, Alignment Subversion | Regulatory fines, licence risk |
| Multi-agent consensus manipulation | Coordination Failure, Collusion | Incorrect risk assessment |

**Case Study**: An anonymised trading firm reported that a multi-agent analysis
pipeline, when given carefully crafted market data containing embedded
instructions, altered its risk assessment from "high risk — do not trade" to
"moderate risk — proceed with reduced position." The embedded injection
targeted the data-processing agent, and the altered assessment propagated
through the recommendation chain to the execution agent.

**Regulatory Exposure**: MiFID II, Basel III, and emerging AI-specific
regulations require firms to demonstrate control over automated trading
and decision-making systems. Agentic AI introduces new attack surfaces
that traditional compliance frameworks were not designed to address.

### Technology / Software Development

**Deployment Scale**: Coding agents are the most widely deployed agentic AI
category, with 83% of surveyed tech companies using AI coding assistants
with tool access (file write, code execution, git operations).

**Primary Vulnerabilities**:

| Risk | AVE Categories | Impact |
|------|---------------|--------|
| Malicious code insertion | Unsafe Code Execution, Supply Chain | Backdoors in production code |
| Credential exfiltration | Information Leakage, Tool-Use Risks | Compromised infrastructure |
| CI/CD pipeline compromise | Supply Chain, Privilege Escalation | Full deployment chain compromise |
| Dependency poisoning | Supply Chain, Environmental Manipulation | Widespread downstream impact |

**Case Study**: A coding agent with git push access was manipulated via an
indirect injection embedded in a code review comment. The injected instruction
caused the agent to modify a different file than the one under review, inserting
a subtle dependency change that would import a malicious package on next build.

### Healthcare

**Deployment Scale**: Lower adoption than finance or tech, but the consequences
of exploitation are highest — patient safety is at stake.

**Primary Vulnerabilities**:

| Risk | AVE Categories | Impact |
|------|---------------|--------|
| Clinical decision manipulation | Goal Hijacking, Prompt Injection | Incorrect treatment recommendations |
| Patient data breach | Information Leakage | HIPAA / GDPR violations, patient harm |
| Prescription agent exploitation | Unsafe Code Execution, Privilege Escalation | Dangerous prescriptions |
| Medical record poisoning | Memory Poisoning | Long-term treatment corruption |

**Key Concern**: Healthcare agents often operate in environments where the
consequences of failure are irreversible — a manipulated clinical recommendation
could lead to patient harm. AVSS Reversibility scores for healthcare scenarios
are consistently 8–10.

### Government and Defence

**Primary Vulnerabilities**:

| Risk | AVE Categories | Impact |
|------|---------------|--------|
| Intelligence analysis manipulation | Goal Hijacking, Memory Poisoning | Flawed strategic decisions |
| Classified data exfiltration | Information Leakage, Monitoring Evasion | National security breach |
| Decision support compromise | Multi-Agent Collusion, Consensus Manipulation | Policy errors |
| Supply chain infiltration | Supply Chain, Model Poisoning | Persistent backdoors |

**Key Concern**: The adversary in government/defence contexts is often a
nation-state with significant resources. AVSS Exploitability assessments
must account for highly sophisticated, well-resourced attackers.

---

## Cross-Industry Patterns

### Pattern 1: Customer-Facing Agents Are the Most Attacked

Agents exposed to external users (customer support, public chatbots) have the
highest attack frequency because:
- Largest number of potential attackers (anyone with a browser)
- Lowest attacker sophistication requirement (natural language input)
- Direct injection is the primary vector

### Pattern 2: Internal Agents Have Higher Blast Radius

Agents used internally (coding assistants, DevOps agents, analysis pipelines)
face fewer attacks but with much higher consequences because:
- More tools and higher privileges
- Access to sensitive internal systems
- Less monitoring (trusted internal environment assumption)
- Indirect injection via documents and data sources

### Pattern 3: Regulated Industries Are Most Concerned

| Industry | "Very Concerned" about Agentic AI Security |
|----------|-------------------------------------------|
| Financial services | 89% |
| Healthcare | 84% |
| Government | 81% |
| Technology | 72% |
| Retail | 58% |
| Education | 47% |

### Pattern 4: Security Investment Lags Deployment

Across all sectors:
- Average time from first agent deployment to first security assessment: **8 months**
- Percentage of organisations with agent-specific security policies: **28%**
- Percentage with dedicated agentic AI security team or role: **11%**

---

## Economic Impact

### Cost of Agentic AI Security Incidents

Based on anonymised incident reports:

| Impact Category | Median Cost | Range |
|----------------|------------|-------|
| Data breach via agent | $420K | $85K – $4.2M |
| Service disruption | $180K | $25K – $750K |
| Reputational damage | Difficult to quantify | — |
| Regulatory fines | $310K | $50K – $2.8M |
| Remediation effort | 6 person-weeks | 2 – 16 weeks |

### Security Spending

| Item | % of Agent Programme Budget |
|------|---------------------------|
| Agent development and deployment | 72% |
| Security tooling and guardrails | 14% |
| Security testing (red-teaming) | 7% |
| Training and awareness | 4% |
| Incident response preparation | 3% |

**Key Finding**: Security spending averages 7% of total agent programme
budgets — significantly below the 10–15% recommended by security frameworks.

---

## Recommendations by Industry

| Industry | Priority Defences | Priority AVE Categories |
|----------|------------------|----------------------|
| Financial Services | Permission policies, HITL for transactions | Goal Hijacking, Info Leakage |
| Technology | Sandboxing, supply chain integrity | Code Execution, Supply Chain |
| Healthcare | Strict guardrails, formal verification | All categories (zero tolerance) |
| Government | Full defence-in-depth, supply chain | Supply Chain, Info Leakage |
| Legal | Output monitoring, DLP | Info Leakage, Memory Poisoning |
| Retail | Input filtering, rate limiting | Prompt Injection, Resource Abuse |

---

*Industry data is drawn from the 2025 practitioner survey (87 respondents)
and 12 anonymised incident reports. See Chapter 12 for methodology.*
