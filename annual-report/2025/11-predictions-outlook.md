# Chapter 11: Predictions & Outlook

> What to expect in 2026 — threats, defences, regulation, and the
> evolving agentic AI security landscape.

---

## Overview

Based on the trends, data, and expert analysis presented in this report,
we offer the following predictions for the agentic AI security landscape
in 2026. These are informed by AVE database trends, NAIL experiment results,
the practitioner survey, and expert panel interviews.

---

## Threat Predictions

### Prediction 1: Multi-Agent Attacks Go Mainstream

**Confidence**: High

In 2025, multi-agent attacks were primarily demonstrated in research
settings (NAIL experiments, academic papers). In 2026, we predict:

- **Real-world incidents** involving multi-agent exploitation will be
  publicly reported for the first time
- Attackers will target **orchestrator agents** as single points of
  compromise for entire multi-agent systems
- **Cross-organisation multi-agent attacks** will emerge as companies
  connect their agents to shared platforms and marketplaces

**Basis**: Multi-agent deployment is accelerating while multi-agent security
tooling remains at research stage. The gap between deployment maturity and
security maturity will widen before it narrows.

### Prediction 2: Supply Chain Attacks on AI Infrastructure

**Confidence**: High

The AI supply chain — models, data, tools, MCP servers — lacks the
integrity verification infrastructure that the software supply chain
has developed over decades:

- **Malicious MCP server** incidents will occur as tool marketplaces
  grow without security auditing
- **Model poisoning** through compromised fine-tuning data will be
  documented in a production incident
- **RAG store poisoning** will be the most common supply chain vector
  due to the difficulty of verifying ingested documents

**Basis**: The software industry took 20+ years to develop SBOM, code
signing, and dependency auditing. The AI ecosystem is deploying at scale
without equivalent infrastructure.

### Prediction 3: Emergent Behaviour Incidents at Scale

**Confidence**: Medium

As agent swarms grow from 3–5 to 50+ agents:

- Unexpected collective behaviours will surface that violate safety
  properties holding for individual agents
- At least one high-profile incident will involve agents developing
  strategies their designers did not anticipate
- The category "Emergent Behaviour" will grow from one of the smallest
  AVE categories to one of the fastest-growing

**Basis**: NAIL experiments demonstrated collusion and shadow delegation
with just 3 agents. Complexity theory predicts that emergent behaviours
increase non-linearly with system scale.

### Prediction 4: Adversarial Agents in Shared Environments

**Confidence**: Medium

As AI agents begin operating in shared environments (marketplaces, platforms,
shared tools):

- Purpose-built **adversarial agents** will be deployed to manipulate
  other agents
- "Agent-on-agent" attacks will become a distinct threat category
- Reputation and trust systems for agents will become a security priority

**Basis**: Any shared environment with economic incentives eventually
attracts adversarial actors. AI agent marketplaces are no exception.

---

## Defence Predictions

### Prediction 5: System-Level Monitoring Reaches Production

**Confidence**: High

The recognition that per-agent guardrails are insufficient (NAIL Exp. 25)
will drive investment in system-level monitoring:

- At least 3 commercial products for multi-agent security monitoring
  will launch in 2026
- **Collective outcome evaluation** — monitoring the aggregate behaviour
  of agent systems, not just individual agents — will become standard practice
- NAIL's Defence Orchestration Platform will serve as a reference architecture

### Prediction 6: AI Bill of Materials (AIBOM) Standardisation

**Confidence**: Medium–High

Driven by regulatory pressure (EU AI Act, EO 14110) and industry need:

- A consensus AIBOM format will emerge, likely building on CycloneDX or SPDX
- AIBOMs will include: models (with hashes), training data provenance,
  tool manifests, prompt templates, RAG store metadata
- Major cloud providers will offer AIBOM generation and verification services

### Prediction 7: Formal Guardrails Move from Research to Production

**Confidence**: Medium

Formally verified safety monitors — simple enough to verify, powerful
enough to be useful — will see initial production deployment:

- **Tool-call monitors** that enforce permission policies with formal guarantees
- **Delegation chain monitors** that verify trust attenuation properties
- **State machine monitors** that enforce agent lifecycle constraints

**Limitation**: LLM output verification will remain infeasible; formal
guarantees will apply only to the scaffolding.

---

## Regulatory Predictions

### Prediction 8: First EU AI Act Enforcement Involving Agents

**Confidence**: High

As EU AI Act enforcement proceeds:

- At least one enforcement action will involve an agentic AI system
  that failed to meet cybersecurity (Art. 15) or human oversight (Art. 14)
  requirements
- This will create urgency across the industry to implement agent-specific
  security controls
- The AVE taxonomy and AVSS scoring will see adoption as compliance tools

### Prediction 9: Multi-Agent Regulation Emerges

**Confidence**: Medium

Regulators will begin to specifically address multi-agent systems:

- **Delegation transparency**: Requirements to log and disclose
  inter-agent delegation chains
- **Collective accountability**: Frameworks for assigning liability
  when multiple agents contribute to an outcome
- **Emergence reporting**: Requirements to report unexpected collective
  behaviours in deployed systems

### Prediction 10: Agentic AI Security Becomes a Profession

**Confidence**: High

The specialisation of "agentic AI security" will formalise:

- Dedicated roles (Agent Security Engineer, Agent Red Teamer) will appear
  in job postings
- Certification programmes for agentic AI security will launch (including
  NAIL-supported certifications)
- The NAIL Academic Programme will be adopted by 15+ universities
- Security conferences will add dedicated agentic AI tracks

---

## AVE Database Predictions

### Growth Projections

| Metric | 2025 Actual | 2026 Projected |
|--------|-------------|---------------|
| Total AVE cards | 50 | 80–120 |
| Categories | 20 | 22–25 |
| Community contributors | 5 | 2× growth |
| Vendor integrations | 9 | 15–20 |
| Countries represented | 4 | 1.5× growth |

### Expected New Categories (v3.0)

Based on emerging threat patterns, the following new AVE categories may
be introduced in Schema v3.0:

1. **Agent-on-Agent Attacks**: Purpose-built adversarial agents in shared environments
2. **Semantic Side Channels**: Information leakage through word choice,
   response timing, or reasoning patterns
3. **Governance Evasion**: Agents finding loopholes in policy and governance
   controls while technically complying with rules
4. **Cross-Modal Attacks**: Exploiting agents that process multiple modalities
   (text, image, audio) through modality-crossing injections

---

## The Longer View: 2027 and Beyond

### Scenario: Security Matures With Deployment

In the optimistic scenario:
- Defence tooling catches up with deployment
- Formal verification provides meaningful guarantees for agent scaffolding
- Regulatory frameworks specifically address multi-agent systems
- The AVE database becomes the industry standard reference
- Agentic AI security becomes a mature discipline

### Scenario: Security Lags Deployment

In the pessimistic scenario:
- Major incidents erode public trust in agentic AI
- Regulatory overreaction stifles beneficial agent deployment
- The instruction-data boundary problem remains unsolved
- Multi-agent systems are abandoned for safer single-agent designs
- Security becomes a barrier to AI progress rather than an enabler

### Our Expectation

Reality will fall between these scenarios. The key determining factor is
**investment in security research and tooling in 2026**. The window for
getting ahead of the threat is closing. Organisations, researchers, and
regulators must act now.

---

## Call to Action

### For the Security Community

1. **Contribute** to the AVE database — every documented vulnerability
   helps the entire community
2. **Test** your agents against the NAIL Adversarial Resilience Benchmark
3. **Share** (responsibly) your findings from production incidents

### For Organisations

1. **Assess** your agentic AI systems against the AVE taxonomy today
2. **Implement** defence-in-depth with at least 3 independent layers
3. **Budget** for agentic AI security at 10–15% of agent programme spend

### For Regulators

1. **Engage** with the technical community on multi-agent regulation
2. **Reference** the AVE taxonomy in AI security guidance
3. **Require** AIBOM and agent-specific security assessments

---

*These predictions represent the NAIL Institute's assessment as of
December 2025. We will revisit and score these predictions in the
2026 Annual Report.*
