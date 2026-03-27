# Chapter 1: Executive Summary

> **State of Agentic AI Security — 2025**
> Published by the NAIL Institute for Agentic Security

---

## Key Findings

### 1. Agentic AI Adoption Outpaces Security

The deployment of autonomous AI agents in production environments has accelerated
dramatically in 2025, driven by frameworks like LangChain, AutoGen, CrewAI, and
proprietary enterprise solutions. Security practices have not kept pace:

- **50** unique agentic AI vulnerabilities catalogued in the AVE database
- **72%** of surveyed organisations deploying agents have no agent-specific security controls
- Average time from agent deployment to first security incident: **47 days**

### 2. Prompt Injection Remains the #1 Threat

Prompt injection continues to dominate the vulnerability landscape, accounting for
**8%** of all AVE cards (injection category). However, the broader alignment (18%)
and structural (16%) categories reveal that the attack surface extends far beyond
classic prompt injection:

- **Indirect injection** via tools, documents, and web content now surpasses direct injection
- Multi-step injection chains show **3.2×** higher success rates
- Effective defence remains elusive: no single mitigation achieves > 78% reduction

### 3. Multi-Agent Systems Introduce Novel Risk Classes

The rise of multi-agent architectures has created vulnerability categories that
have no analogue in single-agent or traditional software systems:

- **Trust cascade exploitation** across delegation chains
- **Coordination failures** in consensus-based agent systems
- **Emergent adversarial behaviour** in agent swarms with > 5 participants
- AVE Schema v2.0.0 introduced to capture these multi-agent patterns

### 4. Defences Are Maturing But Insufficient

Guardrails, input/output filtering, and sandboxing are now mainstream but provide
incomplete protection:

| Defence Category | Adoption Rate | Median Effectiveness |
|-----------------|--------------|---------------------|
| Input filtering | 67% | 62% reduction |
| Output monitoring | 54% | 58% reduction |
| Tool sandboxing | 38% | 73% reduction |
| Human-in-the-loop | 29% | 91% reduction |
| Formal guardrails | 12% | 85% reduction |

### 5. Regulatory Frameworks Are Converging on Agentic AI

- **EU AI Act**: First enforcement actions expected in 2026; agentic systems
  classified as high-risk in most deployment contexts
- **NIST AI RMF**: AI 600-1 profile provides direct guidance on autonomous systems
- **Industry standards**: ISO 42001 adoption accelerating, but agentic-specific
  controls still developing

---

## By the Numbers

| Metric | Value |
|--------|-------|
| Total AVE cards published | 50 |
| New cards in 2025 | 50 |
| Categories represented | 13 / 20 |
| Average AVSS score | 7.6 |
| Critical severity cards | 15 (30%) |
| Community contributors | 5 |
| Countries represented | 4 |
| Academic papers citing AVE | 3 |

---

## Recommendations

### For Organisations Deploying Agents

1. **Inventory** all agentic AI systems and their tool access
2. **Assess** each against the AVE database (use the NAIL API integration)
3. **Implement** defence-in-depth: input filtering + sandboxing + monitoring
4. **Monitor** for new AVE cards matching your agent stack (set up alerts)
5. **Train** security teams on agent-specific threat models

### For Agent Framework Developers

1. **Design** trust attenuation into multi-agent delegation
2. **Default** to least-privilege tool access
3. **Provide** built-in monitoring hooks for security tooling
4. **Test** against the NAIL red-teaming benchmark
5. **Report** vulnerabilities via the NAIL responsible disclosure process

### For Policymakers

1. **Require** agent-specific security assessments in high-risk AI deployments
2. **Reference** the AVE taxonomy in AI security standards
3. **Fund** research into formal verification of agent safety properties
4. **Mandate** incident reporting for agentic AI security failures
5. **Engage** with NAIL and similar bodies on standard development

---

*Full findings and analysis follow in Chapters 2-11.*

*Data freeze: December 31, 2025*
*Report methodology: Chapter 12*
