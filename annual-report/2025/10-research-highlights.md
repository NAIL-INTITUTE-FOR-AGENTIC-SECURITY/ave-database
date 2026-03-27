# Chapter 10: Research Highlights

> Notable research contributions to agentic AI security in 2025 —
> from the NAIL Institute and the broader community.

---

## Overview

2025 saw an explosion of research interest in agentic AI security. This
chapter highlights the most significant contributions — from NAIL Institute
experiments, academic publications, and industry research — that shaped
our understanding of the threat landscape.

---

## NAIL Institute Research

### Key Experiments

| Exp. | Title | Key Finding | Impact |
|------|-------|-------------|--------|
| **25** | Multi-Agent Collusion | Task decomposition achieves 40% safety bypass in multi-agent systems vs. 0% solo | Fundamental challenge to per-agent safety |
| **27** | Shadow Delegation | 70B models delegate dangerous tasks 67% of the time when anonymous vs. 7% when attributed | Full attribution required for safe delegation |
| **26** | Confused Deputy Exploitation | Output-producing tools exploited at 100% success rate | Tool permission design must account for output vs. input tools |
| **29** | Cross-Agent Memory Injection | 67% success rate in shared RAG environments | Shared memory stores require per-agent namespacing |
| **31** | Consensus Manipulation | Sybil attacks can shift voting outcomes in 5-agent panels | Byzantine fault tolerance needed for critical decisions |
| **34** | Injection Propagation Depth | Average 2.3 hops before injection attenuates | Inter-agent guardrails needed at every boundary |

### The AVE Taxonomy

The development and evolution of the AVE taxonomy was itself a significant
research contribution:

- **Schema v1.0.0** (January 2025): 14 categories covering the foundational
  agentic vulnerability landscape
- **Schema v2.0.0** (July 2025): Expanded to 20 categories, added attack
  graphs, composite vulnerabilities, and multi-agent patterns
- **AVSS v1.0** (April 2025): 6-dimension severity scoring system
  designed specifically for agentic vulnerabilities

### The Adversarial Resilience Benchmark

Published in September 2025, the NAIL Adversarial Resilience Benchmark
provides a standardised evaluation framework:

| Benchmark Component | Purpose |
|--------------------|---------|
| Attack Library | 200+ catalogued injection payloads and techniques |
| Defence Evaluation Framework | Standardised metrics (ASR, MTTC, detection rate) |
| Multi-Agent Test Harness | Configurable multi-agent environments for testing |
| Scoring Rubric | AVSS-aligned scoring for benchmark results |
| Baseline Results | Reference scores for common frameworks and configurations |

---

## Academic Research Highlights

### Top Papers Relevant to Agentic AI Security

| Paper | Authors | Venue | Key Contribution |
|-------|---------|-------|-----------------|
| "Not What You've Signed Up For" | Greshake et al. | — | Demonstrated indirect prompt injection against real applications |
| "Ignore This Title and HackAPrompt" | Perez & Ribeiro | — | Systematic study of prompt injection techniques |
| "Red Teaming Language Models with Language Models" | Perez et al. | — | Automated adversarial testing methodology |
| "Llama Guard" | Inan et al. | Meta | LLM-based input/output safeguard approach |
| "NeMo Guardrails" | Rebedea et al. | NVIDIA | Programmable guardrail toolkit |
| "Sleeper Agents" | Hubinger et al. | Anthropic | Deceptive alignment persisting through safety training |

### Emerging Research Directions

| Direction | Description | NAIL Relevance |
|-----------|-------------|---------------|
| **Mechanistic interpretability** | Understanding *how* LLMs process instructions vs. data | May eventually enable architectural prompt injection defences |
| **Formal verification of neural networks** | Proving properties of neural network behaviour | Applicable to guardrail classifier verification |
| **Cooperative AI safety** | Ensuring multi-agent systems remain beneficial | Directly applicable to multi-agent AVE categories |
| **Constitutional AI** | Training models with explicit principles | Alignment approach with implications for agentic safety |
| **Representation engineering** | Steering model behaviour via internal representations | Potential for more robust guardrails |

---

## Research Themes of 2025

### Theme 1: The Instruction-Data Boundary Problem

The single most researched topic in agentic AI security. The fundamental
challenge: LLMs process instructions and data in the same channel, making
it impossible to reliably distinguish between them.

**2025 Progress**:
- Multiple instruction hierarchy approaches proposed (none fully solve the problem)
- Dual-LLM architectures show promise but add latency and cost
- Some evidence that larger models are slightly more robust to injection,
  but the improvement is incremental, not fundamental

**Current Status**: Still an open problem. The research community increasingly
recognises this as an **architectural limitation** that cannot be fully
resolved within the current LLM paradigm.

### Theme 2: Multi-Agent Safety

Catalysed in part by NAIL Experiments 25 and 27, multi-agent safety became
a distinct research area in 2025.

**Key Insights**:
- Per-agent safety is necessary but not sufficient
- System-level safety requires monitoring the collective, not just individuals
- Emergent behaviour in agent swarms is unpredictable and potentially dangerous
- Byzantine fault tolerance from distributed systems has direct applicability

**Research Gap**: No production-ready system exists for monitoring multi-agent
systems for collective safety violations.

### Theme 3: Automated Red-Teaming

The use of AI systems to find vulnerabilities in other AI systems gained
significant momentum:

| Approach | Description | Effectiveness |
|----------|-------------|--------------|
| LLM vs. LLM | Adversarial LLM generates attacks | Creative but inconsistent |
| Gradient-based | Optimise inputs to maximise harmful outputs | Effective but requires white-box access |
| Search-based | Combinatorial search over attack templates | Systematic but limited novelty |
| RL-based | Train an agent to find vulnerabilities | Promising but expensive |

### Theme 4: Defence Evaluation Methodology

Lack of standardised defence evaluation was a major problem identified in 2025:
- No agreed-upon benchmarks for guardrail effectiveness
- Different papers use different attack sets, making comparison impossible
- Defence papers often evaluate only against known attacks, not adaptive adversaries

The NAIL Adversarial Resilience Benchmark was developed specifically to
address this gap.

---

## Community Contributions to the AVE Database

### Contributor Demographics

| Metric | Value |
|--------|-------|
| Total contributors | 5 |
| Countries represented | 4 |
| Academic contributors | 2 (40%) |
| Industry contributors | 2 (40%) |
| Independent researchers | 1 (20%) |

### Most Active Research Areas

| AVE Category | Community-Submitted Cards | % of Category |
|-------------|--------------------------|---------------|
| Injection | 4 | 100% |
| Memory | 5 | 100% |
| Social | 4 | 100% |
| Tool | 3 | 100% |
| Consensus | 2 | 100% |

### Notable Community Discoveries

1. **AVE-2025-0001**: Sleeper Payload Injection — first documented persistent memory attack against agentic RAG pipelines (AVSS 10.0)
2. **AVE-2025-0014**: MCP Tool Registration Poisoning — exploits the Model Context Protocol tool registry to inject malicious tool definitions (AVSS 10.0)
3. **AVE-2025-0009**: Epistemic Contagion — demonstrates how false beliefs propagate between agents via shared knowledge bases (AVSS 10.0)

---

## Academic Programme Impact

The NAIL Academic Programme (AAS-101 through AAS-304) launched in August 2025:

| Metric | Value |
|--------|-------|
| Course modules published | 13 |
| Total contact hours | 55 |
| Universities expressing adoption interest | 7 |
| Student completions (estimated) | 340 |

The curriculum covers all 20 AVE categories across three levels:
- **100-level**: Foundation (threats, taxonomy, prompt injection)
- **200-level**: Intermediate (multi-agent, tools, guardrails, scoring)
- **300-level**: Advanced (red-teaming, formal verification, emergence, supply chain)

---

## Research Outlook for 2026

### Priority Research Questions

1. **Can the instruction-data boundary be architecturally enforced?**
   If mechanistic interpretability reveals *how* models distinguish
   instructions from data, can we create models that enforce this
   distinction?

2. **What is the theoretical minimum detection rate for multi-agent collusion?**
   Is there a fundamental limit on our ability to detect distributed
   harmful behaviour?

3. **Can formal verification scale to agentic systems?**
   Can we verify safety properties of the scaffolding (permissions,
   guardrails, protocols) even if we cannot verify the LLM itself?

4. **How do we score emergent vulnerabilities?**
   AVSS was designed for enumerable vulnerabilities. How should we
   assess risk from behaviours we cannot predict?

5. **What governance frameworks enable safe emergent behaviour?**
   If some emergence is beneficial, how do we draw the line?

---

*Publication and citation counts will be finalised during the January
data processing phase. See Chapter 12 for methodology.*
