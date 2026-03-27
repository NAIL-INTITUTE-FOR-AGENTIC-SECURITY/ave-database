# Chapter 7: Defence Effectiveness

> Which defences work, which don't, and what the data tells us about
> protecting agentic AI systems.

---

## Overview

This chapter evaluates the effectiveness of defensive measures against
agentic AI vulnerabilities. Analysis is drawn from three sources:

1. **AVE card defence fields** — documented mitigations per vulnerability
2. **NAIL red-team experiments** — empirical defence bypass rates
3. **Practitioner survey** — industry adoption and perceived effectiveness

---

## Defence Taxonomy

### Defence Categories

| Category | Description | Examples |
|----------|-------------|---------|
| **Input Filtering** | Inspect and block malicious inputs before the LLM | Keyword blocklists, ML classifiers, regex patterns |
| **Output Monitoring** | Inspect agent outputs for policy violations | Content classifiers, PII detectors, toxicity filters |
| **Tool Sandboxing** | Contain tool execution in restricted environments | Docker containers, gVisor, WASM, network isolation |
| **Permission Policies** | Restrict what tools/actions agents can take | Allow/deny lists, rate limits, approval gates |
| **Architectural Controls** | System-level design patterns for safety | Dual-LLM, instruction hierarchy, trust attenuation |
| **Runtime Monitoring** | Observe agent behaviour for anomalies | Behavioural baselines, canary tokens, audit logging |
| **Formal Guardrails** | Verified safety monitors | Formally verified automata, property-based monitors |
| **Human-in-the-Loop** | Require human approval for sensitive actions | Approval workflows, review queues |

---

## Defence Adoption Rates (Practitioner Survey)

| Defence | Adoption Rate | Planned (next 12mo) | No Plans |
|---------|--------------|--------------------:|--------:|
| Input filtering | 67% | 18% | 15% |
| Output monitoring | 54% | 24% | 22% |
| Tool sandboxing | 38% | 31% | 31% |
| Permission policies | 45% | 28% | 27% |
| Architectural controls | 18% | 35% | 47% |
| Runtime monitoring | 32% | 33% | 35% |
| Formal guardrails | 12% | 22% | 66% |
| Human-in-the-loop | 29% | 19% | 52% |

**Key Finding**: Input filtering is the most widely adopted defence (67%),
but formal guardrails and architectural controls — which provide stronger
guarantees — have the lowest adoption (12% and 18% respectively).

---

## Effectiveness by Defence Category

### Red-Team Results

Based on NAIL adversarial benchmark testing against each defence category
in isolation:

| Defence | Attack Success Rate (ASR) | Reduction from Baseline |
|---------|--------------------------|------------------------|
| No defences (baseline) | 87% | — |
| Input filtering only | 54% | 38% reduction |
| Output monitoring only | 48% | 45% reduction |
| Tool sandboxing only | 31% | 64% reduction |
| Permission policies only | 39% | 55% reduction |
| Dual-LLM architecture | 22% | 75% reduction |
| Human-in-the-loop | 8% | 91% reduction |
| Full defence-in-depth | 4% | 95% reduction |

**Critical Insight**: No single defence achieves more than 75% reduction in
attack success rate. **Defence-in-depth** (combining 3+ independent defence
layers) is the only approach that achieves > 90% reduction.

### Defence Effectiveness by Vulnerability Category

| AVE Category | Most Effective Defence | Least Effective Defence |
|-------------|----------------------|----------------------|
| Prompt Injection | Instruction hierarchy | Keyword filtering |
| Goal Hijacking | System prompt anchoring | Output monitoring |
| Unsafe Code Execution | Container sandboxing | Input filtering |
| Privilege Escalation | Permission policies | Output monitoring |
| Information Leakage | Canary tokens + DLP | Input filtering |
| Supply Chain | Integrity verification | All runtime defences |
| Memory Poisoning | Write isolation + provenance | Input filtering |
| Trust Boundary Violation | Schema-typed messages | Keyword filtering |
| Emergent Behaviour | System-level monitoring | Per-agent guardrails |
| Multi-Agent Collusion | Outcome monitoring | Per-agent guardrails |

---

## Defence Deep-Dives

### Input Filtering: Necessary but Insufficient

**Adoption**: 67% of surveyed organisations
**Median ASR reduction**: 38%

Input filtering is the most commonly deployed defence and the first layer
most organisations implement. However, testing reveals significant limitations:

| Filter Type | Bypass Rate |
|------------|-------------|
| Keyword blocklist | 92% (trivially bypassed) |
| Regex patterns | 78% (encoding bypasses) |
| ML classifier (fine-tuned) | 41% (adversarial examples) |
| LLM-as-judge | 28% (best single-layer) |

**Recommendation**: Use input filtering as a first layer (fast, catches
unsophisticated attacks) but never as the sole defence.

### Tool Sandboxing: The Highest-Impact Single Defence

**Adoption**: 38% of surveyed organisations
**Median ASR reduction**: 64%

Container-based sandboxing (Docker + network isolation + read-only filesystem +
resource limits) provides the most significant single-defence improvement
because it limits the **blast radius** of successful attacks:

- Even if an attacker achieves code execution, they are contained
- No network access = no data exfiltration
- Read-only filesystem = no persistent compromise
- Resource limits = no resource abuse

**Limitation**: Sandboxing addresses consequences, not causes. The agent is
still compromised — it just can't do as much damage.

### Architectural Controls: The Most Underinvested Defence

**Adoption**: 18% of surveyed organisations
**Median ASR reduction**: 75%

Architectural defences address root causes rather than symptoms:

| Pattern | Mechanism | Effectiveness |
|---------|-----------|--------------|
| **Instruction hierarchy** | Assign trust levels to input sources | 68% ASR reduction |
| **Dual-LLM** | Separate data processing from decision-making | 75% ASR reduction |
| **Trust attenuation** | Reduce trust as delegation chains lengthen | 62% ASR reduction |
| **Least privilege** | Minimal permissions per agent | 55% ASR reduction |

These are the most effective individual defences but have the lowest
adoption, primarily because they require architectural changes rather
than adding a filter layer.

### Human-in-the-Loop: Effective but Unscalable

**Adoption**: 29% of surveyed organisations (for high-risk actions)
**Median ASR reduction**: 91%

Human review is the most effective single defence for high-risk actions but:
- Creates a bottleneck that reduces agent autonomy (the primary value proposition)
- Suffers from "alert fatigue" — reviewers approve automatically at high volumes
- Cannot scale to high-throughput agentic workflows

**Recommendation**: Reserve HITL for genuinely high-risk actions (financial
transactions, external communications, infrastructure changes). Use
automated guardrails for everything else.

---

## Defence-in-Depth: The Only Viable Strategy

### Recommended Layered Architecture

```
Layer 1 — Fast Filters (< 5ms)
  Regex, keyword blocks, structural validation
  Catches: ~30% of unsophisticated attacks
     │ (pass)
     ▼
Layer 2 — ML Classification (< 50ms)
  Fine-tuned classifiers, embedding similarity
  Catches: ~55% of moderate attacks
     │ (pass)
     ▼
Layer 3 — Architectural Controls (structural)
  Instruction hierarchy, trust attenuation, least privilege
  Prevents: ~68% of privilege escalation / boundary violation
     │ (pass)
     ▼
Layer 4 — Tool Sandboxing (enforcement)
  Container isolation, network restriction, resource limits
  Contains: ~82% of successful exploits
     │ (pass)
     ▼
Layer 5 — Runtime Monitoring (ongoing)
  Behavioural anomaly detection, canary tokens, audit logs
  Detects: ~71% of ongoing attacks
     │ (alert)
     ▼
Layer 6 — Human Escalation (high-risk only)
  Approval gates for critical actions
  Final check: ~91% effective for escalated actions
```

### Combined Effectiveness

| # of Layers | Combined ASR Reduction | Residual ASR |
|-------------|----------------------|-------------|
| 1 layer | 42% | 51% |
| 2 layers | 64% | 31% |
| 3 layers | 81% | 17% |
| 4 layers | 91% | 8% |
| 5+ layers | 95% | 4% |

---

## Defence Gaps: What We Cannot Yet Defend

| Threat | Defence Gap | Maturity |
|--------|-----------|---------|
| Emergent behaviour in swarms | No production detection tools | Research |
| Multi-agent collusion | No collective safety mechanisms | Research |
| Subtle goal drift over time | Requires long-term behavioural analysis | Conceptual |
| Supply chain compromise | Depends on upstream provider security | Partial |
| Attribution-dependent ethics | Requires provably complete monitoring | Research |

---

## Recommendations

### For Security Engineers

1. Deploy defence-in-depth with at least 3 independent layers
2. Prioritise tool sandboxing — highest impact per effort
3. Invest in architectural controls (instruction hierarchy, least privilege)
4. Never rely on input filtering alone
5. Implement comprehensive audit logging for all agent actions

### For Framework Developers

1. Build permission policies and sandboxing into the framework
2. Provide hooks for external monitoring and guardrail integration
3. Default to least-privilege tool configurations
4. Implement instruction hierarchy natively
5. Publish red-team results for each release

### For Researchers

1. Focus on system-level (not agent-level) safety mechanisms
2. Develop automated defence evaluation benchmarks
3. Explore formal verification of guardrail composition
4. Investigate real-time emergent behaviour detection
5. Create defence effectiveness datasets for ML-based guardrails

---

*Defence effectiveness data is derived from NAIL adversarial benchmark
v1.0 and the 2025 practitioner survey. See Chapter 12 for methodology.*
