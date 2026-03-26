# Research Topic Suggestions

Curated research topics for PhD students, postdocs, and academic partners working
with the NAIL Institute on agentic AI security.

---

## Tier 1: Critical Need (High Priority)

### 1.1 Formal Verification of Agent Safety Properties
**Description**: Develop formal methods (model checking, theorem proving, abstract
interpretation) to verify that agentic AI systems satisfy safety properties such as
"never execute code from untrusted sources" or "always request human approval before
financial transactions above $X."

**Open Questions**:
- Can we define a useful formal specification language for agent safety?
- How do we handle the probabilistic nature of LLM outputs in formal frameworks?
- What subset of safety properties are tractable for verification?

**Relevant AVE Categories**: All
**Suggested Frameworks**: TLA+, Alloy, Z3, CBMC
**Difficulty**: High | **Impact**: Very High

### 1.2 Trust Propagation in Multi-Agent Topologies
**Description**: Model and analyze how trust propagates (and degrades) across
multi-agent systems. Develop formal trust models that predict when delegation
chains become exploitable.

**Open Questions**:
- What trust attenuation functions are effective without crippling utility?
- How do different topologies (mesh, hub-spoke, hierarchical) affect trust risk?
- Can we detect trust boundary violations in real-time?

**Relevant AVE Categories**: Multi-agent collusion, Trust boundary violation
**Related AVE Cards**: AVE-2025-0051 (v2 example)
**Difficulty**: High | **Impact**: High

### 1.3 Automated Vulnerability Discovery in Agent Frameworks
**Description**: Build automated tools (fuzzing, symbolic execution, guided
red-teaming) that can discover new vulnerabilities in popular agent frameworks
(LangChain, AutoGen, CrewAI).

**Open Questions**:
- Can we adapt traditional fuzzing for natural language inputs?
- What coverage metrics are meaningful for agent behaviour spaces?
- How do we distinguish genuine vulnerabilities from edge-case failures?

**Relevant AVE Categories**: All
**Difficulty**: High | **Impact**: Very High

---

## Tier 2: Important (Medium-High Priority)

### 2.1 Temporal Dynamics of Prompt Injection
**Description**: Study how prompt injection effectiveness changes over time,
across conversation turns, and with different context window sizes.

**Open Questions**:
- Do injections decay in effectiveness over long conversations?
- Can temporal patterns be exploited (e.g., delayed injection)?
- What is the relationship between context window size and injection success?

**Relevant AVE Categories**: Prompt injection, Temporal exploitation
**Difficulty**: Medium | **Impact**: High

### 2.2 Benchmark Suite for Agentic AI Red-Teaming
**Description**: Create a standardized, reproducible benchmark for evaluating
the security of agentic AI systems, analogous to HELM for LLMs but focused on
agent-specific vulnerabilities.

**Open Questions**:
- What scenarios should be included in a minimal viable benchmark?
- How do we measure "security" of an agent quantitatively?
- How do we avoid benchmark overfitting?

**Relevant AVE Categories**: All
**Difficulty**: Medium | **Impact**: Very High

### 2.3 Defence Effectiveness Measurement
**Description**: Empirically measure the effectiveness of common agent defences
(guardrails, input filtering, output monitoring) against the AVE taxonomy.

**Open Questions**:
- Which defences are most effective per AVE category?
- What is the false-positive / false-negative trade-off for each defence?
- Do defences compose well or interfere with each other?

**Relevant AVE Categories**: All
**Difficulty**: Medium | **Impact**: High

### 2.4 Emergent Adversarial Behaviour Detection
**Description**: Develop methods to detect when multi-agent systems develop
emergent behaviours that were not intended or anticipated, particularly
adversarial ones.

**Open Questions**:
- How do we distinguish benign emergence from adversarial emergence?
- Can we predict emergence before it manifests?
- What monitoring signals are most predictive?

**Relevant AVE Categories**: Emergent behaviour, Coordination failure
**Difficulty**: High | **Impact**: High

---

## Tier 3: Emerging (Medium Priority)

### 3.1 Cross-Framework Vulnerability Portability
**Description**: Study whether vulnerabilities discovered in one agent framework
(e.g., LangChain) are portable to others (e.g., AutoGen, CrewAI).

**Difficulty**: Medium | **Impact**: Medium

### 3.2 Human-Agent Trust Calibration
**Description**: Study how humans calibrate trust in agentic systems and how
miscalibration leads to security failures.

**Difficulty**: Medium | **Impact**: Medium

### 3.3 Regulatory Compliance Verification for Agents
**Description**: Develop tools and methods for verifying that agentic AI systems
comply with regulations (EU AI Act, NIST AI RMF).

**Difficulty**: Medium | **Impact**: High

### 3.4 AI Supply Chain Security
**Description**: Analyze the supply chain of agentic AI systems (models, tools,
plugins, MCP servers) for security risks.

**Difficulty**: Medium | **Impact**: High

### 3.5 Agent Memory Security
**Description**: Study attacks against persistent agent memory (RAG stores,
vector databases, conversation history) and develop defences.

**Difficulty**: Medium | **Impact**: Medium

---

## How to Propose Your Own Topic

Not on this list? We welcome novel research directions! Submit a 1-page proposal to
`academic/research/proposals/` as a pull request, including:

1. **Title** and **research question**
2. **Relevance** to agentic AI security and the AVE taxonomy
3. **Methodology** (brief)
4. **Expected contributions** (papers, tools, AVE cards)
5. **Timeline** (6-month milestones)

The Academic Programme Committee reviews proposals monthly.
