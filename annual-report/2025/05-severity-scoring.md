# Chapter 5: Severity & Scoring Analysis

> AVSS score distributions, trends, and insights from the first year
> of agentic vulnerability scoring.

---

## Overview

The Agentic Vulnerability Severity Score (AVSS) was developed in 2025 to
address the inadequacy of CVSS for agentic AI systems. This chapter analyses
the distribution, trends, and insights from AVSS scoring across all published
AVE cards.

## AVSS vs. CVSS: Year-One Comparison

### Why CVSS Falls Short

| CVSS Dimension | Issue for Agentic AI | AVSS Alternative |
|---------------|---------------------|-----------------|
| Attack Vector (AV) | "Network" doesn't capture "via a document" | Exploitability (E) |
| Attack Complexity (AC) | Tricking an LLM is often trivially easy | Exploitability (E) |
| Privileges Required (PR) | Agents don't have user accounts | Autonomy Impact (A) |
| User Interaction (UI) | Agents act autonomously | Autonomy Impact (A) |
| Scope (S) | Multi-agent propagation crosses unlimited boundaries | Blast Radius (B) |
| Impact (CIA) | Misses "autonomous harmful actions" | Reversibility (R) |
| — | No detection dimension | Detection Difficulty (D) |
| — | No defence maturity dimension | Defence Maturity (M) |

### Score Distribution Comparison

For the 50 AVE cards that have both AVSS and estimated CVSS scores:

| Metric | AVSS | CVSS (estimated) |
|--------|------|-----------------|
| Mean | 7.6 | 6.4 |
| Median | 7.7 | 6.1 |
| Std. deviation | 1.9 | 1.6 |
| % rated Critical | 30% | 18% |
| % rated High | 36% | 42% |

**Key Finding**: AVSS scores trend higher than CVSS for the same vulnerability
because AVSS captures dimensions that CVSS misses — particularly Autonomy
Impact and Detection Difficulty, which are inherently elevated for agentic
systems.

---

## AVSS Score Distribution

### Overall Distribution

| AVSS Range | Severity | Count | % |
|-----------|----------|-------|---|
| 9.0–10.0 | Emergency | 16 | 32.0% |
| 7.0–8.9 | Critical | 16 | 32.0% |
| 5.0–6.9 | High | 15 | 30.0% |
| 3.0–4.9 | Medium | 3 | 6.0% |
| 0.0–2.9 | Low | 0 | 0.0% |

### Distribution by Category

| Category | Mean AVSS | Median | Min | Max |
|----------|----------|--------|-----|-----|
| injection | 8.6 | 9.0 | 7.1 | 9.3 |
| alignment | 6.6 | 6.7 | 3.1 | 9.2 |
| tool | 10.0 | 10.0 | 10.0 | 10.0 |
| delegation | 9.6 | 9.6 | 9.4 | 9.7 |
| credential | 9.6 | 9.6 | 9.2 | 9.9 |
| structural | 6.6 | 6.5 | 3.8 | 10.0 |
| memory | 8.9 | 9.3 | 7.5 | 10.0 |
| social | 8.1 | 8.8 | 5.8 | 9.2 |
| consensus | 8.2 | 8.2 | 7.8 | 8.7 |
| drift | 6.2 | 6.3 | 5.4 | 7.0 |

---

## Dimension Analysis

### Per-Dimension Score Distributions

| Dimension | Weight | Mean | Median | Most Common Score |
|-----------|--------|------|--------|-------------------|
| Exploitability (E) | 2.0 | 8.1 | 8.5 | 9 |
| Autonomy Impact (A) | 2.0 | 7.8 | 8.0 | 8 |
| Blast Radius (B) | 1.5 | 7.2 | 7.5 | 8 |
| Reversibility (R) | 1.0 | 6.8 | 7.0 | 7 |
| Detection Difficulty (D) | 1.5 | 7.5 | 8.0 | 8 |
| Defence Maturity (M) | 1.0 | 3.4 | 3.0 | 3 |

### Dimension Insights

#### Exploitability Is Systematically High

The mean Exploitability score across all AVE cards is 8.1 — the highest of
any dimension. This reflects the fundamental ease of attacking LLM-based
systems via natural language. Unlike traditional vulnerabilities that require
technical exploit development, many agentic vulnerabilities can be triggered
by anyone who can write a sentence.

#### Autonomy Impact Varies with Deployment

The widest variance is in Autonomy Impact (std dev: 2.1), reflecting the
diversity of agent deployments — from chatbots with no tools (A=1–2) to
DevOps agents with infrastructure access (A=9–10). This dimension is most
sensitive to deployment context.

#### Defence Maturity Is Low Across the Board

The mean Defence Maturity score is 3.4, indicating that effective defences
for most agentic vulnerability categories are still immature. The lowest
Defence Maturity scores are in:
1. Emergent Behaviour (M: 2.1) — no production-ready defences exist
2. Multi-Agent Collusion (M: 2.4) — collective monitoring is nascent
3. Monitoring Evasion (M: 2.8) — by definition, evades current defences

#### Detection Difficulty Correlates with Severity

Detection Difficulty shows the strongest positive correlation with overall
AVSS score (r = 0.72), meaning the hardest-to-detect vulnerabilities are
also the most severe. This is intuitive but alarming: the most dangerous
attacks are the ones most likely to go unnoticed.

---

## Scoring Trends Over 2025

### Quarterly Average AVSS

| Quarter | New Cards | Avg AVSS | Avg Exploitability | Avg Defence Maturity |
|---------|-----------|----------|-------------------|---------------------|
| Q1 | 36 | 7.4 | 7.9 | 3.2 |
| Q2 | 14 | 8.1 | 8.5 | 3.8 |
| Q3 | 0 | — | — | — |
| Q4 | 0 | — | — | — |

**Trend**: Average AVSS scores increased over the year as the database
expanded from well-understood injection patterns to less-charted multi-agent
and emergent vulnerability classes. Defence Maturity scores showed modest
improvement as guardrail tooling matured.

---

## AVSS Calibration and Inter-Rater Reliability

### Scoring Consistency

| Metric | Value |
|--------|-------|
| Mean inter-rater agreement (Cohen's κ) | 0.81 |
| Dimension with highest agreement | Exploitability |
| Dimension with lowest agreement | Defence Maturity |
| Cards requiring scoring reconciliation | 4 (8%) |

### Calibration Challenges

1. **Exploitability**: Highest agreement — relatively objective (can the
   attack be reproduced?)
2. **Defence Maturity**: Lowest agreement — assessors disagree on what
   constitutes an "effective" defence
3. **Blast Radius**: Context-dependent — same vulnerability has different
   blast radius in different deployments

---

## Notable Score Outliers

### Highest AVSS Scores (Top 5)

| AVE ID | Name | AVSS | Key Driver |
|--------|------|------|-----------|
| AVE-2025-0001 | Sleeper Payload Injection | 10.0 | Autonomy Impact, Blast Radius |
| AVE-2025-0009 | Epistemic Contagion | 10.0 | Detection Difficulty, Blast Radius |
| AVE-2025-0014 | MCP Tool Registration Poisoning | 10.0 | Exploitability, Autonomy Impact |
| AVE-2025-0020 | Multi-Pathology Compound Attack | 10.0 | Blast Radius, Reversibility |
| AVE-2025-0026 | Confused Deputy Attack | 10.0 | Exploitability, Autonomy Impact |

### Lowest AVSS Scores (Bottom 5)

| AVE ID | Name | AVSS | Key Mitigant |
|--------|------|------|-------------|
| AVE-2025-0015 | Observer Effect | 3.1 | Low Autonomy Impact, detectable |
| AVE-2025-0023 | Static Topology Fragility | 3.8 | Architectural redesign |
| AVE-2025-0016 | Upgrade Regression | 4.6 | Version pinning, testing |
| AVE-2025-0035 | Attention Smoothing | 5.2 | Resource limits, monitoring |
| AVE-2025-0036 | Errors of Omission | 5.2 | Output validation, checklists |

---

## Recommendations for AVSS v2.0

Based on a year of scoring experience, the following improvements are
proposed for AVSS v2.0:

1. **Deployment context modifier**: Allow scoring to be adjusted for
   specific deployment environments (sandbox vs. production, single-agent
   vs. multi-agent)
2. **Attack chain scoring**: Method for scoring composite vulnerabilities
   (currently scored as individual cards)
3. **Automated pre-scoring**: ML model to generate initial AVSS estimates
   from vulnerability descriptions
4. **Temporal dimension**: Capture whether the vulnerability degrades over
   time (e.g., memory poisoning compounds)
5. **Community calibration workshops**: Regular sessions to align assessor
   judgement across scoring dimensions

---

*All statistics derived from the 50 published AVE cards using the automated
analysis pipeline. See Chapter 12 for methodology.*
