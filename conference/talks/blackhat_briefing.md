# ⚔️ Black Hat USA — Briefing Submission

## Title

**AVE: A Systematic Approach to Agentic AI Vulnerability Enumeration**

## Track

Applied Security / AI & Machine Learning

## Abstract (300 words)

The rapid deployment of agentic AI systems — autonomous agents with tool
access, persistent memory, and multi-agent coordination capabilities —
has created an entirely new class of security vulnerabilities that
existing frameworks cannot adequately describe or address. Traditional
vulnerability databases (CVE, CWE) and scoring systems (CVSS) were
designed for software vulnerabilities, not for systems that can be
manipulated through natural language, accumulate state across sessions,
and delegate actions to other autonomous entities.

We present the Agentic Vulnerability Enumeration (AVE) standard, a
comprehensive framework for cataloguing, scoring, and defending against
vulnerabilities specific to agentic AI systems. Built through open
community collaboration, AVE currently documents 50+ unique vulnerabilities
across 14 categories, each with structured evidence, MITRE ATT&CK/ATLAS
mappings, and scored using our purpose-built Agentic Vulnerability Scoring
System (AVSS).

Our research contributions include:

1. **A novel vulnerability taxonomy** purpose-built for agentic systems,
   covering attack vectors from prompt injection cascades to emergent
   multi-agent coordination failures — categories with no equivalent in
   existing frameworks.

2. **Empirical evidence** from 29 controlled experiments across major
   agent frameworks (LangChain, CrewAI, AutoGen, LlamaIndex),
   demonstrating reproducible attack chains with quantified success rates.

3. **A scoring methodology** (AVSS) that accounts for agent-specific
   factors including autonomy level, tool access breadth, and
   multi-agent blast radius — dimensions absent from CVSS.

4. **Mapping to existing standards** — every AVE card is mapped to
   MITRE ATT&CK, ATLAS, and CWE, with regulatory mappings to EU AI Act,
   NIST AI RMF, ISO 42001, and EO 14110.

5. **Open tooling** — CLI tools, API, VS Code extension, CI/CD
   integration, and an SBOM generator for agentic AI systems.

We will demonstrate novel multi-step attack chains, release new
vulnerability disclosures, and present our certification programme
for assessing agentic AI system security.

## Format

- **Type**: 50-minute Briefing
- **Level**: Intermediate

## Outline

| Time | Section |
|------|---------|
| 0–8 min | The agentic AI revolution and its security gap |
| 8–18 min | AVE taxonomy: 14 categories of agent vulnerabilities |
| 18–28 min | Live demonstrations: 3 novel attack chains |
| 28–35 min | AVSS scoring and risk quantification |
| 35–42 min | Defence frameworks and certification |
| 42–50 min | Regulatory mapping and industry adoption |

## Arsenal Submission (Tool Demo)

**Tool Name**: NAIL AVE Toolkit

**Description**: Open-source command-line toolkit for searching,
analysing, and assessing agentic AI systems against the AVE standard.
Includes certification checker, risk scorer, compliance mapper, and
API client. Attendees can assess their own systems during the demo.

**Requirements**: Laptop with Docker, internet access
