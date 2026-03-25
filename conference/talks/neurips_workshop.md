# 🧠 NeurIPS — Workshop Paper Abstract

## Title

**Towards a Unified Vulnerability Taxonomy for Autonomous AI Agents:
The AVE Framework**

## Workshop Target

Workshop on Socially Responsible Language Modelling Research (SoLaR)
*or* Workshop on Red Teaming GenAI

## Authors

[Name], NAIL Institute for Agentic Security / Neuravant AI Limited

## Abstract (250 words)

The deployment of autonomous AI agents — systems that plan, use tools,
maintain memory, and coordinate with other agents — has outpaced the
development of security frameworks to describe their unique failure
modes. While significant attention has been paid to prompt injection,
the vulnerability landscape for agentic systems is far broader,
encompassing goal drift, multi-agent coordination failures, memory
poisoning, and emergent attack chains that have no analogues in
traditional software security or single-model AI safety.

We introduce the Agentic Vulnerability Enumeration (AVE) framework,
a systematic taxonomy of 50+ documented vulnerabilities across 14
categories, developed through controlled experimentation across major
agent frameworks. Each vulnerability is characterised by structured
evidence including reproduction steps, affected environments, blast
radius analysis, and defence evaluations.

We make three contributions: (1) a formal specification (AVE-RFC-0001)
defining a standardised format for documenting agentic vulnerabilities,
validated by JSON Schema and maintained through an open governance
process; (2) the Agentic Vulnerability Scoring System (AVSS), which
extends CVSS with dimensions specific to agent autonomy, tool access
breadth, and multi-agent interaction complexity; and (3) empirical
results from 29 experiments demonstrating that multi-agent systems
exhibit emergent vulnerabilities — specifically, coordination failures
and privilege escalation chains — that are absent in single-agent
deployments and cannot be predicted from individual agent assessments.

We release the full database, tooling, and API as open-source
community resources under CC-BY-SA-4.0 and Apache-2.0 licenses.

## Keywords

AI Safety, Agentic AI, Vulnerability Taxonomy, Red Teaming,
Multi-Agent Systems, Autonomous Agents

## Paper Length

8 pages + references (workshop format)

## Supplementary

- Full vulnerability database (50+ cards)
- Experiment reproduction code
- Statistical analysis notebooks
