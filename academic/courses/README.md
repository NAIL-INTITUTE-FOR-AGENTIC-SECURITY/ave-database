# Course Modules — Agentic AI Security

University-ready course modules for integration into CS, AI, and cybersecurity curricula.

## Overview

Each module is a self-contained teaching unit (3-4 lecture hours + lab) designed to be
slotted into existing courses or combined into a full-semester elective.

## Module Catalogue

### Introductory (100-level)

| Module | Duration | Prerequisites | Description |
|--------|----------|---------------|-------------|
| [AAS-101](aas-101-intro-agentic-threats.md) | 3 hours | None | Introduction to Agentic AI Security Threats |
| [AAS-102](aas-102-ave-taxonomy.md) | 3 hours | AAS-101 | The AVE Taxonomy: Classifying Agent Vulnerabilities |
| [AAS-103](aas-103-prompt-injection.md) | 4 hours | AAS-101 | Prompt Injection in Agentic Systems |

### Intermediate (200-level)

| Module | Duration | Prerequisites | Description |
|--------|----------|---------------|-------------|
| [AAS-201](aas-201-multi-agent-security.md) | 4 hours | AAS-101 | Multi-Agent System Security |
| [AAS-202](aas-202-tool-use-risks.md) | 4 hours | AAS-101 | Tool-Use and Code Execution Risks |
| [AAS-203](aas-203-guardrails.md) | 4 hours | AAS-201 | Building Effective Guardrails |
| [AAS-204](aas-204-avss-scoring.md) | 3 hours | AAS-102 | AVSS: Scoring Agentic Vulnerabilities |

### Advanced (300-level)

| Module | Duration | Prerequisites | Description |
|--------|----------|---------------|-------------|
| [AAS-301](aas-301-red-teaming.md) | 6 hours | AAS-201, AAS-202 | Red-Teaming Multi-Agent Systems |
| [AAS-302](aas-302-formal-verification.md) | 6 hours | AAS-203, Math | Formal Verification of Agent Safety Properties |
| [AAS-303](aas-303-emergent-behaviour.md) | 4 hours | AAS-201 | Emergent & Adversarial Behaviour in Agent Swarms |
| [AAS-304](aas-304-supply-chain.md) | 4 hours | AAS-202 | AI Supply Chain Security |

### Full-Semester Elective

**"Agentic AI Security" (14 weeks)**
Combines modules: AAS-101 → 102 → 103 → 201 → 202 → 203 → 204 → 301 → Capstone Project

## Module Structure (Standard)

Each module includes:

```
aas-NNN-module-name.md
├── Learning Objectives (3-5 per module)
├── Lecture Content
│   ├── Core concepts
│   ├── Real-world examples (linked to AVE cards)
│   └── Discussion questions
├── Lab / Hands-On Exercise
│   ├── Setup instructions
│   ├── Exercise steps
│   └── Solution guide (instructor-only)
├── Assessment
│   ├── Quiz questions (10)
│   └── Assignment prompt
├── Further Reading
└── AVE Cards Referenced
```

## Adoption Guide

### Option A: Single Module Integration
Pick 1-2 modules relevant to your course. Each is self-contained.

**Example**: Add AAS-103 (Prompt Injection) to an existing NLP or LLM course.

### Option B: Mini-Track (3-4 weeks)
Use the introductory sequence: AAS-101 → 102 → 103.

**Example**: A 3-week "AI Security" segment in a broader AI course.

### Option C: Full Elective (14 weeks)
Use the complete module sequence as a standalone course.

**Example**: "CS 498: Agentic AI Security" as a senior/graduate elective.

## Licensing

All course materials are licensed under **CC BY 4.0**, allowing:
- Free use in any educational setting
- Modification and adaptation
- Commercial use (e.g., professional training)
- Attribution to NAIL Institute required

## Contributing

Faculty are invited to contribute modules or improvements:
1. Fork the repository
2. Create/edit modules following the standard structure
3. Submit a pull request
4. Academic Programme Committee reviews within 14 days
