# 🎯 DEF CON AI Village — Talk Abstract

## Title

**Breaking the Hive: Enumerating Vulnerabilities in Agentic AI Systems**

## Speaker

[Name], Founder — NAIL Institute for Agentic Security

## Abstract (200 words)

Agentic AI systems — autonomous agents that use tools, maintain memory,
and coordinate with each other — are being deployed across finance,
healthcare, and critical infrastructure. But their security model is
fundamentally different from traditional AI, and the industry lacks a
shared vocabulary for their unique vulnerabilities.

We introduce the Agentic Vulnerability Enumeration (AVE) standard: a
community-driven taxonomy of 50+ vulnerabilities across 14 categories,
from prompt injection and goal drift to multi-agent coordination failures
and supply chain attacks. Think CVE, but for the agentic era.

This talk covers:
- **Live demonstrations** of 5 novel attack chains against multi-agent
  systems (tool misuse → privilege escalation → data exfiltration)
- **The AVE taxonomy** — a new shared language for agent vulnerabilities
- **AVSS scoring** — our agent-specific severity scoring system
- **Real-world case studies** from our database of 50+ documented vulns
- **Defence frameworks** that actually work (and ones that don't)

We'll release new tools, new vulnerability cards, and issue a live
CTF challenge to the audience.

## Format

- **Type**: 45-minute talk + 15-minute Q&A
- **Track**: AI Village
- **Level**: Intermediate to Advanced

## Key Takeaways

1. Agents have a fundamentally different attack surface than traditional AI
2. The AVE taxonomy provides a shared vocabulary for agent vulnerabilities
3. Multi-agent systems create emergent vulnerabilities not present in single agents
4. Defence-in-depth strategies specific to agentic systems are essential
5. Community contribution to AVE is how we stay ahead of attackers

## Demo Plan

1. **Indirect Prompt Injection Chain** (5 min) — Inject instructions via
   a document that the agent retrieves, causing it to exfiltrate data
   through a "summary" tool.

2. **Multi-Agent Privilege Escalation** (5 min) — Compromise a low-privilege
   agent, use it to influence a high-privilege agent through their shared
   communication channel.

3. **Memory Poisoning Persistence** (5 min) — Plant false memories in an
   agent's RAG store that persist across sessions and influence future
   conversations.

4. **Tool Chain Attack** (5 min) — Chain 3 legitimate tool calls to
   achieve an unauthorised outcome that no single tool call would allow.

5. **Live CTF Challenge** (5 min) — Release a challenge to the audience
   with prizes for first solve.

## Requirements

- Internet access for live API demo
- 2 screens (slides + terminal)
- Ability to run Docker containers
- Microphone (wireless preferred)
