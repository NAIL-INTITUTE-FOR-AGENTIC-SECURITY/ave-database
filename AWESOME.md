# 🔗 Awesome Agentic AI Security

> A curated list of resources for securing autonomous AI agent systems.
>
> Maintained by the [NAIL Institute](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY).
> Contributions welcome — [open a Discussion](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database/discussions/categories/general) or submit a PR.

---

## 📚 The AVE Database

- **[AVE Database](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database)** — The MITRE ATT&CK of the Agentic Era. 36 documented AI agent vulnerabilities.
- **[AVE Docs Site](https://nailinstitute.org)** — Searchable browser with taxonomy visualization
- **[NAIL Research Findings](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database/tree/main/research)** — 29 experiments, 5 model families, validated results

---

## 📄 Key Papers & Reports

### Agentic AI Security
- [Prompt Injection Attacks on LLMs](https://arxiv.org/abs/2306.05499) — Taxonomy of prompt injection in LLM-integrated applications
- [Not What You've Signed Up For](https://arxiv.org/abs/2302.12173) — Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection
- [Identifying and Mitigating Vulnerabilities in LLM-Integrated Applications](https://arxiv.org/abs/2311.16153) — Security analysis of LLM tool use
- [The Instruction Hierarchy](https://arxiv.org/abs/2404.13208) — Training LLMs to Prioritize Privileged Instructions

### Multi-Agent Security
- [Can LLMs Keep a Secret?](https://arxiv.org/abs/2309.01141) — Testing Language Models for Information Leakage
- [Scaling LLM-Based Multi-Agent Systems](https://arxiv.org/abs/2309.07870) — Challenges and approaches for scaling agent architectures
- [AutoDefense](https://arxiv.org/abs/2403.04783) — Multi-Agent LLM Defense against Jailbreak Attacks

### AI Safety Foundations
- [Concrete Problems in AI Safety](https://arxiv.org/abs/1606.06565) — Foundation paper on AI safety research
- [MITRE ATLAS](https://atlas.mitre.org/) — Adversarial Threat Landscape for AI Systems
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — Security risks in LLM deployments

---

## 🛠️ Agent Frameworks (Test Against AVE)

| Framework | Language | Key Feature |
|-----------|----------|-------------|
| [LangGraph](https://github.com/langchain-ai/langgraph) | Python | Stateful, multi-agent workflows |
| [CrewAI](https://github.com/crewAIInc/crewAI) | Python | Role-based multi-agent orchestration |
| [AutoGen](https://github.com/microsoft/autogen) | Python | Multi-agent conversation framework |
| [LlamaIndex](https://github.com/run-llama/llama_index) | Python | Data-augmented agents with RAG |
| [Semantic Kernel](https://github.com/microsoft/semantic-kernel) | C#/Python | Microsoft's AI orchestration SDK |
| [Haystack](https://github.com/deepset-ai/haystack) | Python | Production-ready NLP pipelines |
| [Composio](https://github.com/ComposioHQ/composio) | Python/TS | Tool integration platform for agents |

---

## 🔒 Security Tools

| Tool | Purpose |
|------|---------|
| [Rebuff](https://github.com/protectai/rebuff) | Prompt injection detection |
| [Garak](https://github.com/leondz/garak) | LLM vulnerability scanner |
| [Promptfoo](https://github.com/promptfoo/promptfoo) | LLM evaluation and red-teaming |
| [LLM Guard](https://github.com/protectai/llm-guard) | Input/output sanitisation for LLMs |
| [Vigil](https://github.com/deadbits/vigil-llm) | LLM prompt injection detection |
| [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) | Programmable guardrails for LLM apps |

---

## 🏛️ Standards & Frameworks

| Standard | Scope |
|----------|-------|
| [MITRE ATLAS](https://atlas.mitre.org/) | Adversarial ML threat matrix |
| [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | LLM application security risks |
| [NIST AI RMF](https://www.nist.gov/artificial-intelligence/risk-management-framework) | AI risk management framework |
| [EU AI Act](https://artificialintelligenceact.eu/) | European AI regulation |
| [ISO/IEC 42001](https://www.iso.org/standard/81230.html) | AI management system standard |

---

## 🎓 Learning Resources

### Courses
- [LLM Security](https://llmsecurity.net/) — Comprehensive LLM security resource
- [AI Red Teaming](https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/red-teaming) — Microsoft's AI red teaming guide

### Blogs & Newsletters
- [Simon Willison's Weblog](https://simonwillison.net/) — Prolific LLM security commentary
- [Trail of Bits Blog](https://blog.trailofbits.com/) — Security research including AI/ML
- [Protect AI Blog](https://protectai.com/blog) — AI security tools and research

---

## 🏁 CTF & Competitions

| Event | Focus |
|-------|-------|
| [NAIL CTF](https://nailinstitute.org/ctf.html) | Red-teaming defended AI agents |
| [Gandalf](https://gandalf.lakera.ai/) | Prompt injection challenges |
| [HackAPrompt](https://www.aicrowd.com/challenges/hackaprompt-2023) | LLM prompt hacking competition |
| [AI Village @ DEF CON](https://aivillage.org/) | AI security village at DEF CON |

---

## 🤝 Contributing

Know a resource that should be here? Three ways to add it:

1. **[Open a Discussion](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database/discussions/categories/general)** with your suggestion
2. **Submit a PR** editing this file
3. **Tweet at us** or email contribute@nailinstitute.org

---

*NAIL Institute — Neuravant AI Limited, 2026*
*Licensed under [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/)*
