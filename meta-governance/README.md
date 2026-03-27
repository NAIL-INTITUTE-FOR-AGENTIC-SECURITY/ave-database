# Meta-Governance Council

> Autonomous governance framework managing the governance of governance — meta-rules, constitutional amendments, and democratic decision-making for AI safety policy.

**Port:** 9304

## Overview

The Meta-Governance Council is the constitutional layer of the NAIL AVE platform. While the Policy Engine manages operational security rules and the Standards Evolution engine manages technical standards, the Meta-Governance Council governs the rules that govern those rules. It maintains a constitution of meta-principles, enables democratic amendment processes, manages the balance of power between automated systems and human oversight, and ensures that governance itself evolves safely and transparently.

## Core Capabilities

### 1. Constitutional Framework

- **Constitutional articles**: foundational principles that all lower-level policies must comply with
- 5 article categories: human_oversight, safety_invariants, transparency_requirements, power_distribution, amendment_procedures
- Article hierarchy: constitutional (immutable without supermajority) > statutory (standard amendment) > procedural (lightweight change)
- Cross-reference validation: articles can reference and depend on other articles
- Consistency checker: new articles validated against existing constitution for contradictions

### 2. Council Membership & Roles

- **5 council roles**: chair (agenda setting, tie-breaking), voting_member (full vote), observer (voice but no vote), technical_advisor (expert testimony), ombudsman (guardian of constitutional principles)
- Term-based membership with configurable duration (default 365 days)
- Expertise domains: each member tagged with areas of expertise across AVE categories
- Quorum rules: configurable minimum attendance (default 60%) for valid sessions
- Recusal tracking: members must recuse from votes where they have conflicts of interest

### 3. Amendment Process

- **7-stage pipeline**: proposal → discussion → committee_review → public_comment → vote → ratification → enacted
- Amendment types: add_article, modify_article, repeal_article, meta_amendment (changing the amendment process itself)
- Sponsor requirements: minimum 2 council members to co-sponsor a proposal
- Discussion periods: configurable minimum deliberation time (default 14 days)
- Committee assignment: proposals routed to relevant expertise committee

### 4. Democratic Voting

- **4 voting methods**: simple_majority (>50%), supermajority (>66.7%), unanimous, ranked_choice
- Constitutional amendments require supermajority; procedural changes require simple majority
- Secret ballot option for sensitive votes
- Proxy voting: absent members can delegate to present members
- Vote verification: cryptographic commitment scheme (hash-then-reveal) for auditability
- Cooling-off period: enacted amendments cannot be repealed for configurable duration

### 5. Power Balance Engine

- **Separation of powers**: monitors concentration of decision-making authority
- 4 power domains: legislative (rule-making), executive (enforcement), judicial (dispute resolution), oversight (audit)
- Concentration alerts: when any single entity controls >30% of decisions in any domain
- Human-AI balance tracking: ratio of human vs automated decisions per domain
- Escalation ladder: decisions above configurable impact threshold require human approval
- Override audit: every time a human overrides an AI recommendation (or vice versa), it's logged and analysed

### 6. Governance Health Metrics

- Participation rate: % of eligible members voting in each session
- Amendment velocity: proposals per quarter, passage rate, average time-to-enactment
- Constitutional coherence score: detected contradictions / total article pairs
- Power distribution Gini coefficient (0 = perfect equality, 1 = total concentration)
- Transparency index: % of decisions with full reasoning published

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/constitution` | Get full constitution |
| GET | `/v1/constitution/articles` | List articles with filters |
| GET | `/v1/constitution/articles/{article_id}` | Article detail with history |
| POST | `/v1/constitution/validate` | Validate proposed text against constitution |
| POST | `/v1/members` | Add council member |
| GET | `/v1/members` | List council members |
| GET | `/v1/members/{member_id}` | Member detail with voting record |
| POST | `/v1/amendments` | Propose an amendment |
| GET | `/v1/amendments` | List amendments with stage filter |
| GET | `/v1/amendments/{amendment_id}` | Amendment detail |
| POST | `/v1/amendments/{amendment_id}/advance` | Advance to next stage |
| POST | `/v1/amendments/{amendment_id}/vote` | Cast a vote |
| GET | `/v1/amendments/{amendment_id}/results` | Get voting results |
| GET | `/v1/power-balance` | Power distribution analysis |
| GET | `/v1/power-balance/alerts` | Concentration alerts |
| GET | `/v1/governance-health` | Governance health metrics |
| GET | `/v1/analytics` | Council analytics |
| GET | `/health` | Health check |

## Design Decisions

- **Constitutional hierarchy** — Meta-rules are harder to change than operational rules, preventing governance instability
- **Mandatory deliberation periods** — No amendment can be rushed through; minimum discussion time enforced
- **Power balance monitoring** — Inspired by constitutional separation of powers; prevents any single entity (human or AI) from accumulating unchecked authority
- **Meta-amendments require highest bar** — Changing the rules for changing rules requires unanimous consent, preventing governance capture
