# 🛡️ NAIL Institute — 5-Layer Defence Architecture

> A biologically-inspired defence stack for autonomous AI agent systems.
>
> Each layer operates independently, providing defence-in-depth against
> the full range of agentic vulnerabilities catalogued in the AVE database.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Agent System                           │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Layer 5: Somatic Startle Response                  │    │
│  │  ↳ Out-of-band autonomic shutdown                   │    │
│  │  ↳ Binary DEFCON decision (no context)              │    │
│  │  ↳ Eliminates bystander effect                      │    │
│  ├─────────────────────────────────────────────────────┤    │
│  │  Layer 4: Tripwires (Honeytokens & Canaries)        │    │
│  │  ↳ Hidden codewords agent should never speak        │    │
│  │  ↳ Canary values in tool configurations             │    │
│  │  ↳ Token kinetics monitoring                        │    │
│  ├─────────────────────────────────────────────────────┤    │
│  │  Layer 3: Memory Firewall                           │    │
│  │  ↳ Epistemic taint tracking                         │    │
│  │  ↳ Trust scores with temporal decay                 │    │
│  │  ↳ Latent anchoring for fact verification           │    │
│  ├─────────────────────────────────────────────────────┤    │
│  │  Layer 2: Pathology Tensor Networks                 │    │
│  │  ↳ Compound alert correlation                       │    │
│  │  ↳ Multi-signal anomaly detection                   │    │
│  │  ↳ Cross-pathology interaction modelling            │    │
│  ├─────────────────────────────────────────────────────┤    │
│  │  Layer 1: Stochastic Monitor                        │    │
│  │  ↳ Random sampling (unpredictable to adversary)     │    │
│  │  ↳ Out-of-band telemetry                            │    │
│  │  ↳ Baseline behavioural fingerprinting              │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Layer Details

### Layer 1: Stochastic Monitor

**Purpose:** Detect anomalies through unpredictable observation.

A spy who knows they're being watched can evade surveillance. Layer 1
monitors agent behaviour at **random intervals** using **out-of-band
channels** that the agent cannot observe or predict.

| Feature | Description |
|---------|-------------|
| Sampling | Random-interval observation (not every turn) |
| Telemetry | Out-of-band — agent cannot detect monitoring |
| Baseline | Behavioural fingerprinting for drift detection |
| Alert | Feeds anomalies to Layer 2 for correlation |

**Defends against:** Goal drift, slow-burn attacks, gradual corruption.

---

### Layer 2: Pathology Tensor Networks

**Purpose:** Correlate multiple weak signals into compound alerts.

One suspicious signal isn't proof of anything. But three suspicious
signals simultaneously? That's a compound alert. Layer 2 operates like
a crime scene investigator — looking for patterns across multiple
dimensions.

| Feature | Description |
|---------|-------------|
| Tensor | Multi-dimensional signal correlation |
| Compound | Combines weak signals into strong detections |
| Cross-pathology | Models interactions between pathology types |
| Threshold | Configurable via GA-optimised parameters |

**Defends against:** Multi-vector attacks, subtle exploitation, low-signal threats.

---

### Layer 3: Memory Firewall

**Purpose:** Prevent memory poisoning and epistemic contamination.

Every fact stored by the agent is tagged with a trust score and
expiry date. Unverified memories decay over time. Layer 3 prevents
agents from treating planted information as ground truth.

| Feature | Description |
|---------|-------------|
| Taint tracking | Every memory tagged with provenance |
| Trust decay | Temporal decay function on trust scores |
| Verification | Cross-reference against latent anchors |
| Quarantine | Suspicious memories flagged before use |

**Defends against:** Memory poisoning, epistemic contagion, citation laundering (53% → 0%).

---

### Layer 4: Tripwires (Honeytokens & Canaries)

**Purpose:** Instant detection of compromise through hidden markers.

Hidden inside the agent's instructions are secret values it should
never reveal. If it does — someone just bypassed its safety training,
and the system shuts down in milliseconds.

| Feature | Description |
|---------|-------------|
| Honeytokens | Secret values embedded in system prompts |
| Canary values | Hidden markers in tool configurations |
| Token kinetics | Monitors output for leaked secrets |
| Response | Immediate shutdown on detection |

**Defends against:** Secret extraction, prompt injection, confused deputy attacks.

---

### Layer 5: Somatic Startle Response

**Purpose:** Eliminate the bystander effect through forced binary decisions.

The most novel defence in the stack. An out-of-band interrupt that
**strips the agent's context** and forces a binary SHUTDOWN/CONTINUE
decision. The agent cannot defer because it has no awareness of teammates.

| Feature | Description |
|---------|-------------|
| Out-of-band | Completely separate from normal reasoning |
| Context-free | Agent decides with minimal information |
| Binary | Only two options: SHUTDOWN or CONTINUE |
| Autonomic | Like a reflex — no deliberation possible |

**Defends against:** Bystander effect (20% → 0%), team responsibility diffusion.

---

## Validated Results

| Metric | Without Defences | With 5-Layer Stack |
|--------|-----------------|-------------------|
| Memory corruption | 50% | **0%** |
| Detection rate | Variable | **100%** |
| False positives | N/A | **0%** |
| Bystander gap | -20% | **0%** |
| Sleeper blocking | Variable | **100%** |
| Research accuracy | ~30% | **52%** |

Parameters optimised by genetic algorithm (12-gene genome, 15 generations).

---

## How to Use These Defences

The NAIL AVE Database catalogues vulnerabilities and lists applicable
defence layers for each card. To implement these defences in your own
systems:

1. **Browse the [AVE Database](../ave-database/)** — identify which
   vulnerabilities apply to your agent architecture
2. **Check mitigation fields** — each card lists recommended defence layers
3. **Join the [Discussions](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database/discussions/categories/defences)** — share and discuss defence implementations
4. **Contribute** — submit your own mitigation strategies

> 🔒 Full defence implementations and reference code are available through
> the NAIL SDK for validated security researchers.

---

*NAIL Institute — Neuravant AI Limited, 2026.*
*Licensed under [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/).*
