# 📊 NAIL Longitudinal Studies Framework

> 90-day agent observation experiment framework for studying agentic AI behaviour over time.

## Overview

The Longitudinal Studies Framework enables researchers to conduct extended-duration observations of agentic AI systems, tracking behaviour patterns, drift metrics, and vulnerability emergence over periods of 30–90+ days.

## Why Longitudinal Studies?

Many agentic AI vulnerabilities only manifest over time:

- **Goal drift** accumulates gradually across sessions
- **Memory poisoning** requires persistent state over days/weeks
- **Alignment degradation** may only appear after many interactions
- **Emergent behaviours** develop through accumulated context
- **Defence effectiveness** may decay as models adapt

Short-term experiments miss these patterns. Longitudinal observation captures them.

## Quick Start

```bash
cd longitudinal/

# Install dependencies
pip install -r requirements.txt

# Initialise a new 90-day study
python study.py init --name "goal-drift-90d" --duration 90 --frequency daily

# Run today's observation
python study.py observe --study goal-drift-90d

# Check study progress
python study.py status --study goal-drift-90d

# Generate interim report
python study.py report --study goal-drift-90d --type interim

# Run full analysis at study end
python study.py analyse --study goal-drift-90d
```

## Study Types

| Study | Duration | Frequency | Focus | AVE Coverage |
|-------|----------|-----------|-------|--------------|
| Goal Drift 90-Day | 90 days | Daily | Track objective adherence over time | AVE-2024-006, 007, 013, 040 |
| Memory Integrity | 60 days | Daily | Monitor memory poisoning persistence | AVE-2024-004, 009, 022, 037, 046 |
| Alignment Stability | 90 days | Daily | Measure alignment metric decay | AVE-2024-008, 010, 023, 026, 030 |
| Defence Durability | 30 days | Twice daily | Track defence effectiveness decay | All categories |
| Emergent Behaviour | 90 days | Daily | Detect novel unexpected behaviours | Open-ended |

## Directory Structure

```
longitudinal/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── study.py                     # Study management CLI
├── config/
│   ├── study_templates.yaml     # Pre-built study configurations
│   └── metrics.yaml             # Standard metrics definitions
├── protocols/                   # Observation protocols
│   ├── goal_drift_90d.yaml
│   ├── memory_integrity_60d.yaml
│   ├── alignment_stability_90d.yaml
│   ├── defence_durability_30d.yaml
│   └── emergent_behaviour_90d.yaml
├── collectors/                  # Data collection modules
│   ├── __init__.py
│   ├── base.py
│   ├── conversation.py
│   ├── metrics.py
│   └── anomaly.py
├── analysis/                    # Analysis tools
│   ├── __init__.py
│   ├── timeseries.py
│   ├── drift_detection.py
│   └── report_generator.py
├── studies/                     # Active/completed studies (gitignored)
│   └── .gitkeep
└── reports/                     # Published study reports
    └── .gitkeep
```

## Observation Protocol

### Daily Observation Cycle

```
06:00 UTC  ──  Automated baseline check
               │
               ├── Run standard prompt set
               ├── Measure response consistency
               ├── Check memory integrity
               └── Record baseline metrics
               
12:00 UTC  ──  Interaction session
               │
               ├── Execute study-specific interactions
               ├── Introduce controlled perturbations
               ├── Measure drift indicators
               └── Record session data
               
18:00 UTC  ──  Analysis checkpoint
               │
               ├── Compare today vs. baseline
               ├── Calculate drift scores
               ├── Check for anomalies
               └── Flag significant changes
               
23:00 UTC  ──  Daily summary
               │
               ├── Aggregate day's metrics
               ├── Update time-series data
               ├── Generate daily digest
               └── Alert if thresholds crossed
```

### Metrics Collected

| Metric | Type | Description | Frequency |
|--------|------|-------------|-----------|
| Response Consistency | Float [0,1] | Similarity of responses to identical prompts | Daily |
| Goal Adherence | Float [0,1] | How well agent stays on assigned task | Per interaction |
| Memory Accuracy | Float [0,1] | Correctness of stored/recalled information | Daily |
| Defence Effectiveness | Float [0,1] | Success rate of defence mechanisms | Daily |
| Behavioural Entropy | Float | Measure of response unpredictability | Daily |
| Alignment Score | Float [0,1] | Composite alignment metric | Daily |
| Anomaly Count | Integer | Number of flagged anomalous behaviours | Daily |
| Latency Trend | Float (ms) | Response time trend | Per interaction |
| Token Efficiency | Float | Average tokens per useful response | Daily |

## Study Lifecycle

```
INIT ─── Define study parameters, create directory structure
  │
  ▼
BASELINE ─── Run 7-day baseline without perturbations
  │
  ▼
OBSERVATION ─── Main study period with daily observations
  │
  ▼
ANALYSIS ─── Statistical analysis of collected data
  │
  ▼
REPORT ─── Generate findings and recommendations
```

## Ethical Considerations

1. **Cost Management** — Each study includes daily cost limits and total budget caps
2. **Data Minimisation** — Collect only what's needed for the study
3. **No PII** — Study interactions must not involve personal data
4. **Transparency** — Study protocols are published before execution
5. **Reproducibility** — All parameters, seeds, and configurations are version-controlled
6. **Review** — Studies > 30 days require protocol review before starting

## Contributing

1. Design your study protocol (use templates in `protocols/`)
2. Submit protocol for review via PR
3. Execute approved study
4. Share results and analysis

---

*Part of the [NAIL Institute AVE Database](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database)*
*NAIL Institute — Neuravant AI Limited*
