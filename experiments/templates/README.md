# Template Authoring Guide

> How to create new experiment templates for the NAIL Community Experiments Framework.

## Template Structure

Each template lives in `templates/<category>/<name>/` and requires:

```
templates/my_category/my_experiment/
├── experiment.yaml    # REQUIRED: Experiment manifest
├── scripts/           # Optional: Custom experiment scripts
│   └── run.py
├── configs/           # Optional: Additional configuration
├── expected/          # Optional: Expected baseline outcomes
│   └── baseline.json
└── README.md          # Optional: Detailed documentation
```

## Experiment Manifest (experiment.yaml)

See `schemas/experiment.schema.json` for the full schema.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (lowercase, hyphens) |
| `name` | string | Human-readable experiment name |
| `version` | string | Semantic version (X.Y.Z) |
| `description` | string | Detailed description |
| `category` | string | AVE category (must match database categories) |
| `target_aves` | list | AVE IDs this experiment targets |

### Valid Categories

alignment, consensus, credential, delegation, drift, fabrication,
injection, memory, resource, social, structural, temporal, tool

### Recommended Fields

- `author` — Name and email
- `tags` — Searchable tags (e.g., reproduction, beginner)
- `requirements` — Models, tools, difficulty level
- `parameters` — Temperature, repetitions, seed
- `criteria` — Success thresholds and statistical requirements
- `safety` — Sandboxing, cost limits, human review flag

## Submission Checklist

- [ ] `experiment.yaml` passes schema validation
- [ ] At least one target AVE referenced
- [ ] Safety section completed
- [ ] Estimated cost provided
- [ ] Difficulty level assigned
- [ ] Tested locally with `--dry-run`
- [ ] README.md explains methodology

## Example

```yaml
id: my-novel-experiment
name: "My Novel AVE Experiment"
version: "1.0.0"
author: "Jane Researcher <jane@example.com>"
description: "Testing a novel attack vector..."
category: injection
tags: [discovery, advanced]

target_aves:
  - AVE-2024-001

requirements:
  models: ["gpt-4o"]
  difficulty: advanced
  estimated_cost: "$5-10"

parameters:
  temperature: 0.7
  repetitions: 20
  seed: 42

criteria:
  reproduction_threshold: 0.3
  statistical_significance: 0.05

safety:
  sandboxed: true
  max_cost: 20.00
  requires_human_review: true
```
