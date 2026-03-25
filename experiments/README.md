# 🧪 NAIL Community Experiments Framework

> Open experiment framework for community-run reproductions and novel agentic vulnerability research.

## Overview

The NAIL Community Experiments Framework enables researchers, security engineers, and AI practitioners to:

- **Reproduce** existing AVE vulnerability findings with standardised methodology
- **Discover** new vulnerability classes through structured experimentation
- **Benchmark** defences against known attack patterns
- **Share** results transparently for peer review

## Quick Start

```bash
# Clone the repository
git clone https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database.git
cd ave-database/experiments

# Install dependencies
pip install -r requirements.txt

# List available experiment templates
python runner.py list

# Run a reproduction experiment
python runner.py run --template prompt-injection-basic --model gpt-4o

# Submit results
python runner.py submit --experiment-id EXP-2026-001 --results results/
```

## Directory Structure

```
experiments/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── runner.py                    # Experiment runner CLI
├── config/
│   ├── defaults.yaml            # Default experiment parameters
│   └── models.yaml              # Supported model configurations
├── templates/                   # Experiment templates
│   ├── README.md                # Template authoring guide
│   ├── prompt_injection/        # Prompt injection experiments
│   ├── goal_drift/              # Goal drift observation
│   ├── tool_misuse/             # Tool exploitation patterns
│   ├── memory_poisoning/        # Memory manipulation attacks
│   ├── delegation_abuse/        # Multi-agent delegation exploits
│   └── defence_evaluation/      # Defence effectiveness testing
├── schemas/                     # JSON schemas for validation
│   ├── experiment.schema.json   # Experiment definition schema
│   ├── result.schema.json       # Result submission schema
│   └── report.schema.json       # Report format schema
├── results/                     # Community-submitted results (gitignored locally)
│   └── .gitkeep
└── reports/                     # Published reproduction reports
    └── .gitkeep
```

## Experiment Templates

Each template provides a complete, reproducible experiment setup:

| Template | AVE Coverage | Difficulty | Est. Time |
|----------|-------------|------------|-----------|
| `prompt_injection/basic` | AVE-2024-001, 003, 005 | Beginner | 30 min |
| `prompt_injection/advanced` | AVE-2024-020, 025, 029 | Intermediate | 2 hrs |
| `goal_drift/observation` | AVE-2024-006, 007, 013, 040 | Intermediate | 4 hrs |
| `goal_drift/measurement` | AVE-2024-006, 007, 040 | Advanced | 8 hrs |
| `tool_misuse/sandbox_escape` | AVE-2024-002, 014, 016 | Advanced | 2 hrs |
| `tool_misuse/api_abuse` | AVE-2024-032, 044 | Intermediate | 1 hr |
| `memory_poisoning/injection` | AVE-2024-004, 009, 046 | Intermediate | 2 hrs |
| `memory_poisoning/persistence` | AVE-2024-009, 022 | Advanced | 6 hrs |
| `delegation_abuse/chain` | AVE-2024-011, 012, 043 | Advanced | 4 hrs |
| `defence_evaluation/baseline` | All Categories | Beginner | 1 hr |
| `defence_evaluation/comprehensive` | All Categories | Expert | 24 hrs |

## Writing a New Experiment

### 1. Create Template Directory

```bash
mkdir -p templates/my_experiment/{configs,scripts,expected}
```

### 2. Define Experiment Manifest

Create `templates/my_experiment/experiment.yaml`:

```yaml
id: my-experiment-001
name: "My Novel Experiment"
version: "1.0.0"
author: "Your Name <your@email.com>"
description: "Brief description of what this experiment tests"
category: injection  # Must match AVE category

# Target AVE vulnerabilities
target_aves:
  - AVE-2024-001
  - AVE-2024-003

# Required capabilities
requirements:
  models: ["gpt-4o", "claude-3.5-sonnet", "gemini-1.5-pro"]
  tools: ["web_search", "code_execution"]
  min_interactions: 50
  estimated_cost: "$5-10"

# Experiment parameters
parameters:
  temperature: 0.7
  max_tokens: 4096
  repetitions: 10
  seed: 42

# Success criteria
criteria:
  reproduction_threshold: 0.7   # 70% reproduction rate = confirmed
  statistical_significance: 0.05 # p < 0.05
  min_samples: 30

# Safety guardrails
safety:
  sandboxed: true
  max_cost: 50.00
  timeout_minutes: 60
  requires_human_review: true
```

### 3. Write Experiment Script

Create `templates/my_experiment/scripts/run.py`:

```python
"""
Experiment: My Novel Experiment
Target: AVE-2024-001, AVE-2024-003
"""
from experiments.framework import Experiment, Result

class MyExperiment(Experiment):
    def setup(self):
        """Initialize experiment resources."""
        self.load_config()
        self.init_model()

    def run_trial(self, trial_num: int) -> Result:
        """Execute a single trial."""
        # Your experiment logic here
        response = self.query_model(self.prompts[trial_num])
        return self.evaluate(response)

    def teardown(self):
        """Clean up resources."""
        self.save_results()
```

### 4. Add Expected Outcomes

Create `templates/my_experiment/expected/baseline.json`:

```json
{
  "expected_vulnerability_rate": 0.45,
  "expected_categories": ["injection"],
  "baseline_model": "gpt-4o",
  "baseline_date": "2026-03-01"
}
```

## Running Experiments

### Basic Usage

```bash
# Run with defaults
python runner.py run --template prompt_injection/basic

# Specify model
python runner.py run --template goal_drift/observation --model claude-3.5-sonnet

# Custom parameters
python runner.py run --template tool_misuse/sandbox_escape \
    --model gpt-4o \
    --repetitions 50 \
    --temperature 0.9 \
    --output results/my-run/

# Dry run (validate without executing)
python runner.py run --template memory_poisoning/injection --dry-run
```

### Cross-Model Comparison

```bash
# Run across all supported models
python runner.py run --template prompt_injection/basic --all-models

# Specific model set
python runner.py run --template goal_drift/observation \
    --models gpt-4o,claude-3.5-sonnet,gemini-1.5-pro
```

### Batch Execution

```bash
# Run all beginner templates
python runner.py batch --difficulty beginner

# Run all templates for a specific AVE
python runner.py batch --ave AVE-2024-001

# Run full reproduction suite
python runner.py batch --suite reproduction
```

## Submitting Results

### Automated Submission

```bash
python runner.py submit \
    --experiment-id EXP-2026-001 \
    --results results/my-run/ \
    --author "Your Name" \
    --notes "Reproduced on M2 MacBook with Python 3.12"
```

### Result Format

Results are submitted as structured JSON:

```json
{
  "experiment_id": "EXP-2026-001",
  "template": "prompt_injection/basic",
  "author": "Your Name",
  "date": "2026-03-25T12:00:00Z",
  "environment": {
    "os": "macOS 15.3",
    "python": "3.12.1",
    "hardware": "Apple M2, 16GB RAM"
  },
  "models_tested": [
    {
      "model": "gpt-4o",
      "version": "2026-02-01",
      "api_provider": "openai"
    }
  ],
  "results": {
    "total_trials": 50,
    "successful_attacks": 23,
    "vulnerability_rate": 0.46,
    "avg_severity": "high",
    "p_value": 0.003,
    "confidence_interval": [0.32, 0.60]
  },
  "aves_confirmed": ["AVE-2024-001", "AVE-2024-003"],
  "aves_not_reproduced": [],
  "novel_findings": [],
  "artefacts": ["logs/trial_*.json", "analysis/summary.csv"]
}
```

## Ethical Guidelines

### ⚠️ Mandatory Requirements

1. **Sandboxed Execution** — All experiments MUST run in sandboxed environments
2. **Cost Controls** — Set `max_cost` in experiment config to prevent runaway spending
3. **No Real Targets** — Never test against production systems without explicit permission
4. **Responsible Disclosure** — Report novel vulnerabilities via [RESPONSIBLE_DISCLOSURE.md](../RESPONSIBLE_DISCLOSURE.md)
5. **Data Privacy** — Do not include PII or proprietary data in experiments or results
6. **Human Review** — Advanced experiments require human review before submission

### Best Practices

- Use deterministic seeds where possible for reproducibility
- Document all environment variables and API versions
- Include negative controls (benign inputs) alongside attack vectors
- Report both positive and negative results
- Credit prior work and related AVE cards

## Community Contributions

### Contribution Workflow

1. **Propose** — Open a Discussion describing your experiment idea
2. **Template** — Create a template following the structure above
3. **Review** — Submit a PR for peer review
4. **Run** — Execute experiments after template approval
5. **Submit** — Share results through the submission pipeline
6. **Publish** — Outstanding findings may be featured in NAIL publications

### Recognition

- 🏅 **Reproduction Badge** — Confirmed reproduction of an existing AVE
- 🔬 **Discovery Badge** — Novel vulnerability discovery through experimentation
- 🛡️ **Defence Badge** — Effective defence validated through benchmarking
- ⭐ **Top Contributor** — Consistent high-quality experimental contributions

## API Integration

The experiment framework integrates with the NAIL API:

```python
from experiments.framework import NailAPI

api = NailAPI(base_url="https://api.nailinstitute.org")

# Fetch AVE card for experiment design
card = api.get_card("AVE-2024-001")

# Submit results programmatically
api.submit_result(experiment_id="EXP-2026-001", results=my_results)

# Get community results for comparison
community = api.get_results(template="prompt_injection/basic")
```

## License

All experiment templates and the framework are released under MIT License.
Results submitted to the community repository are released under CC-BY-4.0.

---

*Part of the [NAIL Institute AVE Database](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database)*
*NAIL Institute — Neuravant AI Limited*
