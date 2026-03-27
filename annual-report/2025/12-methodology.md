# Chapter 12: Methodology

> How this report was compiled, analysed, and validated.

---

## Data Collection

### Primary Data Source: NAIL AVE Database
- **Scope**: All AVE cards with status `published`, `proven`, or `proven_mitigated`
  as of December 31, 2025 (data freeze date)
- **Format**: JSON, validated against AVE Schema v1.0.0 and v2.0.0
- **Access**: Public API at `api.nailinstitute.org`

### Secondary Data Sources

| Source | Type | Coverage |
|--------|------|----------|
| Annual Practitioner Survey | Quantitative + qualitative | 87 respondents, 14 countries |
| Academic Literature Review | Systematic review | Papers published Jan-Dec 2025 |
| Industry Incident Reports | Anonymised case studies | 12 organisations contributed |
| Expert Panel | Semi-structured interviews | 8 interviews conducted |
| Framework Changelogs | Security-relevant changes | LangChain, AutoGen, CrewAI, etc. |

### Practitioner Survey

- **Distribution**: December 1-31, 2025
- **Channels**: NAIL community, social media, partner organisations
- **Response rate**: 62%
- **Demographics**: Security engineers (38%), AI/ML engineers (29%),
  researchers (18%), management (10%), other (5%)
- **Geographic spread**: NA (41%), EU (32%), APAC (19%), other (8%)
- **Confidence level**: 95% CI, margin of error ±7%

## Analysis Methods

### Quantitative Analysis

1. **Descriptive Statistics**: Frequency counts, distributions, central tendency
   for all AVE card fields (category, severity, AVSS scores)
2. **Trend Analysis**: Time-series analysis of card publication rates, severity
   trends, and category evolution
3. **Correlation Analysis**: Relationships between categories, frameworks, and
   severity levels
4. **Defence Effectiveness**: Comparative analysis of mitigation strategies
   based on evidence fields and survey data

### Qualitative Analysis

1. **Thematic Coding**: Expert panel interview transcripts coded using
   inductive thematic analysis
2. **Case Study Analysis**: In-depth analysis of 6 selected incidents
3. **Regulatory Mapping**: Systematic mapping of AVE categories to
   EU AI Act, NIST AI RMF, and ISO 42001 requirements

### Tools and Software

| Tool | Purpose | Version |
|------|---------|---------|
| Python | Data processing and analysis | 3.12 |
| pandas | Data manipulation | 2.2+ |
| scipy | Statistical analysis | 1.13+ |
| matplotlib | Visualisation | 3.9+ |
| plotly | Interactive charts | 5.22+ |
| jsonschema | AVE card validation | 4.22+ |

### Analysis Pipeline

```
AVE Database (JSON) ──► Validation ──► Cleaning ──► Analysis ──► Visualisation
                                                        │
Survey Data (CSV) ──────► Cleaning ──────────────────►──┤
                                                        │
Literature (BibTeX) ──── Systematic Review ──────────►──┤
                                                        │
Expert Interviews ────── Thematic Coding ────────────►──┘
                                                        │
                                                  ┌─────▼─────┐
                                                  │  Report    │
                                                  │ Generation │
                                                  └─────┬─────┘
                                                        │
                                              ┌─────────┼─────────┐
                                              │         │         │
                                          ┌───▼──┐ ┌───▼───┐ ┌──▼───┐
                                          │  MD  │ │  PDF  │ │ Data │
                                          │ Files│ │Report │ │ Pkg  │
                                          └──────┘ └───────┘ └──────┘
```

## Reproducibility

All analysis is reproducible:
- **Code**: `annual-report/2025/scripts/` (Python analysis scripts)
- **Data**: `annual-report/2025/data/` (anonymised input data)
- **Environment**: `annual-report/2025/requirements.txt`

To reproduce:
```bash
cd annual-report/2025/
pip install -r requirements.txt
python scripts/generate_report_data.py
```

## Quality Assurance

### Peer Review
- Each chapter reviewed by 2+ independent reviewers
- Reviewers selected for domain expertise per chapter
- Review period: February 1-28
- All review comments addressed and documented

### Statistical Review
- Quantitative analyses reviewed by a statistician
- Survey methodology reviewed by research methods expert
- All figures independently verified from source data

### Responsible Disclosure
- All incident case studies anonymised
- No unpublished vulnerabilities disclosed
- All AVE cards referenced are publicly available

## Limitations

1. **Reporting Bias**: The AVE database reflects submitted and reviewed cards,
   not all agentic AI vulnerabilities in existence. Proprietary systems are
   underrepresented.
2. **Framework Bias**: Open-source frameworks are more heavily represented due
   to accessibility for security research.
3. **Temporal Bias**: The AVE database launched in 2025; historical data is limited.
4. **Survey Bias**: Self-selected sample of NAIL community members and partners.
5. **Severity Subjectivity**: AVSS scoring involves expert judgement; inter-rater
   reliability is 0.81 (Cohen's kappa).

## Citation

```bibtex
@report{nail_ave_annual_2025,
  title   = {State of Agentic AI Security: Annual AVE Report 2025},
  author  = {{NAIL Institute for Agentic Security}},
  year    = {2025},
  url     = {https://nailinstitute.org/annual-report/2025},
  note    = {Inaugural edition}
}
```

## Changelog

| Date | Change |
|------|--------|
| 2025-04-01 | Initial publication |

---

*Questions about methodology? Contact report@nailinstitute.org*
