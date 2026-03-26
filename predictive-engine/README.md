# Predictive Vulnerability Engine — AVE Threat Forecasting

Machine learning system trained on AVE history, CVE trends, research
publications, and framework release patterns to predict emerging agentic
AI vulnerability categories before they manifest in the wild.

## Overview

The Predictive Vulnerability Engine (PVE) analyses signals across multiple
data sources to forecast:

- **New vulnerability categories** likely to emerge in the next 90 days
- **Severity trend shifts** for existing categories
- **Framework-specific risk** based on release cadence and architecture changes
- **Attack technique evolution** predicted from research paper trends
- **Defence gap windows** where protections lag behind emerging threats

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                   Predictive Vulnerability Engine                      │
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                     Data Ingestion Layer                          │ │
│  │                                                                   │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────┐│ │
│  │  │ AVE Card │ │ CVE/NVD  │ │ ArXiv    │ │ GitHub   │ │ MITRE ││ │
│  │  │ History  │ │ Feeds    │ │ Papers   │ │ Advisories│ │ Updates││ │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬───┘│ │
│  └───────┼─────────────┼───────────┼─────────────┼───────────┼────┘  │
│          │             │           │             │           │        │
│  ┌───────▼─────────────▼───────────▼─────────────▼───────────▼────┐  │
│  │                   Feature Engineering Pipeline                   │ │
│  │                                                                   │ │
│  │  • Temporal features (trend, seasonality, momentum)              │ │
│  │  • Text embeddings (paper abstracts, CVE descriptions)           │ │
│  │  • Graph features (knowledge graph topology metrics)             │ │
│  │  • Release features (framework version cadence, delta size)      │ │
│  │  • Community signals (GitHub issues, discussions, mentions)      │ │
│  └──────────────────────────┬────────────────────────────────────┘   │
│                              │                                        │
│  ┌──────────────────────────▼────────────────────────────────────┐   │
│  │                      Model Ensemble                             │  │
│  │                                                                  │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │  │
│  │  │ Time Series  │  │ NLP Trend    │  │ Graph Neural         │ │  │
│  │  │ Forecaster   │  │ Classifier   │  │ Network              │ │  │
│  │  │ (Prophet +   │  │ (BERT-based  │  │ (GNN on knowledge    │ │  │
│  │  │  ARIMA)      │  │  topic model)│  │  graph topology)     │ │  │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────────────┘ │  │
│  │         │                 │                  │                  │  │
│  │  ┌──────▼─────────────────▼──────────────────▼───────────────┐ │  │
│  │  │              Ensemble Aggregator                           │ │  │
│  │  │  • Weighted voting    • Confidence calibration             │ │  │
│  │  │  • Consensus scoring  • Uncertainty quantification         │ │  │
│  │  └──────────────────────┬────────────────────────────────────┘ │  │
│  └──────────────────────────┼────────────────────────────────────┘   │
│                              │                                        │
│  ┌──────────────────────────▼────────────────────────────────────┐   │
│  │                    Prediction Outputs                           │  │
│  │                                                                  │  │
│  │  • 90-day category emergence forecast                           │  │
│  │  • Severity trend projections per category                      │  │
│  │  • Framework risk scores (next 30/60/90 days)                   │  │
│  │  • Attack technique evolution timeline                          │  │
│  │  • Defence gap alerts and priority recommendations              │  │
│  └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

## Models

### 1. Time Series Forecaster

Predicts vulnerability volume and severity trends per category.

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Prophet** | Facebook Prophet | Trend + seasonality decomposition |
| **ARIMA** | statsmodels | Short-term autoregressive forecast |
| **Ensemble** | Weighted average | Combined prediction with CI |

**Features:**
- Monthly vulnerability count per category
- Severity distribution shifts
- Discovery-to-publication latency
- Defence response time

### 2. NLP Trend Classifier

Analyses research paper abstracts and CVE descriptions to detect
emerging threat themes before they crystallise into AVE categories.

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Embeddings** | Sentence-BERT | Semantic text representation |
| **Topic Model** | BERTopic | Dynamic topic clustering |
| **Classifier** | Fine-tuned DistilBERT | AVE category prediction |

**Features:**
- Paper abstract embeddings (rolling 90-day window)
- Topic drift velocity
- Cross-citation network density
- Keyword emergence frequency

### 3. Graph Neural Network

Leverages knowledge graph topology to predict new node emergence
and relationship formation.

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **GNN** | PyTorch Geometric | Link prediction on KG |
| **Node2Vec** | node2vec | Node embedding generation |
| **Temporal GNN** | TGN | Time-aware graph learning |

**Features:**
- Node degree centrality trends
- Subgraph density per category
- Cross-category relationship growth
- Defence-vulnerability coverage ratio

## Prediction Types

### Category Emergence Forecast

```json
{
  "prediction_id": "pred-20260301-001",
  "type": "category_emergence",
  "horizon_days": 90,
  "predictions": [
    {
      "predicted_category": "agentic_supply_chain_v2",
      "description": "Second-generation supply chain attacks targeting agent plugin marketplaces and tool registries",
      "confidence": 0.78,
      "estimated_emergence": "2026-05-15",
      "supporting_signals": [
        {"source": "arxiv", "signal": "12 papers on agent plugin security in Q1 2026"},
        {"source": "github", "signal": "3 advisories for LangChain tool registries"},
        {"source": "ave_trend", "signal": "supply_chain category +40% QoQ"}
      ],
      "recommended_actions": [
        "Begin developing detection heuristics for plugin validation bypass",
        "Extend AVE taxonomy with sub-categories for marketplace attacks",
        "Alert Defence Orchestration Platform to pre-deploy guardrails"
      ]
    }
  ]
}
```

### Severity Trend Projection

```json
{
  "prediction_id": "pred-20260301-002",
  "type": "severity_trend",
  "category": "prompt_injection",
  "current_distribution": {"critical": 0.15, "high": 0.30, "medium": 0.40, "low": 0.15},
  "projected_30d": {"critical": 0.20, "high": 0.35, "medium": 0.35, "low": 0.10},
  "projected_90d": {"critical": 0.25, "high": 0.35, "medium": 0.30, "low": 0.10},
  "trend": "escalating",
  "confidence": 0.72,
  "driver": "Novel jailbreak techniques bypassing instruction hierarchy"
}
```

### Framework Risk Score

```json
{
  "prediction_id": "pred-20260301-003",
  "type": "framework_risk",
  "framework": "LangChain",
  "current_risk_score": 6.8,
  "projected_30d_risk": 7.2,
  "projected_90d_risk": 7.8,
  "risk_factors": [
    {"factor": "Rapid release cadence (2 minor versions/month)", "weight": 0.3},
    {"factor": "Growing attack surface (12 new tools added)", "weight": 0.25},
    {"factor": "Community-contributed tools with limited review", "weight": 0.25},
    {"factor": "3 unpatched high-severity AVE cards", "weight": 0.2}
  ],
  "recommended_actions": [
    "Prioritise tool_abuse guardrails for LangChain deployments",
    "Review community tool onboarding process",
    "Deploy continuous monitoring for new tool usage patterns"
  ]
}
```

## API

### Predictions

```
GET  /v1/predictions/latest                      Latest prediction batch
GET  /v1/predictions/categories                   Category emergence forecasts
GET  /v1/predictions/severity/{category}          Severity trend for a category
GET  /v1/predictions/framework-risk/{name}        Framework risk projection
GET  /v1/predictions/attack-evolution              Attack technique timeline
GET  /v1/predictions/defence-gaps                  Defence gap analysis
```

### Model Management

```
GET  /v1/models/status                            Model health and last training
POST /v1/models/retrain                            Trigger model retraining
GET  /v1/models/performance                        Accuracy metrics and backtests
GET  /v1/models/features                           Feature importance rankings
```

### Data Ingestion

```
POST /v1/ingest/signals                            Push external signal data
GET  /v1/signals/sources                           List configured data sources
GET  /v1/signals/health                            Data pipeline health check
```

## Requirements

- Python 3.11+
- scikit-learn, XGBoost (ensemble models)
- Prophet (time series)
- sentence-transformers (NLP embeddings)
- BERTopic (topic modelling)
- PyTorch + PyTorch Geometric (GNN)
- FastAPI (API server)
- Redis (feature store caching)
- PostgreSQL (prediction store)

## Contact

- **Email**: predictions@nailinstitute.org
- **Slack**: `#predictive-engine`
