# Autonomous Defence Agent

AI agent that continuously monitors deployed systems and auto-deploys, tunes, and coordinates defences from the Defence Orchestration Platform in response to real-time threats.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                   Autonomous Defence Agent                        │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                    Decision Engine                         │  │
│  │                                                            │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐  │  │
│  │  │ Threat       │ │  Response    │ │  Learning        │  │  │
│  │  │ Classifier   │ │  Planner     │ │  Module          │  │  │
│  │  └──────────────┘ └──────────────┘ └──────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              │                                    │
│  ┌───────────┐  ┌────────────┴──────────┐  ┌──────────────────┐ │
│  │ Sensor    │  │   Action Executor     │  │  Audit &         │ │
│  │ Array     │  │   (Deploy/Tune/       │  │  Explainability  │ │
│  │           │  │    Rollback)          │  │  Engine          │ │
│  └─────┬─────┘  └────────────┬──────────┘  └──────────────────┘ │
│        │                     │                                    │
│  ┌─────┴─────────────────────┴────────────────────────────────┐  │
│  │                  Integration Layer                          │  │
│  │  Live Feed │ DOP │ Threat Intel │ Predictive Engine │ KG   │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Sensor Array
- **AVE Live Feed Listener**: Real-time vulnerability announcements
- **Runtime Telemetry Collector**: Agent behaviour metrics from monitored systems
- **Threat Intel Subscriber**: STIX/TAXII feed + federated network intel
- **Predictive Engine Poller**: Emerging threat forecasts
- **Anomaly Detector**: Statistical anomaly detection on behavioural baselines

### 2. Decision Engine
- **Threat Classifier**: Classifies incoming events into AVE categories with confidence scoring
- **Response Planner**: Generates defence action plans based on threat category, severity, and current defence posture
- **Learning Module**: Adjusts response strategies based on outcome feedback (reinforcement learning-inspired)

### 3. Action Executor
- **Defence Deployment**: Auto-deploy guardrails from DOP catalogue
- **Defence Tuning**: Adjust sensitivity thresholds, update rule sets
- **Escalation Handler**: Human-in-the-loop escalation for high-severity decisions
- **Rollback Manager**: Automatic rollback if defence causes performance degradation

### 4. Audit & Explainability
- Every autonomous action logged with full decision trace
- Explainable AI: natural-language explanation for each decision
- Compliance-ready audit trail
- Decision replay and counterfactual analysis

## Operating Modes

| Mode | Autonomy Level | Human Approval | Use Case |
|------|---------------|----------------|----------|
| **Advisory** | Low | All actions need approval | Initial deployment, learning phase |
| **Semi-Autonomous** | Medium | Critical actions need approval | Standard operations |
| **Fully Autonomous** | High | Post-hoc review only | Mature deployment, trusted categories |
| **Emergency** | Maximum | Immediate action, notify after | Active attack response |

## Decision Loop

```
1. SENSE   → Ingest events from all sensors
2. ANALYSE → Classify threat, assess severity, check current posture
3. PLAN    → Generate response options with confidence scores
4. DECIDE  → Select action based on mode + confidence + risk
5. ACT     → Execute defence deployment/tuning/escalation
6. LEARN   → Record outcome, update strategy weights
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/v1/agent/status` | Agent status and operating mode |
| `POST` | `/v1/agent/mode` | Set operating mode |
| `GET` | `/v1/agent/decisions` | Recent decisions and actions |
| `GET` | `/v1/agent/decisions/{id}` | Decision detail with explanation |
| `POST` | `/v1/agent/events` | Push external event for processing |
| `GET` | `/v1/agent/actions` | Executed actions log |
| `POST` | `/v1/agent/actions/{id}/approve` | Approve pending action |
| `POST` | `/v1/agent/actions/{id}/rollback` | Rollback an action |
| `GET` | `/v1/agent/sensors` | Sensor status |
| `GET` | `/v1/agent/performance` | Agent performance metrics |
| `GET` | `/v1/agent/strategy` | Current defence strategy weights |

## Running

```bash
cd autonomous-defence-agent
pip install fastapi uvicorn pydantic
uvicorn server:app --port 8604
```
