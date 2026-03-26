# 🧠 Cognitive Threat Modelling

> AI system that models attacker intent, capability, and opportunity to predict
> not just what vulnerabilities will emerge but which will be exploited.

**Phase 14 · Item 4 · Port 8803**

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                      COGNITIVE THREAT MODELLING                           │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ Attacker │ Capab-   │ Opport-  │ Intent   │ Exploit  │ Priority            │
│ Profile  │ ility    │ unity    │ Analyser │ Predict- │ Ranker              │
│ Engine   │ Assessor │ Mapper   │          │ or       │                     │
├──────────┴──────────┴──────────┴──────────┴──────────┴─────────────────────┤
│                     THREAT INTELLIGENCE FUSION                            │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ AVE Feed │ MITRE    │ Exploit  │ Dark Web │ Vuln     │ Attack              │
│          │ ATT&CK   │ DB       │ Signals  │ Market   │ Surface             │
└──────────┴──────────┴──────────┴──────────┴──────────┴─────────────────────┘
```

## Concepts

| Concept | Description |
|---------|-------------|
| **Attacker Profile** | Modelled threat actor with motivation, skill, resources, and targets |
| **ICO Score** | Intent × Capability × Opportunity composite exploitation likelihood |
| **Attack Surface** | Organisation's exposed agentic AI components mapped to AVE categories |
| **Exploit Prediction** | Ranked list of which vulnerabilities will likely be exploited next |
| **Kill Chain Mapping** | Maps predicted exploits to agentic AI kill chain stages |

## Key Features

1. **Attacker Profiling** — Model threat actor archetypes with motivation/skill/resources
2. **ICO Scoring** — Intent × Capability × Opportunity composite exploitation probability
3. **Attack Surface Mapping** — Define organisational exposure per AVE category
4. **Exploit Prediction** — Rank vulnerabilities by exploitation likelihood
5. **Kill Chain Analysis** — Map predictions to agentic AI attack stages
6. **Scenario Generation** — Auto-generate "most likely" and "most dangerous" attack scenarios
7. **Temporal Prediction** — Time-horizon forecasts (7d / 30d / 90d)
8. **Defence Prioritisation** — Recommend which defences to deploy based on predicted attacks

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/attackers` | Create attacker profile |
| `GET` | `/v1/attackers` | List attacker profiles |
| `GET` | `/v1/attackers/{id}` | Profile details |
| `POST` | `/v1/surfaces` | Define attack surface |
| `GET` | `/v1/surfaces` | List attack surfaces |
| `GET` | `/v1/surfaces/{id}` | Surface details |
| `POST` | `/v1/predict` | Generate exploit predictions |
| `GET` | `/v1/predictions` | List predictions |
| `GET` | `/v1/predictions/{id}` | Prediction details |
| `POST` | `/v1/scenarios/generate` | Auto-generate attack scenarios |
| `GET` | `/v1/scenarios` | List scenarios |
| `GET` | `/v1/kill-chain/{prediction_id}` | Kill chain mapping |
| `GET` | `/v1/prioritise` | Defence prioritisation recommendations |
| `GET` | `/v1/analytics` | Cognitive modelling analytics |

## Running

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 8803 --reload
```

Docs at http://localhost:8803/docs
