# 🧬 Self-Evolving Defence Catalogue

> Defence library that autonomously generates, tests, and publishes new
> guardrails in response to novel vulnerability classes discovered by the ecosystem.

**Phase 14 · Item 1 · Port 8800**

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    SELF-EVOLVING DEFENCE CATALOGUE                        │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ Vuln     │ Defence  │ Code     │ Test     │ Publish  │ Version             │
│ Watcher  │ Generator│ Synth-   │ Harness  │ Pipeline │ Registry            │
│          │ (LLM)    │ esizer   │          │          │                     │
├──────────┴──────────┴──────────┴──────────┴──────────┴─────────────────────┤
│                       EVALUATION FEEDBACK LOOP                            │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ Coverage │ Efficacy │ Perf     │ False +  │ Compat-  │ Regression          │
│ Analyser │ Scorer   │ Bench    │ Tracker  │ ibility  │ Guard               │
└──────────┴──────────┴──────────┴──────────┴──────────┴─────────────────────┘
```

## Key Features

1. **Vulnerability Watch** — Monitors new AVE cards and threat signals for uncovered categories
2. **Autonomous Generation** — Synthesizes guardrail code from vulnerability specifications
3. **Automated Testing** — Runs generated defences against attack test suites
4. **Efficacy Scoring** — Measures detection rate, false-positive rate, latency impact
5. **Compatibility Check** — Validates against all supported frameworks (via ADL)
6. **Versioned Publishing** — Semantic versioning with changelog for each defence release
7. **Regression Guard** — Ensures new defences don't degrade existing coverage
8. **Community Review** — Optional human review gate before auto-publish

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/catalogue/generate` | Trigger defence generation for a vulnerability |
| `GET` | `/v1/catalogue/defences` | List all catalogue defences |
| `GET` | `/v1/catalogue/defences/{id}` | Defence details |
| `POST` | `/v1/catalogue/defences/{id}/test` | Run test suite against a defence |
| `POST` | `/v1/catalogue/defences/{id}/publish` | Publish a defence to the registry |
| `GET` | `/v1/catalogue/registry` | Published defence registry |
| `GET` | `/v1/catalogue/coverage` | AVE category coverage analysis |
| `POST` | `/v1/catalogue/evaluate` | Evaluate all defences for efficacy |
| `GET` | `/v1/catalogue/changelog` | Defence evolution changelog |
| `GET` | `/v1/catalogue/analytics` | Catalogue analytics |

## Running

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 8800 --reload
```

Docs at http://localhost:8800/docs
