# 🪞 AVE Digital Twin

> Full simulation of an organisation's agentic AI stack for red/blue team
> exercises, policy testing, and compliance rehearsal in a sandboxed environment.

**Phase 14 · Item 3 · Port 8802**

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           AVE DIGITAL TWIN                                │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ Stack    │ Agent    │ Defence  │ Exercise │ Policy   │ Compliance          │
│ Builder  │ Emulator │ Simulator│ Runner   │ Tester   │ Rehearsal           │
│          │          │          │          │          │                     │
├──────────┴──────────┴──────────┴──────────┴──────────┴─────────────────────┤
│                      TWIN RUNTIME ENGINE                                  │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ Snapshot │ Diff     │ Replay   │ Metric   │ Report   │ Export              │
│ Manager  │ Analyser │ Engine   │ Collector│ Generator│ Pipeline            │
└──────────┴──────────┴──────────┴──────────┴──────────┴─────────────────────┘
```

## Key Features

1. **Stack Definition** — Declare agents, tools, models, defences, and data flows as a twin spec
2. **Agent Emulation** — Simulated agent behaviours matching real framework execution patterns
3. **Defence Simulation** — Test guardrail effectiveness within the twin environment
4. **Red/Blue Exercises** — Run automated attack campaigns and measure defensive response
5. **Policy Testing** — Apply governance policies to the twin and observe outcomes
6. **Compliance Rehearsal** — Simulate regulatory audits against the twin stack
7. **Snapshot & Diff** — Capture twin state, compare before/after policy or defence changes
8. **Exercise Reports** — Detailed reports with scores, gaps, and remediation guidance

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/twins` | Create a digital twin |
| `GET` | `/v1/twins` | List twins |
| `GET` | `/v1/twins/{id}` | Twin details |
| `DELETE` | `/v1/twins/{id}` | Destroy a twin |
| `POST` | `/v1/twins/{id}/snapshot` | Capture current state |
| `GET` | `/v1/twins/{id}/snapshots` | List snapshots |
| `POST` | `/v1/twins/{id}/diff` | Diff two snapshots |
| `POST` | `/v1/exercises` | Launch a red/blue exercise |
| `GET` | `/v1/exercises` | List exercises |
| `GET` | `/v1/exercises/{id}` | Exercise details & report |
| `POST` | `/v1/twins/{id}/policy-test` | Test policy against twin |
| `POST` | `/v1/twins/{id}/compliance-audit` | Run compliance rehearsal |
| `GET` | `/v1/analytics` | Twin analytics |

## Running

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 8802 --reload
```

Docs at http://localhost:8802/docs
