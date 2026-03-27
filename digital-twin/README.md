# Digital Twin Simulation Engine

> Phase 20 · Service 4 of 5 · Port **9403**

Full-fidelity digital twin of production agent ecosystems for attack simulation, defence validation, what-if scenario analysis, chaos injection, and continuous drift detection between twin and production.

## Core Capabilities

### 1. Twin Registry

- Create digital twins of production environments with topology, agent inventory, and configuration
- 4 twin states: provisioning, synced, drifted, archived
- Snapshot-based versioning with point-in-time restore
- Multi-layer modelling: agents, networks, policies, data flows, trust relationships

### 2. Agent & Topology Modelling

- Per-agent profiles: role, capabilities, trust score, connected services, policy bindings
- Network topology as directed graph: agents ↔ services ↔ data stores
- Policy overlay: which policies apply to which agents/connections
- Data flow mapping: what data moves between which components

### 3. Attack Simulation

- 5 attack types: injection (prompt/tool), lateral movement, privilege escalation, data exfiltration, coordinated multi-agent
- Attack scenario definition: entry point, kill chain stages, attacker capabilities
- Step-by-step simulation with probabilistic outcomes based on defence coverage
- Kill chain progression tracking with branch points
- Blast radius computation: which agents/data/services are impacted

### 4. Defence Validation

- Test defence configurations against catalogued attack scenarios
- Coverage matrix: which defences block which attack stages
- Gap identification: attack paths that bypass all active defences
- Defence efficacy scoring with confidence intervals

### 5. What-If Scenario Engine

- Clone twin state, apply hypothetical changes, re-run simulations
- Compare scenarios side-by-side: before vs after adding a defence, changing a policy, etc.
- Sensitivity analysis: which single change most improves/degrades security posture
- Cost-benefit modelling: defence cost vs risk reduction

### 6. Drift Detection

- Continuous comparison between twin model and production telemetry
- 4 drift types: topology (new/removed agents), configuration (changed settings), policy (rule changes), behaviour (anomalous patterns)
- Drift severity scoring and auto-resync triggers
- Drift history for trend analysis

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/twins` | Create a digital twin |
| GET | `/v1/twins` | List twins |
| GET | `/v1/twins/{twin_id}` | Get twin with full topology |
| DELETE | `/v1/twins/{twin_id}` | Archive twin |
| POST | `/v1/twins/{twin_id}/agents` | Add agent to twin |
| POST | `/v1/twins/{twin_id}/connections` | Add connection |
| POST | `/v1/simulations` | Run attack simulation |
| GET | `/v1/simulations/{sim_id}` | Get simulation results |
| POST | `/v1/defence-validation` | Validate defences against attacks |
| POST | `/v1/scenarios/compare` | Compare what-if scenarios |
| GET | `/v1/drift/{twin_id}` | Check drift status |
| POST | `/v1/drift/{twin_id}/sync` | Re-sync twin |
| GET | `/v1/analytics` | Engine-wide analytics |
| GET | `/health` | Health check |

## Design Decisions

- **Probabilistic simulation** — Attack outcomes are probabilistic based on defence coverage and attacker capability, not deterministic
- **Twin is a model, not a replica** — The twin captures topology and policy, not live data; it's a security-focused abstraction
- **Drift is expected** — Production evolves; the twin's value comes from detecting and quantifying that drift
