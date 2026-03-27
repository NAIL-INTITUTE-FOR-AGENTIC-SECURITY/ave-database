# Universal Agent Protocol Bridge

> Phase 20 · Service 2 of 5 · Port **9401**

Cross-framework agent communication bridge supporting MCP, A2A, LangChain, AutoGen, CrewAI, and custom protocols with message translation, protocol negotiation, capability discovery, and session management.

## Core Capabilities

### 1. Protocol Registry

- **6 supported protocols**: MCP (Model Context Protocol), A2A (Agent-to-Agent), LangChain, AutoGen, CrewAI, custom
- Per-protocol schema: message format, capability namespace, authentication method, version
- Protocol status: active, beta, deprecated
- Dynamic protocol plugin registration

### 2. Message Translation Engine

- Canonical internal message format (NAIL Unified Agent Message — NUAM)
- Bidirectional translation: source protocol → NUAM → target protocol
- Field mapping rules per protocol pair with fallback defaults
- Lossy translation warnings when target protocol lacks source fields
- Message validation against protocol-specific JSON schemas

### 3. Protocol Negotiation

- Capability advertisement: each endpoint declares supported protocols + versions
- Automatic best-match protocol selection based on mutual capabilities
- Version negotiation with backward compatibility preferences
- Fallback chain: prefer native → negotiate → translate → reject

### 4. Endpoint Registry & Discovery

- Register agent endpoints with protocol, URL, capabilities, and trust level
- Service discovery: find agents by capability, protocol, or tag
- Health monitoring with heartbeat polling
- Capability intersection queries: "find agents that support both MCP and A2A"

### 5. Session Management

- Stateful conversation sessions across protocol boundaries
- Session context preservation during protocol switches
- Timeout and cleanup for abandoned sessions
- Session replay for debugging cross-protocol interactions

### 6. Metrics & Observability

- Per-protocol message volume and error rates
- Translation latency percentiles
- Protocol adoption trends
- Failed negotiation analysis

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/protocols` | List supported protocols |
| GET | `/v1/protocols/{protocol_id}` | Protocol schema details |
| POST | `/v1/translate` | Translate a message between protocols |
| POST | `/v1/negotiate` | Negotiate best protocol for two endpoints |
| POST | `/v1/endpoints` | Register an agent endpoint |
| GET | `/v1/endpoints` | List/search endpoints |
| GET | `/v1/endpoints/{endpoint_id}` | Get endpoint details |
| DELETE | `/v1/endpoints/{endpoint_id}` | Deregister endpoint |
| POST | `/v1/sessions` | Create a cross-protocol session |
| GET | `/v1/sessions/{session_id}` | Get session state |
| POST | `/v1/sessions/{session_id}/send` | Send message through session |
| DELETE | `/v1/sessions/{session_id}` | Close session |
| GET | `/v1/analytics` | Bridge-wide analytics |
| GET | `/health` | Health check |

## Design Decisions

- **Canonical intermediate format** — All translations go through NUAM to avoid O(n²) direct mappings
- **Lossy translation is acceptable** — Not all protocols have equivalent fields; warnings are logged, not errors
- **Sessions are optional** — Stateless one-shot translation is the default; sessions add context for multi-turn conversations
