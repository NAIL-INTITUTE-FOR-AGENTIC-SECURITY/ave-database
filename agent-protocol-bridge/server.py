"""
Universal Agent Protocol Bridge — Phase 20 Service 2 of 5
Port: 9401

Cross-framework agent communication with protocol registry,
NUAM canonical message format, bidirectional translation,
protocol negotiation, endpoint discovery, and session management.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ProtocolName(str, Enum):
    mcp = "mcp"
    a2a = "a2a"
    langchain = "langchain"
    autogen = "autogen"
    crewai = "crewai"
    custom = "custom"


class ProtocolStatus(str, Enum):
    active = "active"
    beta = "beta"
    deprecated = "deprecated"


class SessionState(str, Enum):
    open = "open"
    active = "active"
    closed = "closed"
    expired = "expired"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class ProtocolSchema(BaseModel):
    protocol_id: str
    name: ProtocolName
    version: str
    status: ProtocolStatus
    message_format: Dict[str, Any]
    capability_namespace: str
    auth_method: str
    description: str = ""


class NUAMMessage(BaseModel):
    """NAIL Unified Agent Message — canonical internal format."""
    message_id: str = ""
    source_protocol: str = ""
    target_protocol: str = ""
    sender: str = ""
    receiver: str = ""
    message_type: str = "request"  # request | response | notification | error
    method: str = ""
    params: Dict[str, Any] = Field(default_factory=dict)
    body: Any = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = ""


class TranslateRequest(BaseModel):
    source_protocol: ProtocolName
    target_protocol: ProtocolName
    message: Dict[str, Any]


class NegotiateRequest(BaseModel):
    endpoint_a: str
    endpoint_b: str
    preferences: List[ProtocolName] = Field(default_factory=list)


class EndpointCreate(BaseModel):
    name: str
    url: str
    protocols: List[ProtocolName]
    capabilities: List[str] = Field(default_factory=list)
    trust_level: float = Field(default=0.5, ge=0.0, le=1.0)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EndpointRecord(EndpointCreate):
    endpoint_id: str
    healthy: bool = True
    last_seen: str = ""
    created_at: str


class SessionCreate(BaseModel):
    source_endpoint: str
    target_endpoint: str
    source_protocol: ProtocolName
    target_protocol: ProtocolName


class SessionRecord(SessionCreate):
    session_id: str
    state: SessionState = SessionState.open
    messages: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str
    updated_at: str


class SessionSend(BaseModel):
    message: Dict[str, Any]
    direction: str = "forward"  # forward | reply


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

protocols: Dict[str, ProtocolSchema] = {}
endpoints: Dict[str, EndpointRecord] = {}
sessions: Dict[str, SessionRecord] = {}
translation_log: List[Dict[str, Any]] = []


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Bootstrap Protocols
# ---------------------------------------------------------------------------

_PROTOCOL_SEEDS = [
    ProtocolSchema(
        protocol_id="PROTO-MCP",
        name=ProtocolName.mcp,
        version="2025-03-26",
        status=ProtocolStatus.active,
        message_format={"type": "jsonrpc", "envelope": {"jsonrpc": "2.0", "method": "", "params": {}, "id": ""}},
        capability_namespace="mcp.tools.*",
        auth_method="bearer_token",
        description="Model Context Protocol — Anthropic standard for tool use",
    ),
    ProtocolSchema(
        protocol_id="PROTO-A2A",
        name=ProtocolName.a2a,
        version="1.0.0",
        status=ProtocolStatus.active,
        message_format={"type": "json", "envelope": {"task_id": "", "message": {"role": "", "parts": []}}},
        capability_namespace="a2a.skills.*",
        auth_method="api_key",
        description="Agent-to-Agent Protocol — Google standard for agent communication",
    ),
    ProtocolSchema(
        protocol_id="PROTO-LANGCHAIN",
        name=ProtocolName.langchain,
        version="0.2.0",
        status=ProtocolStatus.active,
        message_format={"type": "json", "envelope": {"input": "", "config": {}, "kwargs": {}}},
        capability_namespace="langchain.chains.*",
        auth_method="api_key",
        description="LangChain Runnable interface",
    ),
    ProtocolSchema(
        protocol_id="PROTO-AUTOGEN",
        name=ProtocolName.autogen,
        version="0.4.0",
        status=ProtocolStatus.active,
        message_format={"type": "json", "envelope": {"sender": "", "receiver": "", "message": "", "context": {}}},
        capability_namespace="autogen.agents.*",
        auth_method="none",
        description="Microsoft AutoGen agent messaging",
    ),
    ProtocolSchema(
        protocol_id="PROTO-CREWAI",
        name=ProtocolName.crewai,
        version="0.28.0",
        status=ProtocolStatus.active,
        message_format={"type": "json", "envelope": {"task": "", "agent": "", "context": "", "expected_output": ""}},
        capability_namespace="crewai.tasks.*",
        auth_method="none",
        description="CrewAI task delegation format",
    ),
    ProtocolSchema(
        protocol_id="PROTO-CUSTOM",
        name=ProtocolName.custom,
        version="1.0.0",
        status=ProtocolStatus.beta,
        message_format={"type": "json", "envelope": {"action": "", "payload": {}, "headers": {}}},
        capability_namespace="custom.*",
        auth_method="custom",
        description="User-defined custom protocol",
    ),
]

PROTOCOL_MAP: Dict[ProtocolName, str] = {}


def _bootstrap():
    if protocols:
        return
    for p in _PROTOCOL_SEEDS:
        protocols[p.protocol_id] = p
        PROTOCOL_MAP[p.name] = p.protocol_id


# ---------------------------------------------------------------------------
# Translation Helpers
# ---------------------------------------------------------------------------

def _to_nuam(source_proto: ProtocolName, msg: Dict[str, Any]) -> NUAMMessage:
    """Convert protocol-specific message to canonical NUAM."""
    nuam = NUAMMessage(
        message_id=f"NUAM-{uuid.uuid4().hex[:12]}",
        source_protocol=source_proto.value,
        timestamp=_now(),
    )
    if source_proto == ProtocolName.mcp:
        nuam.method = msg.get("method", "")
        nuam.params = msg.get("params", {})
        nuam.message_type = "request"
    elif source_proto == ProtocolName.a2a:
        task = msg.get("message", {})
        nuam.method = msg.get("task_id", "")
        nuam.body = task.get("parts", [])
        nuam.sender = task.get("role", "")
    elif source_proto == ProtocolName.langchain:
        nuam.body = msg.get("input", "")
        nuam.params = msg.get("config", {})
        nuam.metadata = msg.get("kwargs", {})
    elif source_proto == ProtocolName.autogen:
        nuam.sender = msg.get("sender", "")
        nuam.receiver = msg.get("receiver", "")
        nuam.body = msg.get("message", "")
        nuam.metadata = msg.get("context", {})
    elif source_proto == ProtocolName.crewai:
        nuam.method = msg.get("task", "")
        nuam.sender = msg.get("agent", "")
        nuam.body = msg.get("context", "")
        nuam.metadata = {"expected_output": msg.get("expected_output", "")}
    else:
        nuam.method = msg.get("action", "")
        nuam.body = msg.get("payload", {})
        nuam.metadata = msg.get("headers", {})
    return nuam


def _from_nuam(target_proto: ProtocolName, nuam: NUAMMessage) -> Dict[str, Any]:
    """Convert NUAM to target protocol format."""
    warnings: List[str] = []
    if target_proto == ProtocolName.mcp:
        out = {"jsonrpc": "2.0", "method": nuam.method, "params": nuam.params, "id": nuam.message_id}
    elif target_proto == ProtocolName.a2a:
        out = {"task_id": nuam.method, "message": {"role": nuam.sender or "assistant", "parts": nuam.body if isinstance(nuam.body, list) else [{"text": str(nuam.body)}]}}
    elif target_proto == ProtocolName.langchain:
        out = {"input": str(nuam.body) if nuam.body else nuam.method, "config": nuam.params, "kwargs": nuam.metadata}
    elif target_proto == ProtocolName.autogen:
        out = {"sender": nuam.sender, "receiver": nuam.receiver, "message": str(nuam.body) if nuam.body else nuam.method, "context": nuam.metadata}
    elif target_proto == ProtocolName.crewai:
        out = {"task": nuam.method, "agent": nuam.sender, "context": str(nuam.body) if nuam.body else "", "expected_output": nuam.metadata.get("expected_output", "")}
    else:
        out = {"action": nuam.method, "payload": nuam.body if isinstance(nuam.body, dict) else {"data": nuam.body}, "headers": nuam.metadata}
    if nuam.source_protocol == target_proto.value:
        warnings.append("Source and target protocols are the same; pass-through translation")
    return {"translated_message": out, "warnings": warnings}


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Universal Agent Protocol Bridge",
    description="Phase 20 — Cross-framework message translation, negotiation, and session management",
    version="20.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_bootstrap()


@app.get("/health")
def health():
    return {
        "service": "universal-agent-protocol-bridge",
        "status": "healthy",
        "phase": 20,
        "port": 9401,
        "stats": {
            "protocols": len(protocols),
            "endpoints": len(endpoints),
            "sessions": len(sessions),
        },
        "timestamp": _now(),
    }


# ── Protocols ──────────────────────────────────────────────────────────────

@app.get("/v1/protocols")
def list_protocols(status: Optional[ProtocolStatus] = None):
    results = list(protocols.values())
    if status:
        results = [p for p in results if p.status == status]
    return {"protocols": [p.dict() for p in results], "total": len(results)}


@app.get("/v1/protocols/{protocol_id}")
def get_protocol(protocol_id: str):
    if protocol_id not in protocols:
        raise HTTPException(404, "Protocol not found")
    return protocols[protocol_id].dict()


# ── Translation ────────────────────────────────────────────────────────────

@app.post("/v1/translate")
def translate(body: TranslateRequest):
    nuam = _to_nuam(body.source_protocol, body.message)
    nuam.target_protocol = body.target_protocol.value
    result = _from_nuam(body.target_protocol, nuam)
    entry = {
        "source": body.source_protocol.value,
        "target": body.target_protocol.value,
        "nuam_id": nuam.message_id,
        "warnings": result["warnings"],
        "timestamp": _now(),
    }
    translation_log.append(entry)
    if len(translation_log) > 50000:
        translation_log.pop(0)
    return {
        "nuam": nuam.dict(),
        "translated": result["translated_message"],
        "warnings": result["warnings"],
    }


# ── Negotiation ────────────────────────────────────────────────────────────

@app.post("/v1/negotiate")
def negotiate(body: NegotiateRequest):
    ep_a = endpoints.get(body.endpoint_a)
    ep_b = endpoints.get(body.endpoint_b)
    if not ep_a:
        raise HTTPException(404, f"Endpoint {body.endpoint_a} not found")
    if not ep_b:
        raise HTTPException(404, f"Endpoint {body.endpoint_b} not found")
    mutual = set(ep_a.protocols) & set(ep_b.protocols)
    if body.preferences:
        for pref in body.preferences:
            if pref in mutual:
                return {"negotiated_protocol": pref.value, "mutual_protocols": [p.value for p in mutual], "strategy": "preference_match"}
    if mutual:
        # Prefer by protocol priority
        priority = [ProtocolName.mcp, ProtocolName.a2a, ProtocolName.langchain, ProtocolName.autogen, ProtocolName.crewai, ProtocolName.custom]
        for p in priority:
            if p in mutual:
                return {"negotiated_protocol": p.value, "mutual_protocols": [p.value for p in mutual], "strategy": "priority_fallback"}
    # No mutual — need translation
    return {
        "negotiated_protocol": None,
        "requires_translation": True,
        "endpoint_a_protocols": [p.value for p in ep_a.protocols],
        "endpoint_b_protocols": [p.value for p in ep_b.protocols],
        "strategy": "translation_required",
    }


# ── Endpoints ──────────────────────────────────────────────────────────────

@app.post("/v1/endpoints", status_code=201)
def register_endpoint(body: EndpointCreate):
    eid = f"EP-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = EndpointRecord(**body.dict(), endpoint_id=eid, last_seen=now, created_at=now)
    endpoints[eid] = record
    return record.dict()


@app.get("/v1/endpoints")
def list_endpoints(
    protocol: Optional[ProtocolName] = None,
    capability: Optional[str] = None,
    tag: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(endpoints.values())
    if protocol:
        results = [e for e in results if protocol in e.protocols]
    if capability:
        results = [e for e in results if capability in e.capabilities]
    if tag:
        results = [e for e in results if tag in e.tags]
    return {"endpoints": [e.dict() for e in results[:limit]], "total": len(results)}


@app.get("/v1/endpoints/{endpoint_id}")
def get_endpoint(endpoint_id: str):
    if endpoint_id not in endpoints:
        raise HTTPException(404, "Endpoint not found")
    return endpoints[endpoint_id].dict()


@app.delete("/v1/endpoints/{endpoint_id}")
def deregister_endpoint(endpoint_id: str):
    if endpoint_id not in endpoints:
        raise HTTPException(404, "Endpoint not found")
    del endpoints[endpoint_id]
    return {"deregistered": endpoint_id}


# ── Sessions ───────────────────────────────────────────────────────────────

@app.post("/v1/sessions", status_code=201)
def create_session(body: SessionCreate):
    if body.source_endpoint not in endpoints:
        raise HTTPException(404, "Source endpoint not found")
    if body.target_endpoint not in endpoints:
        raise HTTPException(404, "Target endpoint not found")
    sid = f"SESS-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = SessionRecord(**body.dict(), session_id=sid, state=SessionState.open, created_at=now, updated_at=now)
    sessions[sid] = record
    return record.dict()


@app.get("/v1/sessions/{session_id}")
def get_session(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    return sessions[session_id].dict()


@app.post("/v1/sessions/{session_id}/send")
def session_send(session_id: str, body: SessionSend):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    s = sessions[session_id]
    if s.state in (SessionState.closed, SessionState.expired):
        raise HTTPException(422, "Session is closed")
    s.state = SessionState.active
    # Translate through the bridge
    src_proto = s.source_protocol if body.direction == "forward" else s.target_protocol
    tgt_proto = s.target_protocol if body.direction == "forward" else s.source_protocol
    nuam = _to_nuam(src_proto, body.message)
    nuam.target_protocol = tgt_proto.value
    result = _from_nuam(tgt_proto, nuam)
    msg_entry = {
        "direction": body.direction,
        "original": body.message,
        "translated": result["translated_message"],
        "nuam_id": nuam.message_id,
        "timestamp": _now(),
    }
    s.messages.append(msg_entry)
    s.updated_at = _now()
    return msg_entry


@app.delete("/v1/sessions/{session_id}")
def close_session(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    sessions[session_id].state = SessionState.closed
    sessions[session_id].updated_at = _now()
    return {"closed": session_id}


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/v1/analytics")
def analytics():
    proto_volume: Dict[str, int] = defaultdict(int)
    for entry in translation_log:
        proto_volume[entry["source"]] += 1
        proto_volume[entry["target"]] += 1
    session_state_dist: Dict[str, int] = defaultdict(int)
    for s in sessions.values():
        session_state_dist[s.state.value] += 1
    return {
        "protocols_registered": len(protocols),
        "endpoints_registered": len(endpoints),
        "total_translations": len(translation_log),
        "protocol_volume": dict(proto_volume),
        "sessions": {
            "total": len(sessions),
            "state_distribution": dict(session_state_dist),
        },
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9401)
