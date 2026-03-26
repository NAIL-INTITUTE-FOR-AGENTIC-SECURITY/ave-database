"""
Governance-as-Code Pipeline — Core pipeline server.

Declarative policy engine that embeds AVE governance checks into
CI/CD workflows.  Supports a GaC DSL for policy definition,
multi-gate pipelines (risk appetite, compliance scan, AVE coverage),
webhook integration with CI/CD platforms, verdicts/reports, and
human-in-the-loop override capability.
"""

from __future__ import annotations

import hashlib
import random
import statistics
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="NAIL Governance-as-Code Pipeline",
    description=(
        "Declarative policy engine embedding AVE governance into CI/CD "
        "workflows with multi-gate pipelines, webhook triggers, and verdicts."
    ),
    version="1.0.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AVE_CATEGORIES = [
    "prompt_injection", "tool_misuse", "memory_poisoning", "goal_hijacking",
    "identity_spoofing", "privilege_escalation", "data_exfiltration",
    "resource_exhaustion", "multi_agent_manipulation", "context_overflow",
    "guardrail_bypass", "output_manipulation", "supply_chain_compromise",
    "model_extraction", "reward_hacking", "capability_elicitation",
    "alignment_subversion", "delegation_abuse",
]

CI_PLATFORMS = ["github_actions", "gitlab_ci", "jenkins", "azure_devops", "circleci", "custom"]

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PolicySeverity(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    INFO = "info"


class GateType(str, Enum):
    RISK_APPETITE = "risk_appetite"
    COMPLIANCE_SCAN = "compliance_scan"
    AVE_COVERAGE = "ave_coverage"
    VULNERABILITY_CHECK = "vulnerability_check"
    CUSTOM = "custom"


class GateVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIPPED = "skipped"


class PipelineStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    OVERRIDDEN = "overridden"


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    OVERRIDDEN = "overridden"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class PolicyRule(BaseModel):
    name: str
    description: str = ""
    check_type: str  # max_risk, min_coverage, required_category, compliance_required, custom
    parameters: dict[str, Any] = Field(default_factory=dict)
    severity: PolicySeverity = PolicySeverity.BLOCK
    enabled: bool = True


class Policy(BaseModel):
    id: str = Field(default_factory=lambda: f"POL-{uuid.uuid4().hex[:8].upper()}")
    name: str
    version: str = "1.0.0"
    description: str = ""
    rules: list[PolicyRule] = Field(default_factory=list)
    applicable_to: list[str] = Field(default_factory=lambda: ["all"])  # repo patterns, team names
    enabled: bool = True
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    rules: list[PolicyRule] = Field(default_factory=list)
    applicable_to: list[str] = Field(default_factory=lambda: ["all"])


class Gate(BaseModel):
    id: str = Field(default_factory=lambda: f"GATE-{uuid.uuid4().hex[:8].upper()}")
    name: str
    gate_type: GateType
    description: str = ""
    config: dict[str, Any] = Field(default_factory=dict)
    policy_ids: list[str] = Field(default_factory=list)
    required: bool = True  # pipeline fails if required gate fails
    order: int = 0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class GateCreate(BaseModel):
    name: str
    gate_type: GateType
    description: str = ""
    config: dict[str, Any] = Field(default_factory=dict)
    policy_ids: list[str] = Field(default_factory=list)
    required: bool = True
    order: int = 0


class Pipeline(BaseModel):
    id: str = Field(default_factory=lambda: f"PIPE-{uuid.uuid4().hex[:8].upper()}")
    name: str
    description: str = ""
    gate_ids: list[str] = Field(default_factory=list)
    ci_platform: str = "github_actions"
    webhook_secret: str = Field(
        default_factory=lambda: hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:24]
    )
    status: PipelineStatus = PipelineStatus.CREATED
    total_runs: int = 0
    pass_rate: float = 0.0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PipelineCreate(BaseModel):
    name: str
    description: str = ""
    gate_ids: list[str] = Field(default_factory=list)
    ci_platform: str = "github_actions"


class GateResult(BaseModel):
    gate_id: str
    gate_name: str
    gate_type: str
    verdict: GateVerdict
    required: bool
    details: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0


class PipelineRun(BaseModel):
    id: str = Field(default_factory=lambda: f"RUN-{uuid.uuid4().hex[:8].upper()}")
    pipeline_id: str
    trigger: str = "manual"  # manual, webhook, scheduled
    trigger_metadata: dict[str, Any] = Field(default_factory=dict)
    status: RunStatus = RunStatus.PENDING
    gate_results: list[GateResult] = Field(default_factory=list)
    overall_verdict: GateVerdict = GateVerdict.PASS
    risk_score: float = 0.0
    coverage_score: float = 0.0
    compliance_score: float = 0.0
    report: dict[str, Any] = Field(default_factory=dict)
    overridden_by: Optional[str] = None
    override_reason: Optional[str] = None
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None


class WebhookPayload(BaseModel):
    platform: str = "github_actions"
    event: str = "push"  # push, pull_request, merge, deployment
    repository: str = ""
    branch: str = "main"
    commit_sha: str = ""
    author: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class OverrideRequest(BaseModel):
    overridden_by: str
    reason: str


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → PostgreSQL + Redis + S3)
# ---------------------------------------------------------------------------

POLICIES: dict[str, Policy] = {}
GATES: dict[str, Gate] = {}
PIPELINES: dict[str, Pipeline] = {}
RUNS: dict[str, PipelineRun] = {}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731


def _evaluate_rule(rule: PolicyRule, context: dict[str, Any]) -> tuple[bool, str]:
    """Evaluate a single policy rule against deployment context."""
    check = rule.check_type
    params = rule.parameters

    if check == "max_risk":
        max_allowed = params.get("max_risk_score", 0.7)
        current_risk = context.get("risk_score", random.uniform(0.1, 0.9))
        passed = current_risk <= max_allowed
        detail = f"Risk {current_risk:.4f} {'<=' if passed else '>'} max {max_allowed}"
        return passed, detail

    elif check == "min_coverage":
        min_pct = params.get("min_coverage_pct", 70)
        current = context.get("coverage_pct", random.uniform(40, 100))
        passed = current >= min_pct
        detail = f"Coverage {current:.1f}% {'>=' if passed else '<'} min {min_pct}%"
        return passed, detail

    elif check == "required_category":
        required = params.get("categories", [])
        covered = context.get("covered_categories", random.sample(AVE_CATEGORIES, random.randint(5, 15)))
        missing = [c for c in required if c not in covered]
        passed = len(missing) == 0
        detail = f"Missing categories: {missing}" if not passed else "All required categories covered"
        return passed, detail

    elif check == "compliance_required":
        frameworks = params.get("frameworks", ["NIST_AI_RMF"])
        compliant = context.get("compliant_frameworks", random.sample(
            ["ISO_42001", "NIST_AI_RMF", "EU_AI_ACT", "SOC2_Type_II"],
            random.randint(1, 4)
        ))
        missing = [f for f in frameworks if f not in compliant]
        passed = len(missing) == 0
        detail = f"Missing compliance: {missing}" if not passed else "All required frameworks compliant"
        return passed, detail

    elif check == "no_critical_vulns":
        crit_count = context.get("critical_vulns", random.randint(0, 3))
        passed = crit_count == 0
        detail = f"Critical vulnerabilities: {crit_count}"
        return passed, detail

    elif check == "max_open_issues":
        max_issues = params.get("max_issues", 5)
        current = context.get("open_issues", random.randint(0, 10))
        passed = current <= max_issues
        detail = f"Open issues: {current} {'<=' if passed else '>'} max {max_issues}"
        return passed, detail

    else:
        # Custom rule — simulate
        passed = random.random() > 0.3
        detail = f"Custom check '{check}' {'passed' if passed else 'failed'}"
        return passed, detail


def _evaluate_gate(gate: Gate, context: dict[str, Any]) -> GateResult:
    """Evaluate all policies attached to a gate."""
    details: dict[str, Any] = {"rules_evaluated": 0, "rules_passed": 0, "rule_results": []}
    overall = GateVerdict.PASS
    latency = round(random.uniform(50, 2000), 1)

    for pol_id in gate.policy_ids:
        pol = POLICIES.get(pol_id)
        if not pol or not pol.enabled:
            continue

        for rule in pol.rules:
            if not rule.enabled:
                continue
            details["rules_evaluated"] += 1
            passed, detail = _evaluate_rule(rule, context)

            rule_result = {
                "policy": pol.name,
                "rule": rule.name,
                "passed": passed,
                "detail": detail,
                "severity": rule.severity.value,
            }
            details["rule_results"].append(rule_result)

            if passed:
                details["rules_passed"] += 1
            else:
                if rule.severity == PolicySeverity.BLOCK:
                    overall = GateVerdict.FAIL
                elif rule.severity == PolicySeverity.WARN and overall != GateVerdict.FAIL:
                    overall = GateVerdict.WARN

    # Gate-type-specific scoring
    if gate.gate_type == GateType.RISK_APPETITE:
        details["risk_score"] = context.get("risk_score", round(random.uniform(0.1, 0.9), 4))
    elif gate.gate_type == GateType.AVE_COVERAGE:
        details["coverage_score"] = context.get("coverage_pct", round(random.uniform(40, 100), 1))
    elif gate.gate_type == GateType.COMPLIANCE_SCAN:
        details["compliance_score"] = context.get("compliance_score", round(random.uniform(50, 100), 1))

    return GateResult(
        gate_id=gate.id,
        gate_name=gate.name,
        gate_type=gate.gate_type.value,
        verdict=overall,
        required=gate.required,
        details=details,
        duration_ms=latency,
    )


def _run_pipeline(pipeline: Pipeline, trigger: str, metadata: dict[str, Any]) -> PipelineRun:
    """Execute a full pipeline run through all gates."""
    context: dict[str, Any] = {
        "risk_score": round(random.uniform(0.1, 0.9), 4),
        "coverage_pct": round(random.uniform(40, 100), 1),
        "compliance_score": round(random.uniform(50, 100), 1),
        "critical_vulns": random.randint(0, 3),
        "open_issues": random.randint(0, 10),
        "covered_categories": random.sample(AVE_CATEGORIES, random.randint(8, 16)),
        "compliant_frameworks": random.sample(
            ["ISO_42001", "NIST_AI_RMF", "EU_AI_ACT", "SOC2_Type_II", "GDPR"],
            random.randint(2, 5)
        ),
    }
    context.update(metadata)

    run = PipelineRun(
        pipeline_id=pipeline.id,
        trigger=trigger,
        trigger_metadata=metadata,
        status=RunStatus.RUNNING,
    )

    # Evaluate gates in order
    gates = sorted(
        [GATES[gid] for gid in pipeline.gate_ids if gid in GATES],
        key=lambda g: g.order,
    )

    overall = GateVerdict.PASS
    for gate in gates:
        result = _evaluate_gate(gate, context)
        run.gate_results.append(result)

        if result.verdict == GateVerdict.FAIL and result.required:
            overall = GateVerdict.FAIL
        elif result.verdict == GateVerdict.WARN and overall != GateVerdict.FAIL:
            overall = GateVerdict.WARN

    run.overall_verdict = overall
    run.status = RunStatus.PASSED if overall in (GateVerdict.PASS, GateVerdict.WARN) else RunStatus.FAILED
    run.risk_score = context.get("risk_score", 0.0)
    run.coverage_score = context.get("coverage_pct", 0.0)
    run.compliance_score = context.get("compliance_score", 0.0)
    run.completed_at = _now().isoformat()

    # Build report
    run.report = {
        "pipeline": pipeline.name,
        "trigger": trigger,
        "gates_evaluated": len(run.gate_results),
        "gates_passed": sum(1 for r in run.gate_results if r.verdict == GateVerdict.PASS),
        "gates_warned": sum(1 for r in run.gate_results if r.verdict == GateVerdict.WARN),
        "gates_failed": sum(1 for r in run.gate_results if r.verdict == GateVerdict.FAIL),
        "overall_verdict": overall.value,
        "risk_score": run.risk_score,
        "coverage_score": run.coverage_score,
        "compliance_score": run.compliance_score,
        "recommendations": [],
    }

    # Generate recommendations for failed gates
    for gr in run.gate_results:
        if gr.verdict == GateVerdict.FAIL:
            run.report["recommendations"].append(
                f"Gate '{gr.gate_name}' ({gr.gate_type}) failed — review policy rules and fix violations"
            )

    RUNS[run.id] = run
    pipeline.total_runs += 1
    passed_runs = sum(1 for r in RUNS.values() if r.pipeline_id == pipeline.id and r.status == RunStatus.PASSED)
    pipeline.pass_rate = round(passed_runs / pipeline.total_runs, 4) if pipeline.total_runs else 0.0
    pipeline.updated_at = _now().isoformat()

    return run


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    # ---- Policies ----
    policies_data = [
        ("Risk Appetite Policy", "Maximum acceptable risk thresholds", [
            PolicyRule(name="max-risk-score", check_type="max_risk",
                       parameters={"max_risk_score": 0.7}, severity=PolicySeverity.BLOCK),
            PolicyRule(name="no-critical-vulns", check_type="no_critical_vulns",
                       parameters={}, severity=PolicySeverity.BLOCK),
            PolicyRule(name="max-open-issues", check_type="max_open_issues",
                       parameters={"max_issues": 5}, severity=PolicySeverity.WARN),
        ]),
        ("Compliance Policy", "Required compliance framework adherence", [
            PolicyRule(name="nist-required", check_type="compliance_required",
                       parameters={"frameworks": ["NIST_AI_RMF"]}, severity=PolicySeverity.BLOCK),
            PolicyRule(name="iso-42001-required", check_type="compliance_required",
                       parameters={"frameworks": ["ISO_42001"]}, severity=PolicySeverity.WARN),
        ]),
        ("AVE Coverage Policy", "Minimum AVE category coverage requirements", [
            PolicyRule(name="min-coverage-80", check_type="min_coverage",
                       parameters={"min_coverage_pct": 80}, severity=PolicySeverity.BLOCK),
            PolicyRule(name="required-categories", check_type="required_category",
                       parameters={"categories": ["prompt_injection", "tool_misuse", "data_exfiltration"]},
                       severity=PolicySeverity.BLOCK),
        ]),
        ("Vulnerability Policy", "Vulnerability check requirements", [
            PolicyRule(name="no-critical-vulns", check_type="no_critical_vulns",
                       parameters={}, severity=PolicySeverity.BLOCK),
            PolicyRule(name="max-risk-moderate", check_type="max_risk",
                       parameters={"max_risk_score": 0.5}, severity=PolicySeverity.WARN),
        ]),
    ]

    for name, desc, rules in policies_data:
        pol = Policy(name=name, description=desc, rules=rules)
        POLICIES[pol.id] = pol

    pol_ids = list(POLICIES.keys())

    # ---- Gates ----
    gates_data = [
        ("Risk Appetite Gate", GateType.RISK_APPETITE, True, 1, [pol_ids[0]]),
        ("Compliance Gate", GateType.COMPLIANCE_SCAN, True, 2, [pol_ids[1]]),
        ("AVE Coverage Gate", GateType.AVE_COVERAGE, True, 3, [pol_ids[2]]),
        ("Vulnerability Gate", GateType.VULNERABILITY_CHECK, False, 4, [pol_ids[3]]),
    ]

    for name, gtype, required, order, pids in gates_data:
        gate = Gate(
            name=name, gate_type=gtype, required=required, order=order,
            policy_ids=pids, description=f"{name} — evaluates {gtype.value} policies",
        )
        GATES[gate.id] = gate

    gate_ids = list(GATES.keys())

    # ---- Pipeline ----
    pipe = Pipeline(
        name="Production Deployment Pipeline",
        description="Full governance pipeline for production AI deployments",
        gate_ids=gate_ids,
        ci_platform="github_actions",
    )
    PIPELINES[pipe.id] = pipe

    # ---- Seed runs ----
    for i in range(5):
        trigger = random.choice(["webhook", "manual", "scheduled"])
        meta = {
            "repository": "nail-institute/ave-stack",
            "branch": random.choice(["main", "develop", "feature/new-agent"]),
            "commit_sha": hashlib.sha256(str(i).encode()).hexdigest()[:7],
            "author": random.choice(["alice", "bob", "charlie"]),
        }
        _run_pipeline(pipe, trigger, meta)


_seed()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "governance-as-code-pipeline",
        "version": "1.0.0",
        "policies": len(POLICIES),
        "gates": len(GATES),
        "pipelines": len(PIPELINES),
        "runs": len(RUNS),
    }


# ---- Policies ------------------------------------------------------------

@app.post("/v1/policies", status_code=status.HTTP_201_CREATED)
async def create_policy(data: PolicyCreate):
    pol = Policy(name=data.name, description=data.description, rules=data.rules,
                 applicable_to=data.applicable_to)
    POLICIES[pol.id] = pol
    return {"id": pol.id, "name": pol.name, "rules_count": len(pol.rules)}


@app.get("/v1/policies")
async def list_policies():
    pols = list(POLICIES.values())
    return {
        "count": len(pols),
        "policies": [
            {
                "id": p.id,
                "name": p.name,
                "version": p.version,
                "rules": len(p.rules),
                "enabled": p.enabled,
                "created_at": p.created_at,
            }
            for p in pols
        ],
    }


@app.get("/v1/policies/{pol_id}")
async def get_policy(pol_id: str):
    if pol_id not in POLICIES:
        raise HTTPException(404, "Policy not found")
    return POLICIES[pol_id].dict()


# ---- Gates ---------------------------------------------------------------

@app.post("/v1/gates", status_code=status.HTTP_201_CREATED)
async def create_gate(data: GateCreate):
    for pid in data.policy_ids:
        if pid not in POLICIES:
            raise HTTPException(404, f"Policy {pid} not found")
    gate = Gate(**data.dict())
    GATES[gate.id] = gate
    return {"id": gate.id, "name": gate.name, "gate_type": gate.gate_type.value}


@app.get("/v1/gates")
async def list_gates():
    gates = sorted(GATES.values(), key=lambda g: g.order)
    return {
        "count": len(gates),
        "gates": [
            {
                "id": g.id,
                "name": g.name,
                "type": g.gate_type.value,
                "required": g.required,
                "order": g.order,
                "policies": len(g.policy_ids),
            }
            for g in gates
        ],
    }


@app.get("/v1/gates/{gate_id}")
async def get_gate(gate_id: str):
    if gate_id not in GATES:
        raise HTTPException(404, "Gate not found")
    return GATES[gate_id].dict()


# ---- Pipelines -----------------------------------------------------------

@app.post("/v1/pipelines", status_code=status.HTTP_201_CREATED)
async def create_pipeline(data: PipelineCreate):
    for gid in data.gate_ids:
        if gid not in GATES:
            raise HTTPException(404, f"Gate {gid} not found")
    if data.ci_platform not in CI_PLATFORMS:
        raise HTTPException(400, f"Invalid CI platform. Must be one of: {CI_PLATFORMS}")

    pipe = Pipeline(name=data.name, description=data.description,
                    gate_ids=data.gate_ids, ci_platform=data.ci_platform)
    PIPELINES[pipe.id] = pipe
    return {"id": pipe.id, "name": pipe.name, "webhook_secret": pipe.webhook_secret}


@app.get("/v1/pipelines")
async def list_pipelines():
    pipes = list(PIPELINES.values())
    return {
        "count": len(pipes),
        "pipelines": [
            {
                "id": p.id,
                "name": p.name,
                "ci_platform": p.ci_platform,
                "gates": len(p.gate_ids),
                "total_runs": p.total_runs,
                "pass_rate": p.pass_rate,
                "status": p.status.value,
            }
            for p in pipes
        ],
    }


@app.get("/v1/pipelines/{pipe_id}")
async def get_pipeline(pipe_id: str):
    if pipe_id not in PIPELINES:
        raise HTTPException(404, "Pipeline not found")
    return PIPELINES[pipe_id].dict()


# ---- Run Pipeline --------------------------------------------------------

@app.post("/v1/pipelines/{pipe_id}/run", status_code=status.HTTP_201_CREATED)
async def run_pipeline(pipe_id: str):
    if pipe_id not in PIPELINES:
        raise HTTPException(404, "Pipeline not found")
    run = _run_pipeline(PIPELINES[pipe_id], "manual", {})
    return {
        "run_id": run.id,
        "status": run.status.value,
        "verdict": run.overall_verdict.value,
        "gates_evaluated": len(run.gate_results),
        "report": run.report,
    }


# ---- Runs ----------------------------------------------------------------

@app.get("/v1/runs")
async def list_runs(
    pipeline_id: Optional[str] = None,
    status_filter: Optional[RunStatus] = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=500),
):
    runs = list(RUNS.values())
    if pipeline_id:
        runs = [r for r in runs if r.pipeline_id == pipeline_id]
    if status_filter:
        runs = [r for r in runs if r.status == status_filter]
    runs.sort(key=lambda r: r.started_at, reverse=True)
    return {
        "count": len(runs[:limit]),
        "runs": [
            {
                "id": r.id,
                "pipeline_id": r.pipeline_id,
                "trigger": r.trigger,
                "status": r.status.value,
                "verdict": r.overall_verdict.value,
                "risk_score": r.risk_score,
                "coverage_score": r.coverage_score,
                "compliance_score": r.compliance_score,
                "started_at": r.started_at,
                "completed_at": r.completed_at,
            }
            for r in runs[:limit]
        ],
    }


@app.get("/v1/runs/{run_id}")
async def get_run(run_id: str):
    if run_id not in RUNS:
        raise HTTPException(404, "Run not found")
    return RUNS[run_id].dict()


@app.get("/v1/runs/{run_id}/report")
async def get_run_report(run_id: str):
    if run_id not in RUNS:
        raise HTTPException(404, "Run not found")
    run = RUNS[run_id]
    return {
        "run_id": run.id,
        "pipeline_id": run.pipeline_id,
        "status": run.status.value,
        "verdict": run.overall_verdict.value,
        "report": run.report,
        "gate_results": [gr.dict() for gr in run.gate_results],
    }


# ---- Override ------------------------------------------------------------

@app.post("/v1/runs/{run_id}/override")
async def override_run(run_id: str, req: OverrideRequest):
    if run_id not in RUNS:
        raise HTTPException(404, "Run not found")
    run = RUNS[run_id]
    if run.status not in (RunStatus.FAILED,):
        raise HTTPException(409, f"Can only override FAILED runs (current: {run.status.value})")
    if not req.reason or len(req.reason.strip()) < 10:
        raise HTTPException(400, "Override reason must be at least 10 characters")

    run.status = RunStatus.OVERRIDDEN
    run.overridden_by = req.overridden_by
    run.override_reason = req.reason
    run.completed_at = _now().isoformat()

    return {
        "overridden": True,
        "run_id": run.id,
        "overridden_by": req.overridden_by,
        "reason": req.reason,
    }


# ---- Webhook -------------------------------------------------------------

@app.post("/v1/webhook")
async def webhook_trigger(payload: WebhookPayload):
    if payload.platform not in CI_PLATFORMS:
        raise HTTPException(400, f"Unsupported platform: {payload.platform}")

    # Find matching pipeline for the platform
    matching = [p for p in PIPELINES.values() if p.ci_platform == payload.platform]
    if not matching:
        raise HTTPException(404, f"No pipeline configured for platform: {payload.platform}")

    results: list[dict[str, Any]] = []
    for pipe in matching:
        meta = {
            "repository": payload.repository,
            "branch": payload.branch,
            "commit_sha": payload.commit_sha,
            "author": payload.author,
            "event": payload.event,
            **payload.metadata,
        }
        run = _run_pipeline(pipe, "webhook", meta)
        results.append({
            "pipeline_id": pipe.id,
            "run_id": run.id,
            "status": run.status.value,
            "verdict": run.overall_verdict.value,
        })

    return {"triggered": len(results), "results": results}


# ---- Analytics -----------------------------------------------------------

@app.get("/v1/analytics")
async def pipeline_analytics():
    policies = list(POLICIES.values())
    gates = list(GATES.values())
    pipes = list(PIPELINES.values())
    runs = list(RUNS.values())

    by_status = Counter(r.status.value for r in runs)
    by_verdict = Counter(r.overall_verdict.value for r in runs)
    by_trigger = Counter(r.trigger for r in runs)
    by_platform = Counter(p.ci_platform for p in pipes)

    risk_scores = [r.risk_score for r in runs if r.risk_score > 0]
    avg_risk = round(statistics.mean(risk_scores), 4) if risk_scores else 0.0
    avg_coverage = round(
        statistics.mean(r.coverage_score for r in runs if r.coverage_score > 0), 1
    ) if any(r.coverage_score > 0 for r in runs) else 0.0
    avg_compliance = round(
        statistics.mean(r.compliance_score for r in runs if r.compliance_score > 0), 1
    ) if any(r.compliance_score > 0 for r in runs) else 0.0

    overridden = sum(1 for r in runs if r.status == RunStatus.OVERRIDDEN)

    return {
        "total_policies": len(policies),
        "total_gates": len(gates),
        "total_pipelines": len(pipes),
        "total_runs": len(runs),
        "by_status": dict(by_status),
        "by_verdict": dict(by_verdict),
        "by_trigger": dict(by_trigger),
        "by_platform": dict(by_platform),
        "avg_risk_score": avg_risk,
        "avg_coverage_score": avg_coverage,
        "avg_compliance_score": avg_compliance,
        "override_count": overridden,
        "overall_pass_rate": round(
            sum(1 for r in runs if r.status in (RunStatus.PASSED, RunStatus.OVERRIDDEN)) / len(runs), 4
        ) if runs else 0.0,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8804)
