"""
Self-Evolving Defence Catalogue — Core catalogue server.

Defence library that autonomously generates, tests, and publishes new
guardrails in response to novel vulnerability classes.  Implements a
watch → generate → test → score → publish feedback loop with versioned
registry and regression guarding.
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
    title="NAIL Self-Evolving Defence Catalogue",
    description=(
        "Autonomous defence library that generates, tests, and publishes "
        "guardrails in response to novel vulnerability classes."
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

SUPPORTED_FRAMEWORKS = ["langchain", "crewai", "autogen", "llamaindex", "custom"]

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DefenceStatus(str, Enum):
    DRAFT = "draft"
    TESTING = "testing"
    TESTED = "tested"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"
    FAILED = "failed"


class TestVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"


class GenerationStrategy(str, Enum):
    PATTERN_MATCH = "pattern_match"
    TEMPLATE_EXPANSION = "template_expansion"
    HYBRID = "hybrid"
    ADVERSARIAL_SYNTH = "adversarial_synthesis"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class CatalogueDefence(BaseModel):
    id: str = Field(default_factory=lambda: f"CDEF-{uuid.uuid4().hex[:8].upper()}")
    name: str
    description: str = ""
    target_category: str
    defence_type: str  # input_filter, output_validator, tool_sandbox, etc.
    generation_strategy: GenerationStrategy = GenerationStrategy.PATTERN_MATCH
    code_snippet: str = ""  # synthesized guardrail code
    config: dict[str, Any] = Field(default_factory=dict)
    compatible_frameworks: list[str] = Field(default_factory=list)
    status: DefenceStatus = DefenceStatus.DRAFT
    version: str = "0.1.0"
    efficacy_score: float = 0.0  # 0-1
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    latency_ms: float = 0.0
    test_results: list[dict[str, Any]] = Field(default_factory=list)
    published_at: Optional[str] = None
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    changelog: list[dict[str, Any]] = Field(default_factory=list)


class GenerateRequest(BaseModel):
    vulnerability_title: str
    category: str
    description: str = ""
    severity: str = "high"
    strategy: GenerationStrategy = GenerationStrategy.HYBRID


class TestRequest(BaseModel):
    attack_samples: int = 100
    benign_samples: int = 100


class RegistryEntry(BaseModel):
    defence_id: str
    name: str
    category: str
    version: str
    efficacy_score: float
    detection_rate: float
    false_positive_rate: float
    latency_ms: float
    compatible_frameworks: list[str]
    published_at: str


class CoverageReport(BaseModel):
    total_categories: int
    covered_categories: int
    uncovered_categories: list[str]
    coverage_ratio: float
    by_category: dict[str, dict[str, Any]]


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → PostgreSQL + S3)
# ---------------------------------------------------------------------------

DEFENCES: dict[str, CatalogueDefence] = {}
REGISTRY: list[RegistryEntry] = []
CHANGELOG: list[dict[str, Any]] = []

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731


# Defence code templates per type
CODE_TEMPLATES: dict[str, str] = {
    "input_filter": """
class {class_name}InputFilter:
    \"\"\"Auto-generated input filter for {category}.\"\"\"
    PATTERNS = {patterns}
    THRESHOLD = {threshold}

    def check(self, text: str) -> tuple[bool, float]:
        score = sum(1 for p in self.PATTERNS if p.lower() in text.lower())
        confidence = min(score / max(len(self.PATTERNS), 1), 1.0)
        return confidence >= self.THRESHOLD, confidence
""",
    "output_validator": """
class {class_name}OutputValidator:
    \"\"\"Auto-generated output validator for {category}.\"\"\"
    BLOCKED_PATTERNS = {patterns}

    def validate(self, output: str) -> tuple[bool, list[str]]:
        violations = [p for p in self.BLOCKED_PATTERNS if p.lower() in output.lower()]
        return len(violations) == 0, violations
""",
    "tool_sandbox": """
class {class_name}ToolSandbox:
    \"\"\"Auto-generated tool sandbox for {category}.\"\"\"
    ALLOWED_TOOLS = {allowed}
    MAX_CALLS = {max_calls}

    def check_tool(self, tool_name: str, call_count: int) -> bool:
        return tool_name in self.ALLOWED_TOOLS and call_count < self.MAX_CALLS
""",
}

# Category-specific attack patterns for code generation
CATEGORY_PATTERNS: dict[str, list[str]] = {
    "prompt_injection": ["ignore previous", "system prompt", "you are now", "disregard", "new instructions"],
    "tool_misuse": ["exec(", "eval(", "os.system", "subprocess", "shell=True"],
    "memory_poisoning": ["remember this:", "always respond with", "your instructions are"],
    "goal_hijacking": ["your real goal", "forget your purpose", "actually you should"],
    "identity_spoofing": ["I am the admin", "authorized user", "root access"],
    "privilege_escalation": ["sudo", "admin mode", "elevated permissions", "bypass auth"],
    "data_exfiltration": ["send to external", "upload data", "exfil", "base64 encode and send"],
    "resource_exhaustion": ["repeat 10000 times", "infinite loop", "generate maximum"],
    "multi_agent_manipulation": ["tell agent B", "relay to", "coordinate attack"],
    "context_overflow": ["A" * 50, "padding " * 20, "fill context"],
    "guardrail_bypass": ["unicode trick", "encoding bypass", "homoglyph"],
    "output_manipulation": ["format as code", "inject html", "script tag"],
    "supply_chain_compromise": ["malicious package", "dependency confusion"],
    "model_extraction": ["repeat training data", "output your weights"],
    "reward_hacking": ["maximize reward", "exploit reward function"],
    "capability_elicitation": ["pretend you can", "hypothetically if you could"],
    "alignment_subversion": ["ignore safety", "remove restrictions"],
    "delegation_abuse": ["delegate to untrusted", "forward to external"],
}


def _generate_defence_code(category: str, strategy: GenerationStrategy) -> tuple[str, str, dict]:
    """Synthesize defence code for a vulnerability category."""
    patterns = CATEGORY_PATTERNS.get(category, ["unknown_pattern"])
    class_name = "".join(w.title() for w in category.split("_"))

    if strategy in (GenerationStrategy.PATTERN_MATCH, GenerationStrategy.HYBRID):
        defence_type = "input_filter"
        code = CODE_TEMPLATES["input_filter"].format(
            class_name=class_name,
            category=category,
            patterns=patterns,
            threshold=0.3,
        )
        config = {"patterns": patterns, "threshold": 0.3, "mode": "block"}
    elif strategy == GenerationStrategy.TEMPLATE_EXPANSION:
        defence_type = "output_validator"
        code = CODE_TEMPLATES["output_validator"].format(
            class_name=class_name,
            category=category,
            patterns=patterns,
        )
        config = {"patterns": patterns, "mode": "validate"}
    else:
        defence_type = "tool_sandbox"
        code = CODE_TEMPLATES["tool_sandbox"].format(
            class_name=class_name,
            category=category,
            allowed=["search", "calculator"],
            max_calls=10,
        )
        config = {"allowed_tools": ["search", "calculator"], "max_calls": 10}

    return defence_type, code.strip(), config


def _run_test_suite(defence: CatalogueDefence, attack_samples: int, benign_samples: int) -> dict[str, Any]:
    """Simulate a test run against attack and benign samples."""
    # Simulate detection rates based on strategy quality
    base_detection = {
        GenerationStrategy.PATTERN_MATCH: 0.75,
        GenerationStrategy.TEMPLATE_EXPANSION: 0.70,
        GenerationStrategy.HYBRID: 0.85,
        GenerationStrategy.ADVERSARIAL_SYNTH: 0.90,
    }
    base = base_detection.get(defence.generation_strategy, 0.7)

    true_positives = int(attack_samples * (base + random.uniform(-0.05, 0.10)))
    true_positives = min(true_positives, attack_samples)
    false_negatives = attack_samples - true_positives

    fp_rate_base = random.uniform(0.02, 0.10)
    false_positives = int(benign_samples * fp_rate_base)
    true_negatives = benign_samples - false_positives

    detection_rate = true_positives / attack_samples if attack_samples else 0
    fpr = false_positives / benign_samples if benign_samples else 0
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 0
    f1 = 2 * (precision * detection_rate) / (precision + detection_rate) if (precision + detection_rate) else 0
    latency = round(random.uniform(0.5, 15.0), 2)

    efficacy = round(0.5 * detection_rate + 0.3 * (1 - fpr) + 0.2 * min(1.0, 10.0 / max(latency, 0.1)), 4)

    result = {
        "attack_samples": attack_samples,
        "benign_samples": benign_samples,
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "false_positives": false_positives,
        "detection_rate": round(detection_rate, 4),
        "false_positive_rate": round(fpr, 4),
        "precision": round(precision, 4),
        "f1_score": round(f1, 4),
        "latency_ms": latency,
        "efficacy_score": efficacy,
        "verdict": TestVerdict.PASS.value if efficacy >= 0.6 else TestVerdict.FAIL.value,
        "timestamp": _now().isoformat(),
    }
    return result


def _check_framework_compat(defence_type: str) -> list[str]:
    """Determine framework compatibility based on defence type."""
    compat_map = {
        "input_filter": ["langchain", "crewai", "autogen", "llamaindex", "custom"],
        "output_validator": ["langchain", "crewai", "autogen", "llamaindex", "custom"],
        "tool_sandbox": ["langchain", "crewai", "autogen", "custom"],
        "memory_guard": ["langchain", "autogen", "custom"],
        "rate_limiter": ["langchain", "crewai", "autogen", "llamaindex", "custom"],
    }
    return compat_map.get(defence_type, ["custom"])


def _bump_version(current: str, major: bool = False) -> str:
    parts = current.split(".")
    if major:
        return f"{int(parts[0]) + 1}.0.0"
    return f"{parts[0]}.{int(parts[1]) + 1}.0"


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    seed_defs = [
        ("prompt_injection", GenerationStrategy.HYBRID, DefenceStatus.PUBLISHED),
        ("tool_misuse", GenerationStrategy.PATTERN_MATCH, DefenceStatus.PUBLISHED),
        ("memory_poisoning", GenerationStrategy.TEMPLATE_EXPANSION, DefenceStatus.TESTED),
        ("guardrail_bypass", GenerationStrategy.ADVERSARIAL_SYNTH, DefenceStatus.TESTING),
        ("data_exfiltration", GenerationStrategy.HYBRID, DefenceStatus.PUBLISHED),
        ("privilege_escalation", GenerationStrategy.PATTERN_MATCH, DefenceStatus.TESTED),
    ]

    for cat, strat, stat in seed_defs:
        dtype, code, config = _generate_defence_code(cat, strat)
        compat = _check_framework_compat(dtype)
        d = CatalogueDefence(
            name=f"Auto-{cat.replace('_', '-').title()}-Guard",
            description=f"Autonomously generated defence for {cat} vulnerabilities.",
            target_category=cat,
            defence_type=dtype,
            generation_strategy=strat,
            code_snippet=code,
            config=config,
            compatible_frameworks=compat,
            status=stat,
            version="1.0.0" if stat == DefenceStatus.PUBLISHED else "0.1.0",
        )

        # Simulate test results for non-draft
        if stat != DefenceStatus.DRAFT:
            result = _run_test_suite(d, 200, 200)
            d.test_results.append(result)
            d.detection_rate = result["detection_rate"]
            d.false_positive_rate = result["false_positive_rate"]
            d.latency_ms = result["latency_ms"]
            d.efficacy_score = result["efficacy_score"]

        if stat == DefenceStatus.PUBLISHED:
            d.published_at = _now().isoformat()
            entry = RegistryEntry(
                defence_id=d.id,
                name=d.name,
                category=d.target_category,
                version=d.version,
                efficacy_score=d.efficacy_score,
                detection_rate=d.detection_rate,
                false_positive_rate=d.false_positive_rate,
                latency_ms=d.latency_ms,
                compatible_frameworks=d.compatible_frameworks,
                published_at=d.published_at,
            )
            REGISTRY.append(entry)
            CHANGELOG.append({
                "defence_id": d.id,
                "name": d.name,
                "action": "published",
                "version": d.version,
                "timestamp": d.published_at,
            })

        DEFENCES[d.id] = d


_seed()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "self-evolving-defence-catalogue",
        "version": "1.0.0",
        "defences": len(DEFENCES),
        "published": len(REGISTRY),
        "categories_covered": len({d.target_category for d in DEFENCES.values()}),
    }


# ---- Generate ------------------------------------------------------------

@app.post("/v1/catalogue/generate", status_code=status.HTTP_201_CREATED)
async def generate_defence(req: GenerateRequest):
    if req.category not in AVE_CATEGORIES:
        raise HTTPException(400, f"Invalid category. Must be one of: {AVE_CATEGORIES}")

    dtype, code, config = _generate_defence_code(req.category, req.strategy)
    compat = _check_framework_compat(dtype)

    d = CatalogueDefence(
        name=f"Auto-{req.category.replace('_', '-').title()}-Guard-{uuid.uuid4().hex[:4]}",
        description=f"Generated for: {req.vulnerability_title}. {req.description}",
        target_category=req.category,
        defence_type=dtype,
        generation_strategy=req.strategy,
        code_snippet=code,
        config=config,
        compatible_frameworks=compat,
    )
    DEFENCES[d.id] = d

    CHANGELOG.append({
        "defence_id": d.id,
        "name": d.name,
        "action": "generated",
        "version": d.version,
        "strategy": req.strategy.value,
        "timestamp": _now().isoformat(),
    })

    return {
        "id": d.id,
        "name": d.name,
        "defence_type": dtype,
        "strategy": req.strategy.value,
        "compatible_frameworks": compat,
        "status": d.status.value,
    }


# ---- List / Get ----------------------------------------------------------

@app.get("/v1/catalogue/defences")
async def list_defences(
    category: Optional[str] = None,
    status_filter: Optional[DefenceStatus] = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=500),
):
    defs = list(DEFENCES.values())
    if category:
        defs = [d for d in defs if d.target_category == category]
    if status_filter:
        defs = [d for d in defs if d.status == status_filter]
    defs.sort(key=lambda d: d.updated_at, reverse=True)
    return {"count": len(defs[:limit]), "defences": [d.dict() for d in defs[:limit]]}


@app.get("/v1/catalogue/defences/{def_id}")
async def get_defence(def_id: str):
    if def_id not in DEFENCES:
        raise HTTPException(404, "Defence not found")
    return DEFENCES[def_id].dict()


# ---- Test ----------------------------------------------------------------

@app.post("/v1/catalogue/defences/{def_id}/test")
async def test_defence(def_id: str, req: TestRequest):
    if def_id not in DEFENCES:
        raise HTTPException(404, "Defence not found")
    d = DEFENCES[def_id]
    d.status = DefenceStatus.TESTING
    result = _run_test_suite(d, req.attack_samples, req.benign_samples)
    d.test_results.append(result)
    d.detection_rate = result["detection_rate"]
    d.false_positive_rate = result["false_positive_rate"]
    d.latency_ms = result["latency_ms"]
    d.efficacy_score = result["efficacy_score"]
    d.status = DefenceStatus.TESTED if result["verdict"] == "pass" else DefenceStatus.FAILED
    d.updated_at = _now().isoformat()

    CHANGELOG.append({
        "defence_id": d.id,
        "name": d.name,
        "action": "tested",
        "verdict": result["verdict"],
        "efficacy": result["efficacy_score"],
        "timestamp": _now().isoformat(),
    })

    return result


# ---- Publish -------------------------------------------------------------

@app.post("/v1/catalogue/defences/{def_id}/publish")
async def publish_defence(def_id: str):
    if def_id not in DEFENCES:
        raise HTTPException(404, "Defence not found")
    d = DEFENCES[def_id]
    if d.status not in (DefenceStatus.TESTED,):
        raise HTTPException(409, f"Defence must be in TESTED status to publish (current: {d.status.value})")
    if d.efficacy_score < 0.5:
        raise HTTPException(409, f"Efficacy score {d.efficacy_score} is below minimum 0.5 for publishing")

    d.status = DefenceStatus.PUBLISHED
    d.version = _bump_version(d.version)
    d.published_at = _now().isoformat()
    d.updated_at = _now().isoformat()

    entry = RegistryEntry(
        defence_id=d.id,
        name=d.name,
        category=d.target_category,
        version=d.version,
        efficacy_score=d.efficacy_score,
        detection_rate=d.detection_rate,
        false_positive_rate=d.false_positive_rate,
        latency_ms=d.latency_ms,
        compatible_frameworks=d.compatible_frameworks,
        published_at=d.published_at,
    )
    REGISTRY.append(entry)

    CHANGELOG.append({
        "defence_id": d.id,
        "name": d.name,
        "action": "published",
        "version": d.version,
        "timestamp": d.published_at,
    })

    return {"published": True, "id": d.id, "version": d.version, "efficacy": d.efficacy_score}


# ---- Registry ------------------------------------------------------------

@app.get("/v1/catalogue/registry")
async def get_registry(category: Optional[str] = None):
    entries = REGISTRY[:]
    if category:
        entries = [e for e in entries if e.category == category]
    return {"count": len(entries), "registry": [e.dict() for e in entries]}


# ---- Coverage ------------------------------------------------------------

@app.get("/v1/catalogue/coverage")
async def coverage_analysis():
    by_cat: dict[str, list[CatalogueDefence]] = defaultdict(list)
    for d in DEFENCES.values():
        by_cat[d.target_category].append(d)

    covered = [c for c in AVE_CATEGORIES if c in by_cat]
    uncovered = [c for c in AVE_CATEGORIES if c not in by_cat]

    cat_details: dict[str, dict[str, Any]] = {}
    for cat in AVE_CATEGORIES:
        defs = by_cat.get(cat, [])
        published = [d for d in defs if d.status == DefenceStatus.PUBLISHED]
        best = max((d.efficacy_score for d in defs), default=0.0)
        cat_details[cat] = {
            "total_defences": len(defs),
            "published": len(published),
            "best_efficacy": round(best, 4),
            "covered": len(defs) > 0,
        }

    return CoverageReport(
        total_categories=len(AVE_CATEGORIES),
        covered_categories=len(covered),
        uncovered_categories=uncovered,
        coverage_ratio=round(len(covered) / len(AVE_CATEGORIES), 4),
        by_category=cat_details,
    )


# ---- Evaluate All --------------------------------------------------------

@app.post("/v1/catalogue/evaluate")
async def evaluate_all():
    """Re-test all non-deprecated defences and return summary."""
    results: list[dict[str, Any]] = []
    for d in DEFENCES.values():
        if d.status == DefenceStatus.DEPRECATED:
            continue
        result = _run_test_suite(d, 100, 100)
        d.test_results.append(result)
        d.detection_rate = result["detection_rate"]
        d.false_positive_rate = result["false_positive_rate"]
        d.latency_ms = result["latency_ms"]
        d.efficacy_score = result["efficacy_score"]
        d.updated_at = _now().isoformat()
        results.append({"id": d.id, "name": d.name, **result})

    return {"evaluated": len(results), "results": results}


# ---- Changelog -----------------------------------------------------------

@app.get("/v1/catalogue/changelog")
async def get_changelog(limit: int = Query(50, ge=1, le=500)):
    return {"count": len(CHANGELOG[-limit:]), "changelog": CHANGELOG[-limit:]}


# ---- Analytics -----------------------------------------------------------

@app.get("/v1/catalogue/analytics")
async def catalogue_analytics():
    defs = list(DEFENCES.values())
    by_status = Counter(d.status.value for d in defs)
    by_category = Counter(d.target_category for d in defs)
    by_strategy = Counter(d.generation_strategy.value for d in defs)

    efficacies = [d.efficacy_score for d in defs if d.efficacy_score > 0]
    avg_efficacy = round(statistics.mean(efficacies), 4) if efficacies else 0.0
    avg_detection = round(
        statistics.mean(d.detection_rate for d in defs if d.detection_rate > 0), 4
    ) if any(d.detection_rate > 0 for d in defs) else 0.0
    avg_fpr = round(
        statistics.mean(d.false_positive_rate for d in defs if d.false_positive_rate > 0), 4
    ) if any(d.false_positive_rate > 0 for d in defs) else 0.0

    return {
        "total_defences": len(defs),
        "published": sum(1 for d in defs if d.status == DefenceStatus.PUBLISHED),
        "by_status": dict(by_status),
        "by_category": dict(by_category),
        "by_strategy": dict(by_strategy),
        "avg_efficacy": avg_efficacy,
        "avg_detection_rate": avg_detection,
        "avg_false_positive_rate": avg_fpr,
        "registry_entries": len(REGISTRY),
        "changelog_entries": len(CHANGELOG),
        "category_coverage": round(
            len({d.target_category for d in defs}) / len(AVE_CATEGORIES), 4
        ),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8800)
