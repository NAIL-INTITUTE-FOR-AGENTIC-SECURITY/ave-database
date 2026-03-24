"""
public_api — Read-only public AVE lookup API for the community.

A lightweight FastAPI server that exposes a subset of the AVE database
for public consumption. No authentication required. Read-only.

Endpoints:
    GET  /                          — API information + links
    GET  /health                    — Health check
    GET  /ave                       — List all AVE cards (paginated)
    GET  /ave/{ave_id}              — Get a single card by ID
    GET  /ave/search?q=...          — Full-text search across cards
    GET  /ave/category/{category}   — Cards filtered by category
    GET  /ave/stats                 — Database statistics
    GET  /ave/taxonomy              — Category taxonomy tree
    GET  /ave/recent                — Most recently added/updated cards
    GET  /ave/severity/{severity}   — Cards filtered by severity
    GET  /metrics                   — Request metrics (counts, latency, errors)

All responses use the public (redacted) card format — no internal
mechanism details, evidence hashes, or defence implementations.

Hardened with:
    - Per-IP sliding-window rate limiting (in-memory)
    - Request ID tracing (X-Request-ID on every response)
    - Structured JSON access logging with latency tracking
    - Security headers (HSTS, CSP, X-Content-Type-Options, etc.)
    - Global exception handler with safe error responses
    - Input validation hardening (path traversal, query length)
    - /metrics endpoint for observability

Designed to be deployed on the public internet (GitHub Pages proxy,
Railway, Fly.io, etc.) alongside the docs site.

Usage:
    python -m public_api.server              # Default: 0.0.0.0:8080
    PUBLIC_API_PORT=9400 python -m public_api.server

Environment Variables:
    PUBLIC_API_HOST       — Bind host (default: 0.0.0.0)
    PUBLIC_API_PORT       — Bind port (default: 8080)
    PUBLIC_API_DB_PATH    — Path to ave-database/ (default: auto-detect)
    PUBLIC_API_CORS       — Comma-separated CORS origins (default: *)
    RATE_LIMIT_RPM        — Requests per minute per IP (default: 60)
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import uuid
from collections import Counter, defaultdict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from starlette.middleware.base import BaseHTTPMiddleware


# ═══════════════════════════════════════════════════════════════════════════
# Structured Logging
# ═══════════════════════════════════════════════════════════════════════════

logger = logging.getLogger("nail.api")

# JSON formatter for structured logging in production
class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "msg": record.getMessage(),
        }
        # Attach extras (request_id, latency, etc.)
        for key in ("request_id", "method", "path", "status", "latency_ms",
                     "client_ip", "user_agent"):
            val = getattr(record, key, None)
            if val is not None:
                payload[key] = val
        return json.dumps(payload, default=str)


def _configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(_JSONFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    # Quieten noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


_configure_logging()


# ═══════════════════════════════════════════════════════════════════════════
# Rate Limiter — sliding-window in-memory (no external deps)
# ═══════════════════════════════════════════════════════════════════════════

class SlidingWindowRateLimiter:
    """Per-IP sliding-window rate limiter.

    Stores timestamps of recent requests per client IP in a deque.
    Thread-safe for single-process async (which is how uvicorn runs).
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def is_allowed(self, client_ip: str) -> tuple[bool, dict[str, str]]:
        """Check whether *client_ip* may proceed.

        Returns (allowed, headers) where *headers* always includes
        X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset.
        """
        now = time.monotonic()
        window = self._hits[client_ip]

        # Evict entries older than the window
        while window and window[0] <= now - self.window:
            window.popleft()

        remaining = max(0, self.max_requests - len(window))
        reset_at = int(window[0] + self.window - now) if window else self.window

        headers = {
            "X-RateLimit-Limit": str(self.max_requests),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_at),
        }

        if len(window) >= self.max_requests:
            return False, headers

        window.append(now)
        # Update remaining after recording this hit
        headers["X-RateLimit-Remaining"] = str(remaining - 1 if remaining else 0)
        return True, headers

    def cleanup(self) -> None:
        """Prune stale IPs (call periodically)."""
        now = time.monotonic()
        stale = [ip for ip, dq in self._hits.items()
                 if not dq or dq[-1] <= now - self.window * 2]
        for ip in stale:
            del self._hits[ip]


# ═══════════════════════════════════════════════════════════════════════════
# Metrics Collector
# ═══════════════════════════════════════════════════════════════════════════

class MetricsCollector:
    """Lightweight in-memory request metrics."""

    def __init__(self) -> None:
        self.started_at = time.monotonic()
        self.start_wall = datetime.now(timezone.utc)
        self.total_requests: int = 0
        self.status_counts: Counter[int] = Counter()
        self.endpoint_counts: Counter[str] = Counter()
        self.rate_limited: int = 0
        self._latencies: deque[float] = deque(maxlen=10_000)  # last 10k

    def record(self, path: str, status: int, latency_ms: float) -> None:
        self.total_requests += 1
        self.status_counts[status] += 1
        self.endpoint_counts[path] += 1
        self._latencies.append(latency_ms)

    def record_rate_limit(self) -> None:
        self.rate_limited += 1
        self.total_requests += 1
        self.status_counts[429] += 1

    def snapshot(self) -> dict[str, Any]:
        latencies = sorted(self._latencies) if self._latencies else [0]
        n = len(latencies)
        uptime_s = time.monotonic() - self.started_at

        return {
            "uptime_seconds": round(uptime_s, 1),
            "started_at": self.start_wall.isoformat(),
            "total_requests": self.total_requests,
            "requests_per_minute": round(self.total_requests / max(uptime_s / 60, 1), 2),
            "status_codes": dict(self.status_counts.most_common(10)),
            "top_endpoints": dict(self.endpoint_counts.most_common(10)),
            "rate_limited_count": self.rate_limited,
            "latency_ms": {
                "p50": round(latencies[n // 2], 2),
                "p95": round(latencies[int(n * 0.95)], 2),
                "p99": round(latencies[int(n * 0.99)], 2),
                "max": round(latencies[-1], 2),
            },
        }


# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════

class PublicAPIConfig:
    """Configuration from environment variables."""

    def __init__(self) -> None:
        self.host = os.getenv("PUBLIC_API_HOST", "0.0.0.0")
        self.port = int(os.getenv("PUBLIC_API_PORT", "8080"))
        self.cors_origins = os.getenv("PUBLIC_API_CORS", "*").split(",")
        self.db_path = self._resolve_db_path()
        self.rate_limit_rpm = int(os.getenv("RATE_LIMIT_RPM", "60"))
        self.version = "2.1.0"

    @staticmethod
    def _resolve_db_path() -> Path:
        """Resolve the path to ave-database/."""
        env_path = os.getenv("PUBLIC_API_DB_PATH")
        if env_path:
            return Path(env_path)

        # Auto-detect: look for ave-database/ relative to common locations
        candidates = [
            Path(__file__).parent.parent / "ave-database",
            Path.cwd() / "ave-database",
            Path.cwd() / "public-repo" / "ave-database",
            Path(__file__).parent.parent.parent / "public-repo" / "ave-database",
        ]
        for candidate in candidates:
            if candidate.is_dir() and (candidate / "cards").is_dir():
                return candidate.resolve()

        raise FileNotFoundError(
            "Cannot find ave-database/ directory. "
            "Set PUBLIC_API_DB_PATH environment variable."
        )


# ═══════════════════════════════════════════════════════════════════════════
# Card Database (in-memory, loaded at startup)
# ═══════════════════════════════════════════════════════════════════════════

class CardDatabase:
    """
    In-memory read-only card database.

    Loads all public (redacted) JSON cards at startup for fast lookups.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.cards: dict[str, dict[str, Any]] = {}
        self.index: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """Load all cards and index from disk."""
        cards_dir = self.db_path / "cards"
        if not cards_dir.is_dir():
            raise FileNotFoundError(f"Cards directory not found: {cards_dir}")

        # Load individual card JSON files
        for card_dir in sorted(cards_dir.iterdir()):
            if not card_dir.is_dir():
                continue
            json_file = card_dir / f"{card_dir.name}.json"
            if json_file.exists():
                try:
                    data = json.loads(json_file.read_text())
                    ave_id = data.get("ave_id", card_dir.name)
                    # Strip any remaining internal fields for safety
                    self.cards[ave_id] = self._sanitise(data)
                except (json.JSONDecodeError, OSError):
                    continue

        # Load index if available
        index_file = self.db_path / "index.json"
        if index_file.exists():
            try:
                self.index = json.loads(index_file.read_text())
            except (json.JSONDecodeError, OSError):
                self.index = {}

    @staticmethod
    def _sanitise(card: dict[str, Any]) -> dict[str, Any]:
        """
        Remove any fields that should not be in the public API.

        The cards in public-repo are already redacted by ave.redact,
        but we double-check here as a defence-in-depth measure.
        """
        sensitive_keys = {
            "internal_notes",
            "private_evidence",
            "poc_script",
            "poc_code",
            "raw_experiment_data",
            "defence_implementation",
            "api_keys",
            "credentials",
        }
        return {k: v for k, v in card.items() if k not in sensitive_keys}

    def get(self, ave_id: str) -> dict[str, Any] | None:
        """Get a card by AVE ID."""
        return self.cards.get(ave_id)

    def list_all(
        self,
        offset: int = 0,
        limit: int = 50,
        sort_by: str = "ave_id",
    ) -> tuple[list[dict[str, Any]], int]:
        """List cards with pagination."""
        all_cards = list(self.cards.values())

        # Sort
        if sort_by == "severity":
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            all_cards.sort(
                key=lambda c: severity_order.get(
                    c.get("severity", "medium").lower(), 5
                )
            )
        elif sort_by == "category":
            all_cards.sort(key=lambda c: c.get("category", ""))
        else:
            all_cards.sort(key=lambda c: c.get("ave_id", ""))

        total = len(all_cards)
        return all_cards[offset : offset + limit], total

    def search(self, query: str) -> list[dict[str, Any]]:
        """Full-text search across card fields."""
        q = query.lower()
        results = []
        for card in self.cards.values():
            searchable = json.dumps(card).lower()
            if q in searchable:
                results.append(card)
        return results

    def by_category(self, category: str) -> list[dict[str, Any]]:
        """Filter cards by category."""
        cat_lower = category.lower()
        return [
            c for c in self.cards.values()
            if c.get("category", "").lower() == cat_lower
        ]

    def by_severity(self, severity: str) -> list[dict[str, Any]]:
        """Filter cards by severity."""
        sev_lower = severity.lower()
        return [
            c for c in self.cards.values()
            if c.get("severity", "").lower() == sev_lower
        ]

    def stats(self) -> dict[str, Any]:
        """Compute database statistics."""
        cards = list(self.cards.values())
        categories = Counter(c.get("category", "unknown") for c in cards)
        severities = Counter(c.get("severity", "unknown") for c in cards)
        statuses = Counter(c.get("status", "unknown") for c in cards)

        return {
            "total_cards": len(cards),
            "categories": dict(categories.most_common()),
            "severities": dict(severities.most_common()),
            "statuses": dict(statuses.most_common()),
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }

    def taxonomy(self) -> dict[str, list[str]]:
        """Build category taxonomy with card IDs."""
        tax: dict[str, list[str]] = {}
        for ave_id, card in sorted(self.cards.items()):
            cat = card.get("category", "uncategorised")
            tax.setdefault(cat, []).append(ave_id)
        return tax

    def recent(self, limit: int = 10) -> list[dict[str, Any]]:
        """Most recently added/updated cards."""
        cards = list(self.cards.values())
        # Sort by date_reported descending, fall back to ave_id
        cards.sort(
            key=lambda c: c.get("date_reported", "1970-01-01"),
            reverse=True,
        )
        return cards[:limit]


# ═══════════════════════════════════════════════════════════════════════════
# FastAPI Application
# ═══════════════════════════════════════════════════════════════════════════

def create_app(config: PublicAPIConfig | None = None) -> FastAPI:
    """Create the public API FastAPI application."""
    if config is None:
        config = PublicAPIConfig()

    app = FastAPI(
        title="NAIL Institute — AVE Public API",
        description=(
            "Read-only public API for the Agentic Vulnerabilities & Exposures "
            "(AVE) database. Browse, search, and lookup AI agent vulnerability "
            "cards. No authentication required."
        ),
        version=config.version,
        docs_url="/docs",
        redoc_url="/redoc",
        license_info={
            "name": "CC-BY-SA-4.0",
            "url": "https://creativecommons.org/licenses/by-sa/4.0/",
        },
        contact={
            "name": "NAIL Institute",
            "url": "https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY",
        },
    )

    # ── Shared state ──────────────────────────────────────────────────────

    rate_limiter = SlidingWindowRateLimiter(
        max_requests=config.rate_limit_rpm, window_seconds=60,
    )
    metrics = MetricsCollector()

    # ── Middleware stack (order matters — outermost runs first) ────────────

    # 1. CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    # 2. Security + rate-limit + logging middleware (single pass)
    @app.middleware("http")
    async def hardening_middleware(request: Request, call_next) -> Response:  # noqa: ANN001
        request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex[:16])
        client_ip = _get_client_ip(request)
        start = time.monotonic()

        # ── Rate limiting ────────────────────────────────────────────
        allowed, rl_headers = rate_limiter.is_allowed(client_ip)
        if not allowed:
            metrics.record_rate_limit()
            logger.warning(
                "Rate limited",
                extra={"request_id": request_id, "client_ip": client_ip,
                       "path": request.url.path, "method": request.method,
                       "status": 429, "latency_ms": 0},
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please slow down.",
                         "retry_after": rl_headers.get("X-RateLimit-Reset", "60")},
                headers={**rl_headers, "Retry-After": rl_headers.get("X-RateLimit-Reset", "60"),
                         "X-Request-ID": request_id},
            )

        # ── Forward request ──────────────────────────────────────────
        response: Response = await call_next(request)
        latency_ms = (time.monotonic() - start) * 1000

        # ── Record metrics ───────────────────────────────────────────
        metrics.record(request.url.path, response.status_code, latency_ms)

        # ── Security headers ─────────────────────────────────────────
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), interest-cohort=()"
        )
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        # Rate-limit headers on every response
        for k, v in rl_headers.items():
            response.headers[k] = v
        response.headers["X-Response-Time"] = f"{latency_ms:.1f}ms"

        # ── Structured access log ────────────────────────────────────
        logger.info(
            f"{request.method} {request.url.path} → {response.status_code} "
            f"({latency_ms:.1f}ms)",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "latency_ms": round(latency_ms, 2),
                "client_ip": client_ip,
                "user_agent": request.headers.get("user-agent", "-"),
            },
        )

        return response

    # ── Global exception handler ──────────────────────────────────────

    @app.exception_handler(Exception)
    async def _global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = request.headers.get("X-Request-ID", "unknown")
        logger.error(
            f"Unhandled exception: {exc!r}",
            extra={"request_id": request_id, "path": request.url.path,
                   "method": request.method},
            exc_info=True,
        )
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error",
                "request_id": request_id,
            },
            headers={"X-Request-ID": request_id},
        )

    # Load database
    db = CardDatabase(config.db_path)

    logger.info(
        f"NAIL AVE Public API v{config.version} ready — "
        f"{len(db.cards)} cards loaded, rate limit {config.rate_limit_rpm} rpm"
    )

    # ── Root ──────────────────────────────────────────────────────────────

    @app.get("/", tags=["Info"])
    async def root() -> dict[str, Any]:
        """API root — links and metadata."""
        return {
            "name": "NAIL Institute AVE Public API",
            "version": config.version,
            "description": (
                "Read-only public API for the Agentic Vulnerabilities "
                "& Exposures database."
            ),
            "total_cards": len(db.cards),
            "links": {
                "docs": "/docs",
                "redoc": "/redoc",
                "cards": "/ave",
                "search": "/ave/search?q=injection",
                "stats": "/ave/stats",
                "taxonomy": "/ave/taxonomy",
                "recent": "/ave/recent",
                "metrics": "/metrics",
                "github": "https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database",
                "docs_site": "https://nailinstitute.org",
            },
        }

    # ── Health ────────────────────────────────────────────────────────────

    @app.get("/health", tags=["Info"])
    async def health() -> dict[str, Any]:
        """Health check."""
        return {
            "status": "healthy",
            "version": config.version,
            "cards_loaded": len(db.cards),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ── Metrics ───────────────────────────────────────────────────────────

    @app.get("/metrics", tags=["Info"])
    async def get_metrics() -> dict[str, Any]:
        """Request metrics — counts, latency percentiles, error rates."""
        snap = metrics.snapshot()
        snap["cards_loaded"] = len(db.cards)
        snap["rate_limit_rpm"] = config.rate_limit_rpm
        return snap

    # ── List Cards ────────────────────────────────────────────────────────

    @app.get("/ave", tags=["Cards"])
    async def list_cards(
        offset: int = Query(0, ge=0, description="Pagination offset"),
        limit: int = Query(50, ge=1, le=200, description="Page size"),
        sort: str = Query("ave_id", description="Sort by: ave_id, severity, category"),
    ) -> dict[str, Any]:
        """List all AVE cards with pagination."""
        if sort not in ("ave_id", "severity", "category"):
            raise HTTPException(400, "Invalid sort field. Use: ave_id, severity, category")
        cards, total = db.list_all(offset=offset, limit=limit, sort_by=sort)
        return {
            "cards": cards,
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < total,
        }

    # ── Search ────────────────────────────────────────────────────────────
    # NOTE: Specific /ave/* routes MUST be registered before /ave/{ave_id}
    # to avoid the catch-all swallowing named paths.

    @app.get("/ave/search", tags=["Cards"])
    async def search_cards(
        q: str = Query(..., min_length=2, max_length=200,
                       description="Search query (2-200 chars)"),
    ) -> dict[str, Any]:
        """Full-text search across all card fields."""
        clean_q = _sanitise_query(q)
        results = db.search(clean_q)
        return {
            "query": clean_q,
            "results": results,
            "total": len(results),
        }

    # ── By Category ───────────────────────────────────────────────────────

    @app.get("/ave/category/{category}", tags=["Cards"])
    async def cards_by_category(category: str) -> dict[str, Any]:
        """Get all cards in a specific category."""
        clean_cat = _sanitise_path_segment(category)
        cards = db.by_category(clean_cat)
        return {
            "category": clean_cat,
            "cards": cards,
            "total": len(cards),
        }

    # ── By Severity ───────────────────────────────────────────────────────

    @app.get("/ave/severity/{severity}", tags=["Cards"])
    async def cards_by_severity(severity: str) -> dict[str, Any]:
        """Get all cards with a specific severity level."""
        sev = severity.lower().strip()
        if sev not in ("critical", "high", "medium", "low"):
            raise HTTPException(
                400, "Invalid severity. Use: critical, high, medium, low"
            )
        cards = db.by_severity(sev)
        return {
            "severity": sev,
            "cards": cards,
            "total": len(cards),
        }

    # ── Stats ─────────────────────────────────────────────────────────────

    @app.get("/ave/stats", tags=["Analytics"])
    async def database_stats() -> dict[str, Any]:
        """Database statistics — card counts by category, severity, status."""
        return db.stats()

    # ── Taxonomy ──────────────────────────────────────────────────────────

    @app.get("/ave/taxonomy", tags=["Analytics"])
    async def taxonomy() -> dict[str, Any]:
        """Category taxonomy tree with card IDs."""
        return {
            "taxonomy": db.taxonomy(),
            "total_categories": len(db.taxonomy()),
            "total_cards": len(db.cards),
        }

    # ── Recent ────────────────────────────────────────────────────────────

    @app.get("/ave/recent", tags=["Cards"])
    async def recent_cards(
        limit: int = Query(10, ge=1, le=50, description="Number of cards"),
    ) -> dict[str, Any]:
        """Most recently added or updated cards."""
        cards = db.recent(limit=limit)
        return {
            "cards": cards,
            "total": len(cards),
        }

    # ── Get Card (catch-all — MUST be last /ave route) ────────────────────

    @app.get("/ave/{ave_id}", tags=["Cards"])
    async def get_card(ave_id: str) -> dict[str, Any]:
        """Get a single AVE card by ID."""
        clean_id = _sanitise_ave_id(ave_id)
        card = db.get(clean_id)
        if card is None:
            raise HTTPException(
                status_code=404,
                detail=f"Card {clean_id} not found",
            )
        return card

    return app


# ═══════════════════════════════════════════════════════════════════════════
# Input Validation Helpers
# ═══════════════════════════════════════════════════════════════════════════

_AVE_ID_RE = re.compile(r"^AVE-\d{4}-\d{4}$", re.IGNORECASE)


def _sanitise_ave_id(raw: str) -> str:
    """Validate and normalise an AVE ID. Prevents path traversal."""
    clean = raw.strip().upper()
    if not _AVE_ID_RE.match(clean):
        raise HTTPException(400, "Invalid AVE ID format. Expected: AVE-YYYY-NNNN")
    return clean


def _sanitise_query(raw: str) -> str:
    """Strip dangerous characters from search queries."""
    # Allow alphanum, spaces, hyphens, underscores, dots
    return re.sub(r"[^\w\s\-.,]", "", raw).strip()


def _sanitise_path_segment(raw: str) -> str:
    """Sanitise a URL path segment (category names etc.)."""
    clean = raw.strip().replace("/", "").replace("\\", "").replace("..", "")
    if not clean or len(clean) > 100:
        raise HTTPException(400, "Invalid path segment")
    return clean


def _get_client_ip(request: Request) -> str:
    """Extract client IP, respecting proxy headers."""
    # Fly.io / Cloudflare forward the real IP
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


# ═══════════════════════════════════════════════════════════════════════════
# Entrypoint
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    """Run the public API server."""
    import uvicorn

    config = PublicAPIConfig()
    db = CardDatabase(config.db_path)
    print(f"🌐 NAIL AVE Public API v{config.version}")
    print(f"   Cards loaded:  {len(db.cards)}")
    print(f"   Rate limit:    {config.rate_limit_rpm} req/min per IP")
    print(f"   Listening:     http://{config.host}:{config.port}")
    print(f"   Docs:          http://{config.host}:{config.port}/docs")
    print(f"   Metrics:       http://{config.host}:{config.port}/metrics")

    uvicorn.run(
        create_app(config),
        host=config.host,
        port=config.port,
        log_level="info",
        # Slowloris protection — close idle connections after 30s
        timeout_keep_alive=30,
        # Limit request header size (16KB)
        h11_max_incomplete_event_size=16 * 1024,
    )


if __name__ == "__main__":
    main()
