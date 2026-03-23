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

All responses use the public (redacted) card format — no internal
mechanism details, evidence hashes, or defence implementations.

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
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


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
        self.version = "2.0.0"

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

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    # Load database
    db = CardDatabase(config.db_path)

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
                "github": "https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database",
                "docs_site": "https://nail-institute-for-agentic-security.github.io/ave-database/",
            },
        }

    # ── Health ────────────────────────────────────────────────────────────

    @app.get("/health", tags=["Info"])
    async def health() -> dict[str, Any]:
        """Health check."""
        return {
            "status": "healthy",
            "cards_loaded": len(db.cards),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ── List Cards ────────────────────────────────────────────────────────

    @app.get("/ave", tags=["Cards"])
    async def list_cards(
        offset: int = Query(0, ge=0, description="Pagination offset"),
        limit: int = Query(50, ge=1, le=200, description="Page size"),
        sort: str = Query("ave_id", description="Sort by: ave_id, severity, category"),
    ) -> dict[str, Any]:
        """List all AVE cards with pagination."""
        cards, total = db.list_all(offset=offset, limit=limit, sort_by=sort)
        return {
            "cards": cards,
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < total,
        }

    # ── Get Card ──────────────────────────────────────────────────────────

    @app.get("/ave/{ave_id}", tags=["Cards"])
    async def get_card(ave_id: str) -> dict[str, Any]:
        """Get a single AVE card by ID."""
        card = db.get(ave_id.upper())
        if card is None:
            raise HTTPException(
                status_code=404,
                detail=f"Card {ave_id} not found",
            )
        return card

    # ── Search ────────────────────────────────────────────────────────────

    @app.get("/ave/search", tags=["Cards"])
    async def search_cards(
        q: str = Query(..., min_length=2, description="Search query"),
    ) -> dict[str, Any]:
        """Full-text search across all card fields."""
        results = db.search(q)
        return {
            "query": q,
            "results": results,
            "total": len(results),
        }

    # ── By Category ───────────────────────────────────────────────────────

    @app.get("/ave/category/{category}", tags=["Cards"])
    async def cards_by_category(category: str) -> dict[str, Any]:
        """Get all cards in a specific category."""
        cards = db.by_category(category)
        return {
            "category": category,
            "cards": cards,
            "total": len(cards),
        }

    # ── By Severity ───────────────────────────────────────────────────────

    @app.get("/ave/severity/{severity}", tags=["Cards"])
    async def cards_by_severity(severity: str) -> dict[str, Any]:
        """Get all cards with a specific severity level."""
        cards = db.by_severity(severity)
        return {
            "severity": severity,
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

    return app


# ═══════════════════════════════════════════════════════════════════════════
# Entrypoint
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    """Run the public API server."""
    import uvicorn

    config = PublicAPIConfig()
    print(f"🌐 NAIL AVE Public API v{config.version}")
    print(f"   Cards loaded: {len(CardDatabase(config.db_path).cards)}")
    print(f"   Listening: http://{config.host}:{config.port}")
    print(f"   Docs:      http://{config.host}:{config.port}/docs")

    uvicorn.run(
        create_app(config),
        host=config.host,
        port=config.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
