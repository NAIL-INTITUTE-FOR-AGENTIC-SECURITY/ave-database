#!/usr/bin/env python3
"""
Portal Data Generator
=====================
Generates portal data JSON from AVE card files for the Cross-Model Study Portal.

Usage:
    python generate_portal_data.py

Reads from: ../ave-database/cards/*.json
Writes to:  data/portal_data.json
"""

from __future__ import annotations

import json
from pathlib import Path

BASE_DIR = Path(__file__).parent
CARDS_DIR = BASE_DIR.parent / "ave-database" / "cards"
OUTPUT_DIR = BASE_DIR / "data"


def load_cards() -> list[dict]:
    """Load all AVE card JSON files."""
    cards = []
    for card_file in sorted(CARDS_DIR.glob("*.json")):
        with open(card_file) as f:
            cards.append(json.load(f))
    return cards


def generate_category_stats(cards: list[dict]) -> dict:
    """Generate per-category statistics."""
    stats = {}
    for card in cards:
        cat = card.get("category", "unknown")
        if cat not in stats:
            stats[cat] = {"count": 0, "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
        stats[cat]["count"] += 1
        sev = card.get("severity", "medium").lower()
        if sev in stats[cat]["severities"]:
            stats[cat]["severities"][sev] += 1
    return stats


def generate_severity_distribution(cards: list[dict]) -> dict:
    """Generate overall severity distribution."""
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for card in cards:
        sev = card.get("severity", "medium").lower()
        if sev in dist:
            dist[sev] += 1
    return dist


def generate_card_summaries(cards: list[dict]) -> list[dict]:
    """Generate card summaries for the portal."""
    return [
        {
            "ave_id": card.get("ave_id", ""),
            "name": card.get("name", ""),
            "category": card.get("category", ""),
            "severity": card.get("severity", ""),
            "status": card.get("status", ""),
            "summary": card.get("summary", "")[:200],
            "mitre_mapping": card.get("mitre_mapping", ""),
            "cwe_mapping": card.get("cwe_mapping", ""),
            "date_published": card.get("date_published", ""),
            "defences_count": len(card.get("defences", [])),
            "references_count": len(card.get("references", []))
        }
        for card in cards
    ]


def main():
    """Generate portal data."""
    cards = load_cards()
    print(f"Loaded {len(cards)} AVE cards")

    portal_data = {
        "generated_at": __import__("datetime").datetime.now().isoformat(),
        "total_cards": len(cards),
        "severity_distribution": generate_severity_distribution(cards),
        "category_stats": generate_category_stats(cards),
        "cards": generate_card_summaries(cards)
    }

    OUTPUT_DIR.mkdir(exist_ok=True)
    output_file = OUTPUT_DIR / "portal_data.json"
    with open(output_file, "w") as f:
        json.dump(portal_data, f, indent=2)

    print(f"Portal data written to {output_file}")
    print(f"  Categories: {len(portal_data['category_stats'])}")
    print(f"  Severities: {portal_data['severity_distribution']}")


if __name__ == "__main__":
    main()
