#!/usr/bin/env python3
"""
Annual AVE Report — Data Generation Script

Reads all AVE cards from the database and generates the statistical
tables and figures for the annual report.

Usage:
    python generate_report_data.py --year 2025
    python generate_report_data.py --year 2025 --output-dir ./data/
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# ---------- Configuration ----------
DEFAULT_AVE_DB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "ave-database"
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data"


def load_all_cards(db_path: Path) -> list[dict[str, Any]]:
    """Load all AVE card JSON files from the database."""
    cards = []
    for card_file in sorted(db_path.rglob("*.json")):
        if "schema" in card_file.name.lower():
            continue
        try:
            with open(card_file, "r", encoding="utf-8") as f:
                card = json.load(f)
                if "ave_id" in card:
                    cards.append(card)
        except (json.JSONDecodeError, KeyError):
            continue
    return cards


def filter_published(cards: list[dict]) -> list[dict]:
    """Filter to published/proven cards only."""
    valid_statuses = {"published", "proven", "proven_mitigated", "theoretical", "not_proven"}
    return [c for c in cards if c.get("status") in valid_statuses]


def compute_category_stats(cards: list[dict]) -> list[dict]:
    """Compute per-category statistics."""
    categories = Counter(c.get("category", "unknown") for c in cards)
    total = len(cards)

    results = []
    for rank, (cat, count) in enumerate(categories.most_common(), 1):
        cat_cards = [c for c in cards if c.get("category") == cat]
        avss_scores = [
            c["avss_score"]["overall_score"]
            for c in cat_cards
            if c.get("avss_score", {}).get("overall_score") is not None
        ]
        avg_avss = sum(avss_scores) / len(avss_scores) if avss_scores else 0

        results.append({
            "rank": rank,
            "category": cat,
            "count": count,
            "percentage": round(count / total * 100, 1) if total else 0,
            "avg_avss": round(avg_avss, 1),
        })

    return results


def compute_severity_stats(cards: list[dict]) -> list[dict]:
    """Compute severity distribution."""
    severity_order = ["critical", "high", "medium", "low", "informational"]
    severities = Counter(c.get("severity", "unknown") for c in cards)
    total = len(cards)

    return [
        {
            "severity": sev,
            "count": severities.get(sev, 0),
            "percentage": round(severities.get(sev, 0) / total * 100, 1) if total else 0,
        }
        for sev in severity_order
    ]


def compute_framework_stats(cards: list[dict]) -> list[dict]:
    """Compute agent framework mention statistics."""
    framework_counter: Counter = Counter()
    for card in cards:
        env = card.get("environment", {})
        frameworks = env.get("agent_frameworks", []) or env.get("frameworks", []) or []
        for fw in frameworks:
            framework_counter[fw] += 1

    total = len(cards)
    return [
        {
            "framework": fw,
            "count": count,
            "percentage": round(count / total * 100, 1) if total else 0,
        }
        for fw, count in framework_counter.most_common(10)
    ]


def compute_timeline_stats(cards: list[dict]) -> list[dict]:
    """Compute quarterly publication timeline."""
    quarters: Counter = Counter()
    for card in cards:
        date = card.get("date_published", "")
        if len(date) >= 7:
            month = int(date[5:7])
            year = date[:4]
            quarter = f"{year}-Q{(month - 1) // 3 + 1}"
            quarters[quarter] += 1

    cumulative = 0
    results = []
    for quarter in sorted(quarters.keys()):
        cumulative += quarters[quarter]
        results.append({
            "quarter": quarter,
            "published": quarters[quarter],
            "cumulative": cumulative,
        })

    return results


def compute_mitre_stats(cards: list[dict]) -> list[dict]:
    """Compute MITRE ATT&CK technique distribution."""
    techniques = Counter(c.get("mitre_mapping", "unknown") for c in cards)
    return [
        {"technique": tech, "count": count}
        for tech, count in techniques.most_common(10)
    ]


def compute_cwe_stats(cards: list[dict]) -> list[dict]:
    """Compute CWE distribution."""
    cwes = Counter(c.get("cwe_mapping", "unknown") for c in cards)
    return [
        {"cwe": cwe, "count": count}
        for cwe, count in cwes.most_common(10)
    ]


def compute_summary(cards: list[dict]) -> dict:
    """Compute summary metrics."""
    avss_scores = [
        c["avss_score"]["overall_score"]
        for c in cards
        if c.get("avss_score", {}).get("overall_score") is not None
    ]
    contributors = set(c.get("contributor", "") for c in cards if c.get("contributor"))
    categories_used = set(c.get("category") for c in cards)

    return {
        "total_cards": len(cards),
        "avg_avss": round(sum(avss_scores) / len(avss_scores), 1) if avss_scores else 0,
        "max_avss": max(avss_scores) if avss_scores else 0,
        "min_avss": min(avss_scores) if avss_scores else 0,
        "unique_contributors": len(contributors),
        "categories_represented": len(categories_used),
        "critical_count": sum(1 for c in cards if c.get("severity") == "critical"),
        "high_count": sum(1 for c in cards if c.get("severity") == "high"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Annual AVE Report data")
    parser.add_argument(
        "--year", type=int, default=2025, help="Report year"
    )
    parser.add_argument(
        "--db-path", type=Path, default=DEFAULT_AVE_DB_PATH,
        help="Path to AVE database directory"
    )
    parser.add_argument(
        "--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
        help="Output directory for generated data files"
    )

    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading AVE cards from {args.db_path}...")
    all_cards = load_all_cards(args.db_path)
    print(f"  Total cards loaded: {len(all_cards)}")

    cards = filter_published(all_cards)
    print(f"  Published/proven cards: {len(cards)}")

    # Generate all stats
    data = {
        "report_year": args.year,
        "data_freeze": f"{args.year}-12-31",
        "summary": compute_summary(cards),
        "category_stats": compute_category_stats(cards),
        "severity_stats": compute_severity_stats(cards),
        "framework_stats": compute_framework_stats(cards),
        "timeline_stats": compute_timeline_stats(cards),
        "mitre_stats": compute_mitre_stats(cards),
        "cwe_stats": compute_cwe_stats(cards),
    }

    # Write output
    output_file = args.output_dir / f"report-data-{args.year}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"\nReport data written to {output_file}")
    print(f"\nSummary:")
    for key, value in data["summary"].items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
