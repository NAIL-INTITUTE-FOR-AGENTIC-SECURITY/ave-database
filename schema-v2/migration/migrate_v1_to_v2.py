#!/usr/bin/env python3
"""AVE Card Migration Tool: v1.0.0 → v2.0.0

Migrates AVE card JSON files from schema v1.0.0 to v2.0.0.
This is a non-destructive, backwards-compatible migration that:
  - Updates _meta.schema_version to "2.0.0"
  - Adds _meta.migrated_from, migration_date, v2_fields_populated
  - Optionally enriches multi_agent data from environment.multi_agent flag

Usage:
  python migrate_v1_to_v2.py --input cards/ --output cards/ --in-place
  python migrate_v1_to_v2.py --input cards/ --output cards-v2/
  python migrate_v1_to_v2.py --input cards/ --enrich-multi-agent
  python migrate_v1_to_v2.py --input cards/ --rollback
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


V1_VERSION = "1.0.0"
V2_VERSION = "2.0.0"
V2_FIELD_GROUPS = [
    "multi_agent", "temporal", "composites", "attack_graph",
    "provenance", "affected_components", "counterfactual",
    "regulatory_impact",
]


def load_card(path: Path) -> dict:
    """Load a JSON card file."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_card(path: Path, card: dict) -> None:
    """Save a JSON card file with consistent formatting."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(card, f, indent=2, ensure_ascii=False)
        f.write("\n")


def migrate_card(card: dict, *, enrich_multi_agent: bool = False) -> dict:
    """Migrate a single card from v1 to v2."""
    meta = card.get("_meta", {})

    # Skip if already v2
    if meta.get("schema_version") == V2_VERSION:
        return card

    # Update meta
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta["schema_version"] = V2_VERSION
    meta["migrated_from"] = meta.get("schema_version", V1_VERSION)
    meta["migration_date"] = now

    # Track which v2 fields are populated
    populated = [f for f in V2_FIELD_GROUPS if f in card and card[f] is not None]
    meta["v2_fields_populated"] = populated
    card["_meta"] = meta

    # Optional: enrich multi_agent from environment flag
    if enrich_multi_agent and card.get("environment", {}).get("multi_agent"):
        if "multi_agent" not in card:
            card["multi_agent"] = {
                "topology": "flat",
                "agent_count_min": 2,
                "agent_count_max": None,
                "roles_affected": ["worker"],
                "propagation_pattern": "lateral",
                "isolation_bypass": False,
                "cross_framework": False,
            }
            meta["v2_fields_populated"].append("multi_agent")

    return card


def rollback_card(card: dict) -> dict:
    """Rollback a v2 card to v1."""
    meta = card.get("_meta", {})
    meta["schema_version"] = V1_VERSION
    meta.pop("migrated_from", None)
    meta.pop("migration_date", None)
    meta.pop("v2_fields_populated", None)
    card["_meta"] = meta

    # Remove all v2 field groups
    for field in V2_FIELD_GROUPS:
        card.pop(field, None)

    return card


def find_cards(input_dir: Path) -> list[Path]:
    """Find all JSON card files in a directory."""
    cards = sorted(input_dir.glob("AVE-*.json"))
    if not cards:
        # Try nested structure
        cards = sorted(input_dir.glob("**/AVE-*.json"))
    return cards


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Migrate AVE cards from v1.0.0 to v2.0.0"
    )
    parser.add_argument(
        "--input", "-i", required=True, type=Path,
        help="Input directory containing AVE card JSON files"
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=None,
        help="Output directory (defaults to input directory)"
    )
    parser.add_argument(
        "--in-place", action="store_true",
        help="Modify files in place (output = input)"
    )
    parser.add_argument(
        "--enrich-multi-agent", action="store_true",
        help="Add multi_agent v2 field to cards with environment.multi_agent=true"
    )
    parser.add_argument(
        "--rollback", action="store_true",
        help="Rollback v2 cards to v1"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be done without writing files"
    )

    args = parser.parse_args()

    if args.in_place:
        args.output = args.input
    elif args.output is None:
        parser.error("--output is required unless --in-place is set")

    if not args.input.is_dir():
        print(f"Error: {args.input} is not a directory", file=sys.stderr)
        return 1

    args.output.mkdir(parents=True, exist_ok=True)

    cards = find_cards(args.input)
    if not cards:
        print(f"No AVE card files found in {args.input}", file=sys.stderr)
        return 1

    print(f"Found {len(cards)} card(s) in {args.input}")

    migrated = 0
    skipped = 0
    errors = 0

    for card_path in cards:
        try:
            card = load_card(card_path)
            ave_id = card.get("ave_id", card_path.stem)

            if args.rollback:
                if card.get("_meta", {}).get("schema_version") != V2_VERSION:
                    skipped += 1
                    continue
                card = rollback_card(card)
                action = "rolled back"
            else:
                if card.get("_meta", {}).get("schema_version") == V2_VERSION:
                    skipped += 1
                    continue
                card = migrate_card(
                    card, enrich_multi_agent=args.enrich_multi_agent
                )
                action = "migrated"

            out_path = args.output / card_path.name
            if args.dry_run:
                print(f"  [DRY RUN] {ave_id}: would be {action}")
            else:
                save_card(out_path, card)
                print(f"  ✅ {ave_id}: {action}")
            migrated += 1

        except Exception as e:
            print(f"  ❌ {card_path.name}: {e}", file=sys.stderr)
            errors += 1

    print(f"\nSummary: {migrated} {('rolled back' if args.rollback else 'migrated')}, "
          f"{skipped} skipped, {errors} errors")

    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
