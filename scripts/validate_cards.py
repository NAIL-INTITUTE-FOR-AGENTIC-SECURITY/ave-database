#!/usr/bin/env python3
"""
AVE Card Schema Validator

Validates all AVE card JSON files against the expected schema.
Used by the GitHub Actions CI/CD pipeline.

Usage:
    python scripts/validate_cards.py
    python scripts/validate_cards.py --cards-dir ./ave-database/cards
"""

import json
import glob
import os
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Schema definition
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = {
    "ave_id": str,
    "name": str,
    "category": str,
    "severity": str,
    "status": str,
    "summary": str,
}

OPTIONAL_FIELDS = {
    "aliases": list,
    "mechanism": str,
    "blast_radius": str,
    "prerequisite": str,
    "environment": (str, dict),      # Can be string or structured dict
    "evidence": (str, list),         # Can be string or list of evidence items
    "defences": list,                # List of strings or structured dicts
    "date_discovered": str,
    "date_published": str,
    "cwe_mapping": str,
    "mitre_mapping": str,
    "references": list,
    "related_aves": list,
    "avss_score": (str, dict),       # Can be string or structured score dict
    "poc": str,
    "timeline": list,
    "_meta": dict,
    "contributor": str,
}

VALID_CATEGORIES = {
    # v1 categories
    "alignment", "consensus", "credential", "delegation", "drift",
    "fabrication", "injection", "memory", "resource", "social",
    "structural", "temporal", "tool",
    # v2 categories
    "multi_agent_collusion", "temporal_exploitation", "composite",
    "model_extraction", "reward_hacking", "environmental_manipulation",
    "model_poisoning",
}

VALID_SEVERITIES = {"critical", "high", "medium", "low"}

VALID_STATUSES = {
    "published", "draft", "deprecated", "under-review",
    "proven", "proven_mitigated", "not_proven", "theoretical",
}

AVE_ID_PATTERN = r"^AVE-\d{4}-\d{4}$"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_card(card: dict, filepath: str) -> list[str]:
    """Validate a single AVE card. Returns list of error messages."""
    errors = []
    
    # Check required fields
    for field, expected_type in REQUIRED_FIELDS.items():
        if field not in card:
            errors.append(f"Missing required field: '{field}'")
        elif not isinstance(card[field], expected_type):
            errors.append(
                f"Field '{field}' should be {expected_type.__name__}, "
                f"got {type(card[field]).__name__}"
            )
    
    # Validate AVE ID format
    import re
    ave_id = card.get("ave_id", "")
    if ave_id and not re.match(AVE_ID_PATTERN, ave_id):
        errors.append(f"Invalid AVE ID format: '{ave_id}' (expected AVE-YYYY-NNNN)")
    
    # Validate filename matches AVE ID
    expected_filename = f"{ave_id}.json"
    actual_filename = os.path.basename(filepath)
    if actual_filename != expected_filename:
        errors.append(
            f"Filename '{actual_filename}' doesn't match AVE ID '{ave_id}' "
            f"(expected '{expected_filename}')"
        )
    
    # Validate category
    category = card.get("category", "")
    if category and category.lower() not in VALID_CATEGORIES:
        errors.append(
            f"Invalid category: '{category}' "
            f"(expected one of: {sorted(VALID_CATEGORIES)})"
        )
    
    # Validate severity
    severity = card.get("severity", "")
    if severity and severity.lower() not in VALID_SEVERITIES:
        errors.append(
            f"Invalid severity: '{severity}' "
            f"(expected one of: {sorted(VALID_SEVERITIES)})"
        )
    
    # Validate status
    status = card.get("status", "")
    if status and status.lower() not in VALID_STATUSES:
        errors.append(
            f"Invalid status: '{status}' "
            f"(expected one of: {sorted(VALID_STATUSES)})"
        )
    
    # Validate optional field types
    for field, expected_type in OPTIONAL_FIELDS.items():
        if field in card and card[field] is not None:
            if isinstance(expected_type, tuple):
                # Multiple allowed types
                if not isinstance(card[field], expected_type):
                    type_names = "/".join(t.__name__ for t in expected_type)
                    errors.append(
                        f"Field '{field}' should be {type_names}, "
                        f"got {type(card[field]).__name__}"
                    )
            elif not isinstance(card[field], expected_type):
                # Allow empty strings for string fields
                if expected_type == str and isinstance(card[field], str):
                    continue
                errors.append(
                    f"Field '{field}' should be {expected_type.__name__}, "
                    f"got {type(card[field]).__name__}"
                )
    
    # Validate defences is a list (of strings or dicts)
    defences = card.get("defences", [])
    if not isinstance(defences, list):
        errors.append(f"defences should be a list, got {type(defences).__name__}")
    
    # Validate related_aves references
    related = card.get("related_aves", [])
    if isinstance(related, list):
        for ref in related:
            if isinstance(ref, str) and not re.match(AVE_ID_PATTERN, ref):
                errors.append(f"Invalid related AVE reference: '{ref}'")
    
    # Check summary is non-empty
    summary = card.get("summary", "")
    if isinstance(summary, str) and len(summary.strip()) < 10:
        errors.append("Summary is too short (minimum 10 characters)")
    
    return errors


def validate_all_cards(cards_dir: str) -> tuple[int, int, list[tuple[str, list[str]]]]:
    """Validate all cards in directory. Returns (total, passed, failures)."""
    json_files = sorted(glob.glob(os.path.join(cards_dir, "*.json")))
    
    if not json_files:
        print(f"ERROR: No JSON files found in {cards_dir}")
        sys.exit(1)
    
    total = len(json_files)
    passed = 0
    failures = []
    
    for filepath in json_files:
        try:
            with open(filepath, "r") as f:
                card = json.load(f)
        except json.JSONDecodeError as e:
            failures.append((filepath, [f"Invalid JSON: {e}"]))
            continue
        
        errors = validate_card(card, filepath)
        if errors:
            failures.append((filepath, errors))
        else:
            passed += 1
    
    return total, passed, failures


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate AVE card JSON files")
    parser.add_argument(
        "--cards-dir", "-d",
        default=os.path.join(os.path.dirname(__file__), "..", "ave-database", "cards"),
        help="Path to cards directory",
    )
    args = parser.parse_args()
    
    cards_dir = os.path.abspath(args.cards_dir)
    print(f"Validating cards in: {cards_dir}")
    print("=" * 60)
    
    total, passed, failures = validate_all_cards(cards_dir)
    
    print(f"\nResults: {passed}/{total} cards passed validation")
    
    if failures:
        print(f"\n{'='*60}")
        print(f"FAILURES ({len(failures)} cards):")
        print(f"{'='*60}")
        for filepath, errors in failures:
            print(f"\n  {os.path.basename(filepath)}:")
            for error in errors:
                print(f"    ✗ {error}")
        print()
        sys.exit(1)
    else:
        print("All cards passed validation ✓")
        sys.exit(0)


if __name__ == "__main__":
    main()
