#!/usr/bin/env python3
"""
AVE Card Validator — Validates AVE cards against v1 and v2 JSON Schemas.

Usage:
    python validate_card.py <card.json>                    # auto-detect version
    python validate_card.py <card.json> --schema-version 2 # force v2
    python validate_card.py <directory/> --recursive        # validate all cards
    python validate_card.py <card.json> --strict            # treat warnings as errors

Exit codes:
    0 = valid
    1 = invalid (schema violations)
    2 = usage / file error
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    import jsonschema
    from jsonschema import Draft7Validator, ValidationError
except ImportError:
    print("ERROR: jsonschema package required. Install with: pip install jsonschema")
    sys.exit(2)


# ---------- schema paths ----------
SCRIPT_DIR = Path(__file__).resolve().parent
SCHEMA_V1_PATH = SCRIPT_DIR.parent.parent / "schema" / "ave-card-v1.schema.json"
SCHEMA_V2_PATH = SCRIPT_DIR.parent / "spec" / "ave-card-v2.schema.json"

# ---------- v2-specific optional fields ----------
V2_RECOMMENDED_FIELDS = [
    "provenance",
    "affected_components",
]

V2_MULTI_AGENT_FIELDS = [
    "multi_agent",
    "temporal",
    "composites",
    "attack_graph",
]


def load_json(path: Path) -> dict[str, Any]:
    """Load and parse a JSON file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"  ✗ JSON parse error in {path}: {e}")
        sys.exit(2)
    except FileNotFoundError:
        print(f"  ✗ File not found: {path}")
        sys.exit(2)


def detect_schema_version(card: dict[str, Any]) -> str:
    """Detect schema version from _meta.schema_version, default to '1.0.0'."""
    meta = card.get("_meta", {})
    return meta.get("schema_version", "1.0.0")


def load_schema(version: str) -> dict[str, Any]:
    """Load the appropriate schema file based on version."""
    if version.startswith("2"):
        path = SCHEMA_V2_PATH
    else:
        path = SCHEMA_V1_PATH

    if not path.exists():
        print(f"  ✗ Schema file not found: {path}")
        print(f"    Ensure schema files are in the expected locations.")
        sys.exit(2)

    return load_json(path)


def validate_card(
    card: dict[str, Any],
    schema: dict[str, Any],
    strict: bool = False,
) -> tuple[bool, list[str], list[str]]:
    """
    Validate a card against a JSON Schema.

    Returns:
        (is_valid, errors, warnings)
    """
    errors: list[str] = []
    warnings: list[str] = []

    # --- JSON Schema validation ---
    validator = Draft7Validator(schema)
    schema_errors = sorted(validator.iter_errors(card), key=lambda e: list(e.path))

    for error in schema_errors:
        field_path = ".".join(str(p) for p in error.absolute_path) or "(root)"
        errors.append(f"[{field_path}] {error.message}")

    # --- Semantic checks ---
    # Check AVE ID format
    ave_id = card.get("ave_id", "")
    if ave_id and not ave_id.startswith("AVE-"):
        errors.append(f"[ave_id] Must start with 'AVE-', got: {ave_id}")

    # Check date consistency
    discovered = card.get("date_discovered", "")
    published = card.get("date_published", "")
    if discovered and published and discovered > published:
        warnings.append(
            f"[dates] date_discovered ({discovered}) is after date_published ({published})"
        )

    # Check AVSS score ranges
    avss = card.get("avss_score", {})
    for field in ["base", "exploitability", "impact"]:
        val = avss.get(field)
        if val is not None and not (0.0 <= val <= 10.0):
            errors.append(f"[avss_score.{field}] Must be 0.0-10.0, got: {val}")

    # --- v2-specific recommendations ---
    version = detect_schema_version(card)
    if version.startswith("2"):
        # Recommend provenance for all v2 cards
        for field in V2_RECOMMENDED_FIELDS:
            if field not in card or card[field] is None:
                warnings.append(
                    f"[{field}] Recommended for v2 cards but not populated"
                )

        # If multi_agent environment, recommend multi-agent v2 fields
        env = card.get("environment", {})
        if env.get("multi_agent") is True:
            for field in V2_MULTI_AGENT_FIELDS:
                if field not in card or card[field] is None:
                    warnings.append(
                        f"[{field}] Recommended when environment.multi_agent is true"
                    )

        # Check _meta.v2_fields_populated matches actual populated fields
        meta = card.get("_meta", {})
        declared = set(meta.get("v2_fields_populated", []))
        v2_all_fields = set(V2_RECOMMENDED_FIELDS + V2_MULTI_AGENT_FIELDS + [
            "counterfactual", "regulatory_impact"
        ])
        actually_populated = {
            f for f in v2_all_fields
            if f in card and card[f] is not None
        }
        if declared and declared != actually_populated:
            missing_declared = declared - actually_populated
            undeclared = actually_populated - declared
            if missing_declared:
                warnings.append(
                    f"[_meta.v2_fields_populated] Declares fields not actually populated: "
                    f"{', '.join(sorted(missing_declared))}"
                )
            if undeclared:
                warnings.append(
                    f"[_meta.v2_fields_populated] Missing populated fields: "
                    f"{', '.join(sorted(undeclared))}"
                )

    is_valid = len(errors) == 0
    if strict and warnings:
        is_valid = False

    return is_valid, errors, warnings


def validate_file(
    path: Path,
    force_version: str | None = None,
    strict: bool = False,
) -> bool:
    """Validate a single AVE card file."""
    print(f"\n{'─' * 60}")
    print(f"Validating: {path.name}")

    card = load_json(path)

    # Determine schema version
    if force_version:
        version = force_version
    else:
        version = detect_schema_version(card)

    print(f"  Schema version: {version}")

    # Load and validate
    schema = load_schema(version)
    is_valid, errors, warnings = validate_card(card, schema, strict=strict)

    # Report
    if errors:
        print(f"  ✗ INVALID — {len(errors)} error(s):")
        for e in errors:
            print(f"    ✗ {e}")
    else:
        print(f"  ✓ Schema validation passed")

    if warnings:
        label = "ERROR" if strict else "WARNING"
        print(f"  ⚠ {len(warnings)} warning(s):")
        for w in warnings:
            print(f"    ⚠ [{label}] {w}")

    if is_valid:
        print(f"  ✓ VALID")
    else:
        print(f"  ✗ INVALID")

    return is_valid


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate AVE cards against v1/v2 JSON Schemas"
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to an AVE card JSON file or directory",
    )
    parser.add_argument(
        "--schema-version",
        choices=["1", "2"],
        default=None,
        help="Force schema version (default: auto-detect from _meta.schema_version)",
    )
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Recursively validate all .json files in a directory",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors (exit code 1)",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print summary statistics at end",
    )

    args = parser.parse_args()

    force_version = None
    if args.schema_version:
        force_version = f"{args.schema_version}.0.0"

    # Collect files
    target = args.path.resolve()
    if target.is_file():
        files = [target]
    elif target.is_dir():
        pattern = "**/*.json" if args.recursive else "*.json"
        files = sorted(target.glob(pattern))
        # Exclude schema files themselves
        files = [f for f in files if "schema" not in f.name.lower()]
        if not files:
            print(f"No JSON files found in {target}")
            sys.exit(2)
    else:
        print(f"Path not found: {target}")
        sys.exit(2)

    # Validate
    results = {"valid": 0, "invalid": 0}
    for f in files:
        if validate_file(f, force_version=force_version, strict=args.strict):
            results["valid"] += 1
        else:
            results["invalid"] += 1

    # Summary
    total = results["valid"] + results["invalid"]
    if args.summary or total > 1:
        print(f"\n{'═' * 60}")
        print(f"SUMMARY: {results['valid']}/{total} valid")
        if results["invalid"] > 0:
            print(f"         {results['invalid']} INVALID card(s)")
        print(f"{'═' * 60}")

    sys.exit(0 if results["invalid"] == 0 else 1)


if __name__ == "__main__":
    main()
