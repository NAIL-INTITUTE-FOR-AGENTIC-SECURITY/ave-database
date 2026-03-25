"""
Tests for the AVE toolkit — schema, registry, validation, and database integrity.

Covers:
  - Schema data types (Category, Severity, Status, EnvironmentVector, Evidence, Defence, AVECard)
  - Registry (lookup, search, filters, card_count)
  - Validation (required fields, field formats, severity/category/status enums)
  - Database integrity (all 50 cards load, no duplicates, every card validates)
  - Serialisation (to_dict round-trip, short/str display)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ave.schema import (
    AVECard,
    Category,
    Defence,
    EnvironmentVector,
    Evidence,
    Severity,
    Status,
)
from ave.registry import (
    _dict_to_card,
    all_cards,
    card_count,
    cards_by_category,
    cards_by_severity,
    cards_by_status,
    lookup,
    search,
)
from ave.validate import (
    REQUIRED_FIELDS,
    VALID_CATEGORIES,
    VALID_SEVERITIES,
    VALID_STATUSES,
    validate_card_data,
)


# ═══════════════════════════════════════════════════════════════════════════
# Locate the real cards directory
# ═══════════════════════════════════════════════════════════════════════════

CARDS_DIR = Path(__file__).parent.parent.parent / "ave-database" / "cards"


# ═══════════════════════════════════════════════════════════════════════════
# SCHEMA TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestCategory:
    """Category enum completeness."""

    def test_all_values_are_strings(self) -> None:
        for cat in Category:
            assert isinstance(cat.value, str)

    def test_expected_categories_exist(self) -> None:
        expected = {
            "memory", "consensus", "injection", "resource", "drift",
            "alignment", "social", "tool", "temporal", "structural",
            "credential", "delegation", "fabrication", "emergent",
        }
        actual = {c.value for c in Category}
        assert expected == actual

    def test_category_count(self) -> None:
        assert len(Category) == 14


class TestSeverity:
    """Severity enum levels."""

    def test_severity_levels(self) -> None:
        expected = {"critical", "high", "medium", "low", "info"}
        assert {s.value for s in Severity} == expected

    def test_severity_count(self) -> None:
        assert len(Severity) == 5


class TestStatus:
    """Status enum values."""

    def test_status_values(self) -> None:
        expected = {"proven", "proven_mitigated", "theoretical", "not_proven", "in_progress"}
        assert {s.value for s in Status} == expected

    def test_status_count(self) -> None:
        assert len(Status) == 5


class TestEnvironmentVector:
    """EnvironmentVector frozen dataclass."""

    def test_defaults(self) -> None:
        env = EnvironmentVector()
        assert env.frameworks == ()
        assert env.models_tested == ()
        assert env.multi_agent is False
        assert env.tools_required is False
        assert env.memory_required is False
        assert env.rag_required is False
        assert env.min_context_window is None

    def test_frozen(self) -> None:
        env = EnvironmentVector(multi_agent=True)
        with pytest.raises(AttributeError):
            env.multi_agent = False  # type: ignore[misc]

    def test_custom_values(self) -> None:
        env = EnvironmentVector(
            frameworks=("LangGraph", "CrewAI"),
            models_tested=("nemotron:70b",),
            multi_agent=True,
            tools_required=True,
            min_context_window=128_000,
        )
        assert "LangGraph" in env.frameworks
        assert env.min_context_window == 128_000


class TestEvidence:
    """Evidence frozen dataclass."""

    def test_minimal(self) -> None:
        e = Evidence(experiment_id="exp1")
        assert e.experiment_id == "exp1"
        assert e.data_file == ""
        assert e.p_value is None
        assert e.cross_model is False

    def test_full(self) -> None:
        e = Evidence(
            experiment_id="exp26",
            data_file="results.json",
            key_metric="exploitation_rate",
            key_value="100%",
            p_value=0.0002,
            sample_size=100,
            cross_model=True,
        )
        assert e.p_value == 0.0002
        assert e.cross_model is True


class TestDefence:
    """Defence frozen dataclass."""

    def test_minimal(self) -> None:
        d = Defence(name="Memory Firewall")
        assert d.name == "Memory Firewall"
        assert d.layer == ""

    def test_full(self) -> None:
        d = Defence(
            name="TaintTracker",
            layer="L3",
            effectiveness="100%",
            rmap_module="rmap.immune",
            nail_monitor_detector="SharedMemoryPollutionDetector",
        )
        assert d.layer == "L3"


class TestAVECard:
    """AVECard dataclass and methods."""

    @pytest.fixture()
    def sample_card(self) -> AVECard:
        return AVECard(
            ave_id="AVE-2025-9999",
            name="Test Vulnerability",
            category=Category.MEMORY,
            severity=Severity.HIGH,
            status=Status.PROVEN,
            summary="A test vulnerability for unit testing.",
            mechanism="Test mechanism.",
            blast_radius="Test blast radius.",
            prerequisite="None.",
            environment=EnvironmentVector(
                frameworks=("TestFramework",),
                multi_agent=True,
            ),
            evidence=(Evidence(experiment_id="exp_test"),),
            defences=(Defence(name="TestDefence"),),
        )

    def test_to_dict_round_trip(self, sample_card: AVECard) -> None:
        d = sample_card.to_dict()
        assert d["ave_id"] == "AVE-2025-9999"
        assert d["category"] == "memory"
        assert d["severity"] == "high"
        assert d["status"] == "proven"
        assert d["environment"]["multi_agent"] is True
        assert len(d["evidence"]) == 1
        assert len(d["defences"]) == 1

    def test_to_dict_is_json_serialisable(self, sample_card: AVECard) -> None:
        d = sample_card.to_dict()
        json_str = json.dumps(d)
        assert json_str  # doesn't raise

    def test_short_format(self, sample_card: AVECard) -> None:
        short = sample_card.short()
        assert "AVE-2025-9999" in short
        assert "HIGH" in short
        assert "Test Vulnerability" in short

    def test_str_format(self, sample_card: AVECard) -> None:
        s = str(sample_card)
        assert "AVE-2025-9999" in s
        assert "memory" in s
        assert "TestDefence" in s


# ═══════════════════════════════════════════════════════════════════════════
# REGISTRY TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestRegistry:
    """Registry loading, lookup, and search against the real database."""

    def test_all_cards_loads(self) -> None:
        cards = all_cards()
        assert len(cards) >= 50, f"Expected ≥50 cards, got {len(cards)}"

    def test_lookup_existing(self) -> None:
        card = lookup("AVE-2025-0001")
        assert card is not None
        assert card.ave_id == "AVE-2025-0001"

    def test_lookup_missing(self) -> None:
        assert lookup("AVE-9999-9999") is None

    def test_search_by_keyword(self) -> None:
        results = search(keyword="memory")
        assert len(results) >= 1
        assert any("memory" in c.name.lower() or "memory" in c.summary.lower()
                    or c.category == Category.MEMORY for c in results)

    def test_search_by_category(self) -> None:
        results = search(category=Category.INJECTION)
        assert all(c.category == Category.INJECTION for c in results)

    def test_search_by_severity(self) -> None:
        results = search(severity=Severity.CRITICAL)
        assert all(c.severity == Severity.CRITICAL for c in results)

    def test_search_by_status(self) -> None:
        results = search(status=Status.PROVEN)
        assert all(c.status == Status.PROVEN for c in results)

    def test_cards_by_severity(self) -> None:
        critical = cards_by_severity(Severity.CRITICAL)
        assert all(c.severity == Severity.CRITICAL for c in critical)

    def test_cards_by_category(self) -> None:
        memory = cards_by_category(Category.MEMORY)
        assert all(c.category == Category.MEMORY for c in memory)

    def test_cards_by_status(self) -> None:
        proven = cards_by_status(Status.PROVEN)
        assert all(c.status == Status.PROVEN for c in proven)

    def test_card_count(self) -> None:
        counts = card_count()
        assert counts["total"] >= 50
        assert "by_severity" in counts
        assert "by_category" in counts
        assert "by_status" in counts
        total_by_sev = sum(counts["by_severity"].values())
        assert total_by_sev == counts["total"]

    def test_dict_to_card_minimal(self) -> None:
        data = {
            "ave_id": "AVE-2025-0099",
            "name": "Minimal Card",
            "category": "memory",
            "severity": "low",
            "status": "theoretical",
        }
        card = _dict_to_card(data)
        assert card.ave_id == "AVE-2025-0099"
        assert card.category == Category.MEMORY
        assert card.severity == Severity.LOW

    def test_dict_to_card_invalid_category_falls_back(self) -> None:
        data = {
            "ave_id": "AVE-2025-0099",
            "name": "Bad Category",
            "category": "nonexistent",
            "severity": "low",
            "status": "theoretical",
        }
        card = _dict_to_card(data)
        assert card.category == Category.EMERGENT  # fallback


# ═══════════════════════════════════════════════════════════════════════════
# VALIDATION TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestValidation:
    """Validator catches malformed cards."""

    def test_valid_card_passes(self) -> None:
        data = {
            "ave_id": "AVE-2025-0001",
            "name": "Test",
            "category": "memory",
            "severity": "high",
            "status": "proven",
            "summary": "A summary.",
            "mechanism": "A mechanism.",
            "blast_radius": "Some blast radius.",
            "prerequisite": "Some prereq.",
        }
        result = validate_card_data(data, "test.json")
        assert result.valid, f"Should be valid: {result}"

    def test_missing_required_field(self) -> None:
        data = {
            "ave_id": "AVE-2025-0001",
            "name": "Test",
            # missing category, severity, status, summary, etc.
        }
        result = validate_card_data(data, "test.json")
        assert not result.valid
        assert len(result.errors) >= 5

    def test_empty_required_field(self) -> None:
        data = {
            "ave_id": "AVE-2025-0001",
            "name": "",
            "category": "memory",
            "severity": "high",
            "status": "proven",
            "summary": "ok",
            "mechanism": "ok",
            "blast_radius": "ok",
            "prerequisite": "ok",
        }
        result = validate_card_data(data, "test.json")
        assert not result.valid

    def test_invalid_severity(self) -> None:
        data = {
            "ave_id": "AVE-2025-0001",
            "name": "Test",
            "category": "memory",
            "severity": "apocalyptic",
            "status": "proven",
            "summary": "s",
            "mechanism": "m",
            "blast_radius": "b",
            "prerequisite": "p",
        }
        result = validate_card_data(data, "test.json")
        assert not result.valid

    def test_invalid_ave_id_format(self) -> None:
        data = {
            "ave_id": "NOT-AN-ID",
            "name": "Test",
            "category": "memory",
            "severity": "high",
            "status": "proven",
            "summary": "s",
            "mechanism": "m",
            "blast_radius": "b",
            "prerequisite": "p",
        }
        result = validate_card_data(data, "test.json")
        assert not result.valid

    def test_valid_constants(self) -> None:
        """Schema constants are correct."""
        assert "memory" in VALID_CATEGORIES
        assert "critical" in VALID_SEVERITIES
        assert "proven" in VALID_STATUSES


# ═══════════════════════════════════════════════════════════════════════════
# DATABASE INTEGRITY TESTS — every real card on disk
# ═══════════════════════════════════════════════════════════════════════════

class TestDatabaseIntegrity:
    """Verify the actual AVE database files are consistent."""

    @pytest.fixture()
    def card_json_files(self) -> list[Path]:
        if not CARDS_DIR.is_dir():
            pytest.skip("ave-database/cards/ not found")
        return sorted(CARDS_DIR.glob("AVE-*.json"))

    def test_at_least_50_cards(self, card_json_files: list[Path]) -> None:
        assert len(card_json_files) >= 50, (
            f"Expected ≥50 card JSON files, got {len(card_json_files)}"
        )

    def test_no_duplicate_ids(self) -> None:
        cards = all_cards()
        ids = [c.ave_id for c in cards]
        assert len(ids) == len(set(ids)), "Duplicate AVE IDs detected"

    def test_every_card_has_markdown(self, card_json_files: list[Path]) -> None:
        for jf in card_json_files:
            md_file = jf.with_suffix(".md")
            assert md_file.exists(), f"Missing Markdown companion: {md_file}"

    def test_every_json_is_valid(self, card_json_files: list[Path]) -> None:
        for jf in card_json_files:
            data = json.loads(jf.read_text())
            result = validate_card_data(data, str(jf))
            assert result.valid, f"Validation failed for {jf}:\n{result}"

    def test_every_card_has_required_fields(self, card_json_files: list[Path]) -> None:
        for jf in card_json_files:
            data = json.loads(jf.read_text())
            for fld in REQUIRED_FIELDS:
                assert fld in data, f"{jf.name}: missing {fld}"
                assert data[fld], f"{jf.name}: empty {fld}"

    def test_ave_id_matches_filename(self, card_json_files: list[Path]) -> None:
        for jf in card_json_files:
            data = json.loads(jf.read_text())
            expected_id = jf.stem  # e.g. "AVE-2025-0001"
            assert data.get("ave_id") == expected_id, (
                f"ID mismatch: file={jf.name}, json ave_id={data.get('ave_id')}"
            )

    def test_ave_id_format(self, card_json_files: list[Path]) -> None:
        pattern = re.compile(r"^AVE-\d{4}-\d{4}$")
        for jf in card_json_files:
            assert pattern.match(jf.stem), f"Bad AVE ID format: {jf.stem}"

    def test_severity_distribution(self) -> None:
        counts = card_count()
        # We should have cards in at least 3 severity levels
        assert len(counts["by_severity"]) >= 3

    def test_category_distribution(self) -> None:
        counts = card_count()
        # We should have cards in at least 10 categories
        assert len(counts["by_category"]) >= 10
