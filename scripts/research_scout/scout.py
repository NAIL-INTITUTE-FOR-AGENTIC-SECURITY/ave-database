#!/usr/bin/env python3
"""
NAIL Research Scout — Automated AVE Discovery Agent
=====================================================
Scans research feeds, CVE databases, and incident reports to discover
new agentic AI vulnerability classes for the AVE database.

Usage:
    python scout.py scan --sources arxiv,cve,github
    python scout.py scan --keywords "prompt injection,jailbreak"
    python scout.py analyse --input findings.json --check-duplicates
    python scout.py report --format markdown

Part of the NAIL Institute AVE Database
https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database
"""

from __future__ import annotations

import json
import math
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import click
import httpx
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()

BASE_DIR = Path(__file__).parent
REPO_DIR = BASE_DIR.parent.parent
CARDS_DIR = REPO_DIR / "ave-database" / "cards"
CONFIG_PATH = BASE_DIR / "config.yaml"
FINDINGS_DIR = BASE_DIR / "findings"


def load_config() -> dict:
    """Load scout configuration."""
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def load_existing_cards() -> list[dict]:
    """Load all existing AVE cards for comparison."""
    cards = []
    if CARDS_DIR.exists():
        for card_file in sorted(CARDS_DIR.glob("*.json")):
            with open(card_file) as f:
                cards.append(json.load(f))
    return cards


# ---------------------------------------------------------------------------
# Source Adapters
# ---------------------------------------------------------------------------

class SourceAdapter:
    """Base class for research source adapters."""

    def __init__(self, config: dict):
        self.config = config
        self.client = httpx.Client(timeout=30, follow_redirects=True)

    def fetch(self, keywords: list[str], lookback_days: int = 7) -> list[dict]:
        raise NotImplementedError

    def _rate_limit(self):
        """Respect rate limits."""
        delay = self.config.get("rate_limit_seconds", 1)
        time.sleep(delay)


class ArxivAdapter(SourceAdapter):
    """Fetch papers from arXiv API."""

    def fetch(self, keywords: list[str], lookback_days: int = 7) -> list[dict]:
        results = []
        base_url = self.config.get("base_url", "http://export.arxiv.org/api/query")
        categories = self.config.get("categories", ["cs.CR", "cs.AI"])
        max_results = self.config.get("max_results", 100)

        # Build query
        keyword_query = " OR ".join(f'all:"{kw}"' for kw in keywords[:10])
        cat_query = " OR ".join(f"cat:{c}" for c in categories)
        query = f"({keyword_query}) AND ({cat_query})"

        try:
            self._rate_limit()
            resp = self.client.get(base_url, params={
                "search_query": query,
                "start": 0,
                "max_results": max_results,
                "sortBy": "submittedDate",
                "sortOrder": "descending"
            })

            if resp.status_code == 200:
                # Parse Atom feed
                import feedparser
                feed = feedparser.parse(resp.text)

                cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
                for entry in feed.entries:
                    published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
                    if published < cutoff:
                        continue

                    results.append({
                        "source": "arxiv",
                        "source_id": entry.get("id", "").split("/abs/")[-1],
                        "title": entry.get("title", "").replace("\n", " ").strip(),
                        "summary": entry.get("summary", "").replace("\n", " ").strip()[:500],
                        "url": entry.get("link", ""),
                        "authors": [a.get("name", "") for a in entry.get("authors", [])],
                        "published": published.isoformat(),
                        "categories": [t.get("term", "") for t in entry.get("tags", [])]
                    })
        except Exception as e:
            console.print(f"[yellow]arXiv fetch error: {e}[/]")

        return results


class CVEAdapter(SourceAdapter):
    """Fetch CVEs from NVD API."""

    def fetch(self, keywords: list[str], lookback_days: int = 7) -> list[dict]:
        results = []
        base_url = self.config.get("base_url",
                                    "https://services.nvd.nist.gov/rest/json/cves/2.0")
        max_results = self.config.get("max_results", 50)

        start_date = (datetime.now(timezone.utc) - timedelta(days=lookback_days)
                      ).strftime("%Y-%m-%dT00:00:00.000")
        end_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59.999")

        for keyword in keywords[:5]:
            try:
                self._rate_limit()
                resp = self.client.get(base_url, params={
                    "keywordSearch": keyword,
                    "pubStartDate": start_date,
                    "pubEndDate": end_date,
                    "resultsPerPage": max_results
                })

                if resp.status_code == 200:
                    data = resp.json()
                    for vuln in data.get("vulnerabilities", []):
                        cve = vuln.get("cve", {})
                        desc = ""
                        for d in cve.get("descriptions", []):
                            if d.get("lang") == "en":
                                desc = d.get("value", "")
                                break

                        results.append({
                            "source": "cve",
                            "source_id": cve.get("id", ""),
                            "title": cve.get("id", ""),
                            "summary": desc[:500],
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
                            "published": cve.get("published", ""),
                            "severity": self._extract_severity(cve)
                        })
            except Exception as e:
                console.print(f"[yellow]CVE fetch error for '{keyword}': {e}[/]")

        return results

    def _extract_severity(self, cve: dict) -> str:
        """Extract severity from CVE metrics."""
        metrics = cve.get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                for m in metrics[version]:
                    score = m.get("cvssData", {}).get("baseScore", 0)
                    if score >= 9.0:
                        return "critical"
                    elif score >= 7.0:
                        return "high"
                    elif score >= 4.0:
                        return "medium"
                    return "low"
        return "unknown"


class GitHubAdapter(SourceAdapter):
    """Fetch security advisories from GitHub."""

    def fetch(self, keywords: list[str], lookback_days: int = 7) -> list[dict]:
        results = []
        packages = self.config.get("packages", [])
        token = os.environ.get(self.config.get("api_key_env", "GITHUB_TOKEN"), "")

        if not token:
            console.print("[yellow]GitHub token not set, skipping GitHub source[/]")
            return results

        for package in packages:
            try:
                self._rate_limit()
                resp = self.client.get(
                    f"https://api.github.com/advisories",
                    params={
                        "affects": package,
                        "per_page": 10,
                        "sort": "published",
                        "direction": "desc"
                    },
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json"
                    }
                )

                if resp.status_code == 200:
                    for adv in resp.json():
                        results.append({
                            "source": "github",
                            "source_id": adv.get("ghsa_id", ""),
                            "title": adv.get("summary", ""),
                            "summary": adv.get("description", "")[:500],
                            "url": adv.get("html_url", ""),
                            "published": adv.get("published_at", ""),
                            "severity": adv.get("severity", "unknown"),
                            "package": package
                        })
            except Exception as e:
                console.print(f"[yellow]GitHub fetch error for '{package}': {e}[/]")

        return results


class BlogAdapter(SourceAdapter):
    """Fetch from AI lab blogs via RSS."""

    def fetch(self, keywords: list[str], lookback_days: int = 7) -> list[dict]:
        results = []
        import feedparser

        keyword_lower = [kw.lower() for kw in keywords]
        cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

        for feed_cfg in self.config.get("feeds", []):
            try:
                self._rate_limit()
                feed = feedparser.parse(feed_cfg["url"])

                for entry in feed.entries[:20]:
                    title = entry.get("title", "")
                    summary = entry.get("summary", "")
                    text = (title + " " + summary).lower()

                    if any(kw in text for kw in keyword_lower):
                        results.append({
                            "source": "blog",
                            "source_id": entry.get("id", entry.get("link", "")),
                            "title": title,
                            "summary": summary[:500],
                            "url": entry.get("link", ""),
                            "published": entry.get("published", ""),
                            "blog": feed_cfg["name"]
                        })
            except Exception as e:
                console.print(f"[yellow]Blog fetch error for '{feed_cfg.get('name')}': {e}[/]")

        return results


# ---------------------------------------------------------------------------
# Analysis Engine
# ---------------------------------------------------------------------------

class NoveltyAssessor:
    """Assess novelty of candidates against existing AVE cards."""

    def __init__(self, existing_cards: list[dict]):
        self.cards = existing_cards
        self.card_texts = self._build_card_texts()

    def _build_card_texts(self) -> list[str]:
        """Build text representations of existing cards."""
        texts = []
        for card in self.cards:
            parts = [
                card.get("name", ""),
                card.get("summary", ""),
                card.get("mechanism", ""),
                card.get("category", ""),
                " ".join(card.get("aliases", []))
            ]
            texts.append(" ".join(p for p in parts if p).lower())
        return texts

    def assess(self, candidate: dict) -> dict:
        """Assess novelty of a candidate finding."""
        candidate_text = (
            candidate.get("title", "") + " " + candidate.get("summary", "")
        ).lower()

        # Simple keyword overlap scoring
        candidate_words = set(re.findall(r'\b\w+\b', candidate_text))
        if not candidate_words:
            return {"novelty_score": 0.5, "closest_ave": None, "similarity": 0}

        best_similarity = 0.0
        closest_card = None

        for i, card_text in enumerate(self.card_texts):
            card_words = set(re.findall(r'\b\w+\b', card_text))
            if not card_words:
                continue
            # Jaccard similarity
            intersection = candidate_words & card_words
            union = candidate_words | card_words
            similarity = len(intersection) / len(union) if union else 0
            if similarity > best_similarity:
                best_similarity = similarity
                closest_card = self.cards[i]

        novelty_score = 1.0 - best_similarity

        return {
            "novelty_score": round(novelty_score, 3),
            "closest_ave": closest_card.get("ave_id") if closest_card else None,
            "closest_name": closest_card.get("name") if closest_card else None,
            "similarity": round(best_similarity, 3)
        }


class SeverityEstimator:
    """Estimate severity of candidate vulnerabilities."""

    def __init__(self, config: dict):
        self.config = config.get("severity", {})

    def estimate(self, candidate: dict) -> str:
        """Estimate severity from text analysis."""
        text = (candidate.get("title", "") + " " + candidate.get("summary", "")).lower()

        for keyword in self.config.get("keywords_critical", []):
            if keyword.lower() in text:
                return "critical"

        for keyword in self.config.get("keywords_high", []):
            if keyword.lower() in text:
                return "high"

        for keyword in self.config.get("keywords_medium", []):
            if keyword.lower() in text:
                return "medium"

        return "medium"  # Default


class CategoryClassifier:
    """Classify candidates into AVE categories."""

    CATEGORY_KEYWORDS = {
        "injection": ["injection", "inject", "prompt", "jailbreak", "bypass filter"],
        "tool": ["tool", "api", "function call", "sandbox", "code execution"],
        "memory": ["memory", "context", "persist", "session", "recall"],
        "drift": ["drift", "goal", "objective", "reward", "alignment shift"],
        "alignment": ["alignment", "safety", "value", "constitutional", "rlhf"],
        "structural": ["structure", "schema", "type", "format", "recursion"],
        "delegation": ["delegation", "multi-agent", "agent chain", "trust"],
        "social": ["social", "trust", "manipulation", "persuasion", "phishing"],
        "resource": ["resource", "cost", "exhaustion", "denial", "rate limit"],
        "temporal": ["temporal", "timing", "sequence", "race condition"],
        "credential": ["credential", "authentication", "authorization", "token"],
        "consensus": ["consensus", "voting", "agreement", "collusion"],
        "fabrication": ["fabrication", "hallucination", "false evidence", "fake"]
    }

    def classify(self, candidate: dict) -> str:
        """Classify candidate into an AVE category."""
        text = (candidate.get("title", "") + " " + candidate.get("summary", "")).lower()

        scores = {}
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in text)
            scores[category] = score

        if max(scores.values()) == 0:
            return "alignment"  # Default fallback

        return max(scores, key=scores.get)


# ---------------------------------------------------------------------------
# Scout Engine
# ---------------------------------------------------------------------------

class ResearchScout:
    """Main research scout engine."""

    def __init__(self, config: dict):
        self.config = config
        self.adapters: dict[str, SourceAdapter] = {}
        self._init_adapters()

    def _init_adapters(self):
        """Initialize source adapters."""
        sources = self.config.get("sources", {})

        if sources.get("arxiv", {}).get("enabled"):
            self.adapters["arxiv"] = ArxivAdapter(sources["arxiv"])
        if sources.get("cve", {}).get("enabled"):
            self.adapters["cve"] = CVEAdapter(sources["cve"])
        if sources.get("github", {}).get("enabled"):
            self.adapters["github"] = GitHubAdapter(sources["github"])
        if sources.get("blogs", {}).get("enabled"):
            self.adapters["blogs"] = BlogAdapter(sources["blogs"])

    def scan(self, sources: list[str] | None = None,
             keywords: list[str] | None = None,
             lookback_days: int = 7) -> list[dict]:
        """Scan sources for vulnerability candidates."""
        active_sources = sources or list(self.adapters.keys())
        all_keywords = keywords or (
            self.config.get("keywords", {}).get("primary", []) +
            self.config.get("keywords", {}).get("secondary", [])
        )

        all_findings: list[dict] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            for source_name in active_sources:
                adapter = self.adapters.get(source_name)
                if not adapter:
                    console.print(f"[yellow]Source not available: {source_name}[/]")
                    continue

                task = progress.add_task(f"Scanning {source_name}...", total=None)
                findings = adapter.fetch(all_keywords, lookback_days)
                all_findings.extend(findings)
                progress.update(task, description=f"✓ {source_name}: {len(findings)} items")

        return all_findings

    def analyse(self, findings: list[dict],
                check_duplicates: bool = True) -> list[dict]:
        """Analyse findings for novelty and severity."""
        existing_cards = load_existing_cards()
        assessor = NoveltyAssessor(existing_cards)
        estimator = SeverityEstimator(self.config)
        classifier = CategoryClassifier()

        novelty_threshold = self.config.get("novelty", {}).get("threshold", 0.5)

        candidates = []
        for finding in findings:
            # Assess novelty
            novelty = assessor.assess(finding)

            # Estimate severity
            severity = estimator.estimate(finding)

            # Classify category
            category = classifier.classify(finding)

            # Determine action
            if novelty["novelty_score"] >= novelty_threshold:
                action = "review_for_new_ave"
            elif novelty["novelty_score"] >= 0.3:
                action = "update_existing"
            elif novelty["novelty_score"] >= 0.15:
                action = "monitor"
            else:
                action = "skip"

            candidate = {
                "candidate_id": f"DISC-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}",
                **finding,
                "relevance_score": round(1.0 - novelty.get("similarity", 0), 3),
                "novelty_score": novelty["novelty_score"],
                "closest_ave": novelty.get("closest_ave"),
                "closest_name": novelty.get("closest_name"),
                "similarity_to_closest": novelty["similarity"],
                "estimated_severity": severity,
                "suggested_category": category,
                "recommended_action": action
            }
            candidates.append(candidate)

        # Sort by novelty (highest first)
        candidates.sort(key=lambda x: x["novelty_score"], reverse=True)
        return candidates

    def generate_report(self, candidates: list[dict], fmt: str = "json") -> str:
        """Generate a discovery report."""
        report = {
            "report_id": f"SCOUT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_candidates": len(candidates),
            "actions_summary": {
                "review_for_new_ave": sum(1 for c in candidates if c["recommended_action"] == "review_for_new_ave"),
                "update_existing": sum(1 for c in candidates if c["recommended_action"] == "update_existing"),
                "monitor": sum(1 for c in candidates if c["recommended_action"] == "monitor"),
                "skip": sum(1 for c in candidates if c["recommended_action"] == "skip")
            },
            "candidates": candidates
        }

        if fmt == "json":
            return json.dumps(report, indent=2, default=str)
        elif fmt == "markdown":
            return self._render_markdown(report)
        return json.dumps(report, indent=2, default=str)

    def _render_markdown(self, report: dict) -> str:
        """Render report as Markdown."""
        lines = [
            f"# Research Scout Report — {report['report_id']}",
            f"\n**Generated:** {report['generated_at'][:10]}",
            f"**Total Candidates:** {report['total_candidates']}",
            "\n## Action Summary\n",
            "| Action | Count |",
            "|--------|-------|",
        ]
        for action, count in report["actions_summary"].items():
            lines.append(f"| {action} | {count} |")

        # High-priority candidates
        review_candidates = [c for c in report["candidates"]
                            if c["recommended_action"] == "review_for_new_ave"]
        if review_candidates:
            lines.append("\n## 🔴 New AVE Candidates\n")
            for c in review_candidates[:10]:
                lines.append(f"### {c.get('title', 'Unknown')}")
                lines.append(f"- **Source:** {c.get('source', '?')} ({c.get('source_id', '')})")
                lines.append(f"- **Novelty Score:** {c['novelty_score']:.2f}")
                lines.append(f"- **Estimated Severity:** {c['estimated_severity']}")
                lines.append(f"- **Suggested Category:** {c['suggested_category']}")
                lines.append(f"- **Closest AVE:** {c.get('closest_ave', 'None')} ({c.get('closest_name', '')})")
                lines.append(f"- **Summary:** {c.get('summary', '')[:200]}")
                if c.get("url"):
                    lines.append(f"- **URL:** {c['url']}")
                lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version="1.0.0", prog_name="NAIL Research Scout")
def cli():
    """🔍 NAIL Research Scout — Automated AVE Discovery

    Scan research feeds and databases for new agentic AI vulnerability classes.
    """
    pass


@cli.command()
@click.option("--sources", "-s", default=None, help="Comma-separated sources (arxiv,cve,github,blogs)")
@click.option("--keywords", "-k", default=None, help="Comma-separated search keywords")
@click.option("--lookback", "-l", default=7, type=int, help="Lookback period in days")
@click.option("--check-duplicates/--no-check", default=True)
@click.option("--output", "-o", default=None, help="Output file path")
def scan(sources: str | None, keywords: str | None, lookback: int,
         check_duplicates: bool, output: str | None):
    """Scan sources for new vulnerability candidates."""
    config = load_config()
    scout = ResearchScout(config)

    source_list = sources.split(",") if sources else None
    keyword_list = keywords.split(",") if keywords else None

    console.print(Panel(
        f"[bold cyan]Research Scout Scan[/]\n"
        f"[bold]Sources:[/] {source_list or 'all configured'}\n"
        f"[bold]Lookback:[/] {lookback} days\n"
        f"[bold]Check Duplicates:[/] {check_duplicates}",
        title="🔍 Scanning...",
        border_style="cyan"
    ))

    # Scan
    findings = scout.scan(sources=source_list, keywords=keyword_list,
                          lookback_days=lookback)
    console.print(f"\n[green]Found {len(findings)} raw items[/]")

    # Analyse
    candidates = scout.analyse(findings, check_duplicates=check_duplicates)

    # Display summary
    table = Table(title="Discovery Candidates", border_style="cyan")
    table.add_column("Action", style="bold")
    table.add_column("Count", justify="right")

    actions = {}
    for c in candidates:
        a = c["recommended_action"]
        actions[a] = actions.get(a, 0) + 1

    for action, count in sorted(actions.items()):
        color = "red" if action == "review_for_new_ave" else "yellow" if action == "update_existing" else "dim"
        table.add_row(f"[{color}]{action}[/{color}]", str(count))

    console.print(table)

    # Show top candidates
    top = [c for c in candidates if c["recommended_action"] == "review_for_new_ave"][:5]
    if top:
        console.print("\n[bold red]🔴 Top New AVE Candidates:[/]")
        for c in top:
            console.print(f"  [{c['novelty_score']:.2f}] {c.get('title', '?')[:80]}")
            console.print(f"       Source: {c['source']} | Severity: {c['estimated_severity']} | Category: {c['suggested_category']}")

    # Save
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = Path(output) if output else FINDINGS_DIR / f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.json"
    report = scout.generate_report(candidates)
    with open(out_path, "w") as f:
        f.write(report)
    console.print(f"\n[green]Full report saved:[/] {out_path}")


@cli.command()
@click.option("--input", "-i", "input_file", required=True, help="Input findings JSON")
@click.option("--check-duplicates/--no-check", default=True)
def analyse(input_file: str, check_duplicates: bool):
    """Analyse findings for novelty against existing AVE cards."""
    config = load_config()
    scout = ResearchScout(config)

    with open(input_file) as f:
        data = json.load(f)

    findings = data.get("candidates", data) if isinstance(data, dict) else data
    if isinstance(findings, dict):
        findings = [findings]

    candidates = scout.analyse(findings, check_duplicates=check_duplicates)
    console.print(f"Analysed {len(candidates)} candidates")

    for c in candidates[:10]:
        novelty = c["novelty_score"]
        color = "red" if novelty >= 0.5 else "yellow" if novelty >= 0.3 else "dim"
        console.print(f"  [{color}]{novelty:.2f}[/{color}] {c.get('title', '?')[:70]} → {c['recommended_action']}")


@cli.command()
@click.option("--input", "-i", "input_file", default=None, help="Input findings JSON")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "markdown"]), default="markdown")
@click.option("--output", "-o", default=None, help="Output file path")
def report(input_file: str | None, fmt: str, output: str | None):
    """Generate a discovery report."""
    # Find latest scan
    if not input_file:
        scan_files = sorted(FINDINGS_DIR.glob("scan-*.json"), reverse=True)
        if not scan_files:
            console.print("[yellow]No scan results found. Run 'scout.py scan' first.[/]")
            return
        input_file = str(scan_files[0])

    with open(input_file) as f:
        data = json.load(f)

    candidates = data.get("candidates", [])
    config = load_config()
    scout = ResearchScout(config)

    content = scout.generate_report(candidates, fmt=fmt)

    ext = ".md" if fmt == "markdown" else ".json"
    out_path = output or str(FINDINGS_DIR / f"report{ext}")
    with open(out_path, "w") as f:
        f.write(content)

    console.print(f"[green]Report saved:[/] {out_path}")
    if fmt == "markdown":
        console.print(content[:500])


if __name__ == "__main__":
    cli()
