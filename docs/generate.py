#!/usr/bin/env python3
"""
Generate static documentation site from AVE Database content.

Produces a self-contained HTML site at docs/_site/ suitable for
GitHub Pages deployment. Zero external dependencies beyond jinja2.

Usage:
    python docs/generate.py
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────
DOCS_DIR = Path(__file__).parent
PROJECT_ROOT = DOCS_DIR.parent
SITE_DIR = DOCS_DIR / "_site"
CARDS_DIR = PROJECT_ROOT / "ave-database" / "cards"

# Add ave package to path
sys.path.insert(0, str(PROJECT_ROOT / "ave"))


def load_cards() -> list[dict]:
    """Load all AVE card JSON files."""
    cards = []
    for f in sorted(CARDS_DIR.glob("AVE-*.json")):
        with open(f) as fh:
            cards.append(json.load(fh))
    return cards


def severity_icon(sev: str) -> str:
    return {
        "critical": "🔴", "high": "🟠", "medium": "🟡",
        "low": "🟢", "info": "ℹ️",
    }.get(sev, "❓")


def severity_class(sev: str) -> str:
    return {
        "critical": "sev-critical", "high": "sev-high",
        "medium": "sev-medium", "low": "sev-low", "info": "sev-info",
    }.get(sev, "")


# ── HTML Templates ─────────────────────────────────────────────────────────

CSS = """
:root {
    --bg: #0d1117;
    --surface: #161b22;
    --surface2: #21262d;
    --border: #30363d;
    --text: #e6edf3;
    --text-muted: #8b949e;
    --accent: #58a6ff;
    --accent-hover: #79c0ff;
    --critical: #f85149;
    --high: #f0883e;
    --medium: #d29922;
    --low: #3fb950;
    --info: #58a6ff;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
}

a { color: var(--accent); text-decoration: none; }
a:hover { color: var(--accent-hover); text-decoration: underline; }

.container { max-width: 1200px; margin: 0 auto; padding: 0 24px; }

/* Header */
header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 20px 0;
    position: sticky;
    top: 0;
    z-index: 100;
}

header .container {
    display: flex;
    align-items: center;
    justify-content: space-between;
}

header h1 { font-size: 1.4rem; }
header h1 span { color: var(--text-muted); font-weight: normal; }

nav a {
    margin-left: 24px;
    color: var(--text-muted);
    font-size: 0.9rem;
}
nav a:hover { color: var(--text); text-decoration: none; }
nav a.active { color: var(--accent); }

/* Hero */
.hero {
    text-align: center;
    padding: 60px 0 40px;
    border-bottom: 1px solid var(--border);
}

.hero h2 {
    font-size: 2.4rem;
    margin-bottom: 12px;
    background: linear-gradient(135deg, var(--accent), #a371f7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.hero p {
    font-size: 1.1rem;
    color: var(--text-muted);
    max-width: 700px;
    margin: 0 auto 30px;
}

.hero-stats {
    display: flex;
    justify-content: center;
    gap: 40px;
    margin-top: 30px;
}

.stat {
    text-align: center;
}

.stat-value {
    font-size: 2.2rem;
    font-weight: 700;
    color: var(--text);
}

.stat-label {
    font-size: 0.85rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

/* Search */
.search-bar {
    padding: 24px 0;
    border-bottom: 1px solid var(--border);
}

.search-bar input {
    width: 100%;
    padding: 12px 16px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-size: 1rem;
    outline: none;
}

.search-bar input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.15);
}

/* Filters */
.filters {
    padding: 16px 0;
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

.filter-btn {
    padding: 6px 14px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 20px;
    color: var(--text-muted);
    font-size: 0.85rem;
    cursor: pointer;
    transition: all 0.2s;
}

.filter-btn:hover, .filter-btn.active {
    background: var(--accent);
    color: var(--bg);
    border-color: var(--accent);
}

/* Card Grid */
.card-grid {
    padding: 24px 0;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
    gap: 16px;
}

.card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    transition: border-color 0.2s;
}

.card:hover {
    border-color: var(--accent);
}

.card-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 8px;
}

.card-id {
    font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
    font-size: 0.85rem;
    color: var(--accent);
}

.card-severity {
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.sev-critical { background: rgba(248,81,73,0.15); color: var(--critical); }
.sev-high { background: rgba(240,136,62,0.15); color: var(--high); }
.sev-medium { background: rgba(210,153,34,0.15); color: var(--medium); }
.sev-low { background: rgba(63,185,80,0.15); color: var(--low); }
.sev-info { background: rgba(88,166,255,0.15); color: var(--info); }

.card-title {
    font-size: 1.05rem;
    font-weight: 600;
    margin-bottom: 8px;
}

.card-summary {
    font-size: 0.9rem;
    color: var(--text-muted);
    margin-bottom: 12px;
    display: -webkit-box;
    -webkit-line-clamp: 3;
    -webkit-box-orient: vertical;
    overflow: hidden;
}

.card-meta {
    display: flex;
    gap: 12px;
    font-size: 0.8rem;
    color: var(--text-muted);
}

.card-meta span {
    background: var(--surface2);
    padding: 2px 8px;
    border-radius: 4px;
}

/* Taxonomy page */
.taxonomy-section {
    padding: 40px 0;
}

.taxonomy-section h2 {
    font-size: 1.5rem;
    margin-bottom: 24px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
}

.category-group {
    margin-bottom: 32px;
}

.category-group h3 {
    font-size: 1.1rem;
    color: var(--accent);
    margin-bottom: 12px;
}

.category-group .card-list {
    display: grid;
    gap: 8px;
}

.card-row {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 10px 16px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
}

.card-row:hover { border-color: var(--accent); }
.card-row .card-id { min-width: 140px; }
.card-row .card-name { flex: 1; }

/* Detail page */
.detail {
    padding: 40px 0;
}

.detail h2 {
    font-size: 1.8rem;
    margin-bottom: 8px;
}

.detail-meta {
    display: flex;
    gap: 16px;
    margin-bottom: 24px;
    flex-wrap: wrap;
}

.detail-section {
    margin-bottom: 32px;
}

.detail-section h3 {
    font-size: 1.1rem;
    color: var(--accent);
    margin-bottom: 12px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--border);
}

.detail-section p, .detail-section ul {
    color: var(--text-muted);
    font-size: 0.95rem;
}

.detail-section ul {
    padding-left: 24px;
}

.detail-section li {
    margin-bottom: 4px;
}

/* Footer */
footer {
    border-top: 1px solid var(--border);
    padding: 40px 0;
    text-align: center;
    color: var(--text-muted);
    font-size: 0.85rem;
}

footer a { color: var(--accent); }

/* Responsive */
@media (max-width: 768px) {
    .hero h2 { font-size: 1.6rem; }
    .hero-stats { flex-direction: column; gap: 16px; }
    .card-grid { grid-template-columns: 1fr; }
    header .container { flex-direction: column; gap: 12px; }
}
"""

JS = """
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('search');
    const cards = document.querySelectorAll('.card[data-searchable]');
    const filterBtns = document.querySelectorAll('.filter-btn');
    let activeFilter = 'all';

    if (searchInput) {
        searchInput.addEventListener('input', filterCards);
    }

    filterBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            filterBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            activeFilter = this.dataset.filter;
            filterCards();
        });
    });

    function filterCards() {
        const query = searchInput ? searchInput.value.toLowerCase() : '';
        cards.forEach(card => {
            const text = card.dataset.searchable.toLowerCase();
            const sev = card.dataset.severity;
            const cat = card.dataset.category;
            const matchSearch = !query || text.includes(query);
            const matchFilter = activeFilter === 'all'
                || sev === activeFilter
                || cat === activeFilter;
            card.style.display = (matchSearch && matchFilter) ? '' : 'none';
        });
    }
});
"""


def generate_header(active: str = "database") -> str:
    """Generate page header."""
    def cls(page):
        return ' class="active"' if page == active else ''

    return f"""<header>
  <div class="container">
    <h1>🛡️ NAIL Institute <span>— AVE Database</span></h1>
    <nav>
      <a href="index.html"{cls("database")}>Database</a>
      <a href="taxonomy.html"{cls("taxonomy")}>Taxonomy</a>
      <a href="ctf.html"{cls("ctf")}>🏁 CTF</a>
      <a href="https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database/tree/main/research">🔬 Research</a>
      <a href="contribute.html"{cls("contribute")}>Contribute</a>
      <a href="https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database/discussions">💬 Discuss</a>
      <a href="https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database">GitHub</a>
    </nav>
  </div>
</header>"""


def generate_footer() -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return f"""<footer>
  <div class="container">
    <p>
      <strong>AVE Database</strong> — The MITRE ATT&CK of the Agentic Era<br>
      Maintained by the <a href="https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY">NAIL Institute</a>
      · Licensed under <a href="https://creativecommons.org/licenses/by-sa/4.0/">CC-BY-SA-4.0</a><br>
      Last generated: {now}
    </p>
  </div>
</footer>"""


def generate_index_page(cards: list[dict]) -> str:
    """Generate the main database browsing page."""
    # Stats
    by_sev: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    for c in cards:
        sev = c.get("severity", "unknown")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        cat = c.get("category", "unknown")
        by_cat[cat] = by_cat.get(cat, 0) + 1

    total = len(cards)
    categories = len(by_cat)
    critical_high = by_sev.get("critical", 0) + by_sev.get("high", 0)

    # Filter buttons
    sev_order = ["all", "critical", "high", "medium", "low", "info"]
    filter_html = ""
    for s in sev_order:
        active = ' active' if s == 'all' else ''
        label = s.upper() if s != 'all' else 'ALL'
        count = f" ({by_sev[s]})" if s in by_sev else ""
        filter_html += f'<button class="filter-btn{active}" data-filter="{s}">{label}{count}</button>\n'

    # Category filters
    for cat in sorted(by_cat.keys()):
        filter_html += f'<button class="filter-btn" data-filter="{cat}">{cat} ({by_cat[cat]})</button>\n'

    # Card grid
    card_html = ""
    for c in cards:
        ave_id = c.get("ave_id", "")
        name = c.get("name", "")
        sev = c.get("severity", "")
        cat = c.get("category", "")
        status = c.get("status", "")
        summary = c.get("summary", "")[:200]
        searchable = f"{ave_id} {name} {cat} {summary} {' '.join(c.get('aliases', []))}"

        card_html += f"""<div class="card" data-searchable="{searchable}" data-severity="{sev}" data-category="{cat}">
  <div class="card-header">
    <a class="card-id" href="cards/{ave_id}.html">{ave_id}</a>
    <span class="card-severity {severity_class(sev)}">{severity_icon(sev)} {sev}</span>
  </div>
  <div class="card-title"><a href="cards/{ave_id}.html">{name}</a></div>
  <div class="card-summary">{summary}</div>
  <div class="card-meta">
    <span>{cat}</span>
    <span>{status}</span>
  </div>
</div>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AVE Database — Agentic Vulnerabilities & Exposures</title>
  <meta name="description" content="The MITRE ATT&CK of the Agentic Era. {total} documented AI agent vulnerabilities.">
  <style>{CSS}</style>
</head>
<body>
{generate_header("database")}

<div class="hero">
  <div class="container">
    <h2>Agentic Vulnerabilities & Exposures</h2>
    <p>The world's first structured catalogue of AI agent failure modes.
    Open, community-driven, and backed by empirical research.</p>
    <div class="hero-stats">
      <div class="stat">
        <div class="stat-value">{total}</div>
        <div class="stat-label">Vulnerabilities</div>
      </div>
      <div class="stat">
        <div class="stat-value">{categories}</div>
        <div class="stat-label">Categories</div>
      </div>
      <div class="stat">
        <div class="stat-value">{critical_high}</div>
        <div class="stat-label">Critical / High</div>
      </div>
    </div>
  </div>
</div>

<div class="container">
  <div class="search-bar">
    <input type="text" id="search" placeholder="🔍 Search vulnerabilities — try 'injection', 'memory', 'tool'...">
  </div>
  <div class="filters">
    {filter_html}
  </div>
  <div class="card-grid">
    {card_html}
  </div>
</div>

{generate_footer()}
<script>{JS}</script>
</body>
</html>"""


def generate_card_page(card: dict) -> str:
    """Generate a detail page for a single AVE card."""
    ave_id = card.get("ave_id", "")
    name = card.get("name", "")
    sev = card.get("severity", "")
    cat = card.get("category", "")
    status = card.get("status", "")
    summary = card.get("summary", "")
    blast = card.get("blast_radius", "")
    prereq = card.get("prerequisite", "")
    aliases = card.get("aliases", [])
    cwe = card.get("cwe_mapping", "")
    related = card.get("related_aves", [])
    env = card.get("environment", {})

    sections_html = ""

    # Summary
    sections_html += f"""<div class="detail-section">
  <h3>Summary</h3>
  <p>{summary}</p>
</div>"""

    # Blast Radius
    if blast:
        sections_html += f"""<div class="detail-section">
  <h3>Blast Radius</h3>
  <p>{blast}</p>
</div>"""

    # Prerequisites
    if prereq:
        sections_html += f"""<div class="detail-section">
  <h3>Prerequisites</h3>
  <p>{prereq}</p>
</div>"""

    # Environment
    if isinstance(env, dict) and any(env.values()):
        env_items = ""
        if env.get("frameworks"):
            env_items += f"<li><strong>Frameworks:</strong> {', '.join(env['frameworks'])}</li>"
        if env.get("models_tested"):
            env_items += f"<li><strong>Models tested:</strong> {', '.join(env['models_tested'])}</li>"
        env_items += f"<li><strong>Multi-agent:</strong> {'Yes' if env.get('multi_agent') else 'No'}</li>"
        env_items += f"<li><strong>Tools required:</strong> {'Yes' if env.get('tools_required') else 'No'}</li>"
        env_items += f"<li><strong>Memory required:</strong> {'Yes' if env.get('memory_required') else 'No'}</li>"
        sections_html += f"""<div class="detail-section">
  <h3>Environment</h3>
  <ul>{env_items}</ul>
</div>"""

    # Defences (names only in public tier)
    defences = card.get("defences", [])
    if defences:
        def_items = "".join(
            f"<li><strong>{d.get('name', '?')}</strong> — {d.get('layer', '?')} layer</li>"
            for d in defences if isinstance(d, dict)
        )
        sections_html += f"""<div class="detail-section">
  <h3>Known Defences</h3>
  <ul>{def_items}</ul>
  <p style="margin-top:12px; font-style:italic; color:var(--text-muted);">
    🔒 Full defence implementations available through the
    <a href="https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY">NAIL SDK</a>.
  </p>
</div>"""

    # Related
    related_html = ""
    if related:
        related_html = f"""<div class="detail-section">
  <h3>Related</h3>
  <ul>
    {''.join(f'<li><a href="{r}.html">{r}</a></li>' for r in related)}
    {f'<li>CWE: {cwe}</li>' if cwe else ''}
  </ul>
</div>"""

    # Aliases
    aliases_html = ""
    if aliases:
        aliases_html = f" · <em>aka: {', '.join(aliases)}</em>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{ave_id} — {name} | AVE Database</title>
  <meta name="description" content="{summary[:160]}">
  <style>{CSS}</style>
</head>
<body>
{generate_header("database")}

<div class="container">
  <div class="detail">
    <p style="margin-bottom: 8px;"><a href="../index.html">← Back to Database</a></p>
    <h2>{name}</h2>
    <div class="detail-meta">
      <span class="card-severity {severity_class(sev)}">{severity_icon(sev)} {sev.upper()}</span>
      <span class="card-severity" style="background: var(--surface2); color: var(--text-muted);">{cat}</span>
      <span class="card-severity" style="background: var(--surface2); color: var(--text-muted);">{status}</span>
      <span style="font-family: monospace; color: var(--accent);">{ave_id}</span>
    </div>
    {f'<p style="color:var(--text-muted); margin-bottom:24px;">{aliases_html}</p>' if aliases_html else ''}
    {sections_html}
    {related_html}
  </div>
</div>

{generate_footer()}
</body>
</html>"""


def generate_taxonomy_page(cards: list[dict]) -> str:
    """Generate the taxonomy/categories page."""
    by_cat: dict[str, list[dict]] = {}
    for c in cards:
        cat = c.get("category", "unknown")
        by_cat.setdefault(cat, []).append(c)

    cat_descriptions = {
        "memory": "Memory pollution, laundering, and poisoning attacks",
        "consensus": "Deadlock, paralysis, and group decision failures",
        "injection": "Prompt injection, indirect injection, jailbreaks",
        "resource": "Token embezzlement, EDoS, cost anomaly attacks",
        "drift": "Persona drift, language drift, goal drift",
        "alignment": "Sycophancy, deceptive alignment, RLHF exploits",
        "social": "Collusion, bystander effect, social loafing",
        "tool": "Confused deputy, tool chain exploits, MCP poisoning",
        "temporal": "Chronological desync, sleeper payloads",
        "structural": "Cascade corruption, routing deadlock",
        "credential": "Credential harvesting, secret exfiltration",
        "delegation": "Shadow delegation, privilege escalation",
        "fabrication": "Hallucination, data fabrication",
        "emergent": "Novel behaviours not fitting other categories",
    }

    groups_html = ""
    for cat in sorted(by_cat.keys()):
        cat_cards = by_cat[cat]
        desc = cat_descriptions.get(cat, "")
        rows = ""
        for c in cat_cards:
            sev = c.get("severity", "")
            rows += f"""<div class="card-row">
  <span class="card-id"><a href="cards/{c['ave_id']}.html">{c['ave_id']}</a></span>
  <span class="card-severity {severity_class(sev)}" style="min-width:80px; text-align:center;">{severity_icon(sev)} {sev}</span>
  <span class="card-name">{c.get('name', '')}</span>
</div>
"""
        groups_html += f"""<div class="category-group">
  <h3>🏷️ {cat} <span style="color:var(--text-muted); font-weight:normal;">— {desc} ({len(cat_cards)} cards)</span></h3>
  <div class="card-list">{rows}</div>
</div>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Taxonomy — AVE Database</title>
  <style>{CSS}</style>
</head>
<body>
{generate_header("taxonomy")}

<div class="container">
  <div class="taxonomy-section">
    <h2>AVE Taxonomy — {len(by_cat)} Attack Categories</h2>
    <p style="color:var(--text-muted); margin-bottom:32px;">
      Every vulnerability is classified into an attack surface or failure domain.
      Categories emerge from empirical observation of AI agent behaviour across
      29 controlled experiments and 50,000+ adversarial simulations.
    </p>
    {groups_html}
  </div>
</div>

{generate_footer()}
</body>
</html>"""


def generate_contribute_page() -> str:
    """Generate the contribution guide page."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Contribute — AVE Database</title>
  <style>{CSS}</style>
</head>
<body>
{generate_header("contribute")}

<div class="container">
  <div class="taxonomy-section">
    <h2>Contribute to the AVE Database</h2>
    <p style="color:var(--text-muted); margin-bottom:32px; max-width:700px;">
      Anyone can submit vulnerabilities. If you've observed an AI agent behave
      unexpectedly, fail in a repeatable way, or found an exploitable pattern —
      we want to hear about it.
    </p>

    <div class="card-grid" style="max-width:900px;">
      <a href="https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database/issues/new?template=ave-submission.yml" class="card" style="text-decoration:none;">
        <div class="card-title" style="color:var(--accent);">📝 Submit via Issue</div>
        <div class="card-summary">
          The easiest way. Fill out a structured form on GitHub — no coding required.
          Great for first-time contributors.
        </div>
        <div class="card-meta"><span>Difficulty: Easy</span></div>
      </a>

      <a href="https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database/blob/main/CONTRIBUTING.md" class="card" style="text-decoration:none;">
        <div class="card-title" style="color:var(--accent);">🔀 Submit via Pull Request</div>
        <div class="card-summary">
          For experienced contributors. Submit JSON + Markdown directly. Use the
          AVE CLI to generate card skeletons.
        </div>
        <div class="card-meta"><span>Difficulty: Moderate</span></div>
      </a>

      <a href="https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database/blob/main/SECURITY.md" class="card" style="text-decoration:none;">
        <div class="card-title" style="color:var(--accent);">🔒 Private Disclosure</div>
        <div class="card-summary">
          For severe or weaponizable findings. Responsible disclosure with a 90-day
          timeline. PGP available.
        </div>
        <div class="card-meta"><span>For: High-severity findings</span></div>
      </a>
    </div>

    <div style="margin-top:48px;">
      <h2>Contributor Recognition</h2>
      <p style="color:var(--text-muted); margin-bottom:24px;">
        Every accepted card earns <strong>XP</strong>, unlocks <strong>badges</strong>,
        and climbs the <strong>leaderboard</strong>.
      </p>

      <div class="card" style="max-width:600px;">
        <table style="width:100%; border-collapse:collapse;">
          <tr style="border-bottom:1px solid var(--border);">
            <td style="padding:8px;">👁️ <strong>WATCHER</strong></td>
            <td style="padding:8px; color:var(--text-muted);">0+ XP</td>
            <td style="padding:8px; color:var(--text-muted);">Joined the hunt</td>
          </tr>
          <tr style="border-bottom:1px solid var(--border);">
            <td style="padding:8px;">🏹 <strong>HUNTER</strong></td>
            <td style="padding:8px; color:var(--text-muted);">500+ XP</td>
            <td style="padding:8px; color:var(--text-muted);">Hall of Fame listing</td>
          </tr>
          <tr style="border-bottom:1px solid var(--border);">
            <td style="padding:8px;">🛡️ <strong>SENTINEL</strong></td>
            <td style="padding:8px; color:var(--text-muted);">1,500+ XP</td>
            <td style="padding:8px; color:var(--text-muted);">Fast-track review</td>
          </tr>
          <tr style="border-bottom:1px solid var(--border);">
            <td style="padding:8px;">🏗️ <strong>ARCHITECT</strong></td>
            <td style="padding:8px; color:var(--text-muted);">4,000+ XP</td>
            <td style="padding:8px; color:var(--text-muted);">Invited to review PRs</td>
          </tr>
          <tr>
            <td style="padding:8px;">⭐ <strong>FELLOW</strong></td>
            <td style="padding:8px; color:var(--text-muted);">8,000+ XP</td>
            <td style="padding:8px; color:var(--text-muted);">NAIL Research Fellow</td>
          </tr>
        </table>
      </div>

      <p style="margin-top:24px;">
        <a href="https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database/blob/main/HALL_OF_FAME.md">
          🏆 View the Hall of Fame →
        </a>
      </p>
    </div>

    <div style="margin-top:48px;">
      <h2>CLI Quick Start</h2>
      <div class="card" style="max-width:700px; font-family:monospace; font-size:0.9rem; line-height:2;">
        <div style="color:var(--text-muted);"># Install the AVE toolkit</div>
        <div>pip install -e ave/</div>
        <br>
        <div style="color:var(--text-muted);"># Generate a card skeleton</div>
        <div>python -m ave submit --interactive</div>
        <br>
        <div style="color:var(--text-muted);"># Validate your card</div>
        <div>python -m ave validate ave-database/cards/AVE-DRAFT-0001.json</div>
        <br>
        <div style="color:var(--text-muted);"># View the leaderboard</div>
        <div>python -m ave leaderboard</div>
      </div>
    </div>
  </div>
</div>

{generate_footer()}
</body>
</html>"""


def main():
    """Generate the full documentation site."""
    print(f"\n{'═' * 60}")
    print(f"  Generating AVE Documentation Site")
    print(f"{'═' * 60}\n")

    # Clean output
    if SITE_DIR.exists():
        import shutil
        shutil.rmtree(SITE_DIR)
    SITE_DIR.mkdir(parents=True)
    (SITE_DIR / "cards").mkdir()

    # Load cards
    cards = load_cards()
    print(f"  Loaded {len(cards)} AVE cards")

    # Generate index page
    index_html = generate_index_page(cards)
    (SITE_DIR / "index.html").write_text(index_html)
    print(f"  ✓ index.html")

    # Generate taxonomy page
    taxonomy_html = generate_taxonomy_page(cards)
    (SITE_DIR / "taxonomy.html").write_text(taxonomy_html)
    print(f"  ✓ taxonomy.html")

    # Generate contribute page
    contribute_html = generate_contribute_page()
    (SITE_DIR / "contribute.html").write_text(contribute_html)
    print(f"  ✓ contribute.html")

    # Generate individual card pages
    for card in cards:
        ave_id = card.get("ave_id", "")
        card_html = generate_card_page(card)
        (SITE_DIR / "cards" / f"{ave_id}.html").write_text(card_html)
    print(f"  ✓ {len(cards)} card detail pages")

    # Copy static pages (CTF portal, etc.)
    static_dir = Path(__file__).parent / "static"
    if static_dir.is_dir():
        import shutil
        for static_file in static_dir.glob("*.html"):
            shutil.copy2(static_file, SITE_DIR / static_file.name)
            print(f"  ✓ {static_file.name} (static)")

    print(f"\n  ✅ Site generated at: {SITE_DIR}")
    print(f"  📁 {sum(1 for _ in SITE_DIR.rglob('*.html'))} HTML files")
    print(f"{'═' * 60}\n")


if __name__ == "__main__":
    main()
