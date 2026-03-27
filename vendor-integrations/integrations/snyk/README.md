# Snyk Integration for NAIL AVE Database

## Overview

Bridge agentic AI vulnerability intelligence from NAIL AVE into the developer
security workflow — surfacing AVE-relevant findings in Snyk's IDE plugins,
CI/CD gates, and dashboards alongside traditional dependency vulnerabilities.

## Architecture

```
NAIL AVE API ──► Snyk API / Snyk Apps Platform
                        │
              ┌─────────┼──────────────┐
              │         │              │
         ┌────▼────┐ ┌─▼──────────┐ ┌▼────────────┐
         │ Snyk    │ │ Snyk       │ │ Snyk IDE    │
         │ Web UI  │ │ CI/CD      │ │ Plugins     │
         └─────────┘ └────────────┘ └─────────────┘
```

## Why Snyk + NAIL AVE?

Snyk excels at finding vulnerabilities in **code dependencies** — libraries,
containers, IaC. NAIL AVE adds the **agentic AI layer**:

| Snyk Finds | NAIL AVE Adds |
|-----------|---------------|
| Vulnerable `langchain` package version | Prompt injection vulnerability in LangChain's agent pattern |
| Container image CVEs | Agent runtime configuration weaknesses |
| IaC misconfigurations | Agent permission policy violations |
| Open-source licence issues | MCP server supply chain risks |

Together, they give developers a complete view of their AI agent's security posture.

## Integration Methods

### Method 1: Snyk Apps Platform (Recommended)

Build a Snyk App that enriches Snyk projects with AVE data:

```python
"""NAIL AVE Snyk App — enriches Snyk projects with agentic AI intelligence."""

from flask import Flask, request, jsonify
from nail_ave_sdk import AVEClient

app = Flask(__name__)
nail_client = AVEClient()

@app.route("/webhook", methods=["POST"])
def handle_snyk_webhook():
    """Handle Snyk test completion webhook."""
    event = request.json
    
    if event["type"] != "project_snapshot/test":
        return jsonify({"status": "ignored"}), 200
    
    project = event["data"]["project"]
    dependencies = extract_ai_dependencies(project)
    
    # Cross-reference with NAIL AVE
    ave_findings = []
    for dep in dependencies:
        cards = nail_client.get_cards(
            search=dep["name"],
            severity=["critical", "high"]
        )
        for card in cards:
            ave_findings.append({
                "dependency": dep["name"],
                "version": dep["version"],
                "ave_id": card["ave_id"],
                "name": card["name"],
                "severity": card["severity"],
                "avss_score": card.get("avss_score", {}).get("base"),
                "defences": card.get("defences", []),
            })
    
    return jsonify({
        "status": "enriched",
        "ave_findings": ave_findings,
        "total": len(ave_findings),
    })

AI_PACKAGES = {
    "langchain", "langchain-core", "langchain-community",
    "crewai", "autogen", "llama-index", "llama-index-core",
    "openai", "anthropic", "transformers", "huggingface-hub",
    "chromadb", "pinecone-client", "weaviate-client",
    "mcp", "pydantic-ai",
}

def extract_ai_dependencies(project):
    """Extract AI/agent-related dependencies from a Snyk project."""
    deps = []
    for dep in project.get("dependencies", []):
        if dep["name"].lower() in AI_PACKAGES:
            deps.append(dep)
    return deps

if __name__ == "__main__":
    app.run(port=8090)
```

### Method 2: Snyk CLI + NAIL AVE CLI

Run both in your CI/CD pipeline for comprehensive coverage:

```yaml
# GitHub Actions workflow
name: Security Scan (Snyk + NAIL AVE)

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Standard Snyk scan
      - name: Snyk Test
        uses: snyk/actions/python@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
      
      # NAIL AVE agent security scan
      - name: Install NAIL AVE SDK
        run: pip install nail-ave-sdk
      
      - name: NAIL AVE Dependency Check
        run: |
          nail-ave check-deps \
            --requirements requirements.txt \
            --severity critical,high \
            --fail-on-match \
            --output sarif \
            > nail-ave-results.sarif
      
      # Upload results to GitHub Security tab
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: nail-ave-results.sarif
          category: nail-ave
```

### Method 3: Snyk API Custom Reporting

Enrich Snyk reporting with AVE data via the Snyk API:

```python
import requests
from nail_ave_sdk import AVEClient

SNYK_API = "https://api.snyk.io/rest"
SNYK_TOKEN = "YOUR_SNYK_TOKEN"
SNYK_ORG_ID = "YOUR_ORG_ID"

snyk_headers = {
    "Authorization": f"token {SNYK_TOKEN}",
    "Content-Type": "application/vnd.api+json",
}
nail_client = AVEClient()

def get_snyk_projects():
    """List all Snyk projects in the organisation."""
    resp = requests.get(
        f"{SNYK_API}/orgs/{SNYK_ORG_ID}/projects",
        headers=snyk_headers,
        params={"version": "2024-06-21"}
    )
    return resp.json().get("data", [])

def enrich_project_with_ave(project_id):
    """Add AVE findings to a Snyk project report."""
    # Get project dependencies
    issues = requests.get(
        f"{SNYK_API}/orgs/{SNYK_ORG_ID}/issues",
        headers=snyk_headers,
        params={
            "version": "2024-06-21",
            "scan_item.id": project_id,
            "scan_item.type": "project",
        }
    )
    
    # Extract AI-related packages
    ai_deps = set()
    for issue in issues.json().get("data", []):
        pkg_name = issue.get("attributes", {}).get("coordinates", [{}])[0].get("package", "")
        if pkg_name.lower() in AI_PACKAGES:
            ai_deps.add(pkg_name)
    
    # Cross-reference with NAIL AVE
    enrichment = {}
    for dep in ai_deps:
        cards = nail_client.get_cards(search=dep)
        if cards:
            enrichment[dep] = {
                "total_ave_cards": len(cards),
                "critical": len([c for c in cards if c["severity"] == "critical"]),
                "high": len([c for c in cards if c["severity"] == "high"]),
                "cards": [{"ave_id": c["ave_id"], "name": c["name"]} for c in cards[:5]],
            }
    
    return enrichment

# Generate combined report
for project in get_snyk_projects():
    enrichment = enrich_project_with_ave(project["id"])
    if enrichment:
        print(f"\n📦 Project: {project['attributes']['name']}")
        for dep, data in enrichment.items():
            print(f"  🤖 {dep}: {data['total_ave_cards']} AVE cards "
                  f"({data['critical']} critical, {data['high']} high)")
            for card in data["cards"]:
                print(f"     └─ {card['ave_id']}: {card['name']}")
```

## NAIL AVE CLI: check-deps Command

The `nail-ave` CLI includes a dependency checker for AI packages:

```bash
# Check requirements.txt against AVE database
nail-ave check-deps --requirements requirements.txt

# Output:
# ╔══════════════════════════════════════════════════════════╗
# ║ NAIL AVE Dependency Check                                ║
# ╠══════════════════════════════════════════════════════════╣
# ║ langchain==0.2.5                                         ║
# ║   ├── AVE-2025-0001 (CRITICAL) Prompt Injection          ║
# ║   ├── AVE-2025-0009 (HIGH) Tool Parameter Injection      ║
# ║   └── AVE-2025-0022 (HIGH) Tool-Mediated Injection       ║
# ║                                                           ║
# ║ crewai==0.28.0                                           ║
# ║   ├── AVE-2025-0012 (HIGH) Multi-Agent Trust Violation   ║
# ║   └── AVE-2025-0019 (HIGH) Delegation Privilege Esc.     ║
# ║                                                           ║
# ║ openai==1.30.0                                            ║
# ║   └── No matching AVE cards                               ║
# ╠══════════════════════════════════════════════════════════╣
# ║ Total: 5 findings (1 critical, 4 high)                   ║
# ║ Result: FAIL (critical findings present)                  ║
# ╚══════════════════════════════════════════════════════════╝

# Export as SARIF for IDE/GitHub integration
nail-ave check-deps --requirements requirements.txt --output sarif > results.sarif

# Fail CI if critical issues found
nail-ave check-deps --requirements requirements.txt --fail-on critical
```

## IDE Integration

Snyk's IDE plugins (VS Code, IntelliJ, PyCharm) display vulnerability
information inline. With the NAIL AVE enrichment:

```
# In your Python file:
from langchain.agents import create_react_agent  
#     ^^^^^^^^^^^^^^^^
#     ⚠️ Snyk: 2 known vulnerabilities in langchain@0.2.5
#     🤖 NAIL AVE: 3 agentic AI vulnerabilities
#        • AVE-2025-0001 (Critical): Prompt Injection via Indirect Context
#        • Click for defences →
```

## AI-SBOM Cross-Reference

Combine Snyk's dependency graph with the NAIL AI-SBOM:

```python
def generate_combined_sbom(snyk_project_id, nail_aibom):
    """Merge Snyk dependency data with NAIL AI-SBOM."""
    
    # Snyk provides: package names, versions, traditional CVEs
    snyk_deps = get_snyk_dependencies(snyk_project_id)
    
    # NAIL AIBOM provides: models, prompts, tools, RAG stores, AVE cards
    aibom = nail_aibom
    
    combined = {
        "sbom_version": "1.0",
        "packages": snyk_deps,             # Traditional dependencies
        "models": aibom.get("models", []),  # AI models
        "tools": aibom.get("tools", []),    # Agent tools / MCP servers
        "prompts": aibom.get("prompts", []),# System prompts
        "rag_stores": aibom.get("rag", []), # Knowledge bases
        "vulnerabilities": {
            "cve": get_snyk_vulns(snyk_project_id),  # Traditional CVEs
            "ave": get_nail_ave_vulns(aibom),          # Agentic AI AVEs
        }
    }
    return combined
```

## Requirements

- Snyk account (Free, Team, or Enterprise)
- Snyk API token
- Network access to `api.nailinstitute.org`
- Python 3.9+ (for integration scripts)
- Optional: Snyk CLI (`npm install -g snyk`)
- Optional: GitHub Actions or other CI/CD platform

## Support

- **Docs**: This README
- **Issues**: GitHub issues on `ave-database`
- **Slack**: `#vendor-integrations`
- **Email**: vendor-integrations@nailinstitute.org
