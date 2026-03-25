# 🔬 Cross-Model Study Portal

> Interactive web interface for browsing and comparing AVE vulnerability data across AI models.

## Overview

The Cross-Model Study Portal provides a visual, data-driven interface for exploring how different AI models respond to the vulnerability classes documented in the AVE database. It enables researchers and security engineers to:

- **Compare** vulnerability susceptibility across models and providers
- **Visualise** category-level heatmaps and severity distributions
- **Filter** by model, category, severity, and time period
- **Export** comparison data for further analysis

## Live Demo

Open `index.html` in a browser — no server required. All data is embedded.

## Features

### 1. Model Comparison Matrix
Interactive heatmap showing which models are susceptible to which AVE categories.

### 2. Severity Distribution
Per-model breakdown of critical/high/medium/low vulnerability exposure.

### 3. Category Deep-Dive
Click any category to see per-model results, timelines, and defence effectiveness.

### 4. Defence Effectiveness Tracker
Visual comparison of how well defences perform across different models.

### 5. Export & API
- Download comparison data as CSV/JSON
- Link to NAIL API for live data

## Data Sources

- AVE Database (50 cards, 13 categories)
- Community experiment results
- Published research findings

## Technology

Pure HTML/CSS/JavaScript — zero dependencies, no build step, works offline.

---

*Part of the [NAIL Institute AVE Database](https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database)*
