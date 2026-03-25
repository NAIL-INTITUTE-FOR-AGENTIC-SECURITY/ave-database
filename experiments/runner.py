#!/usr/bin/env python3
"""
NAIL Community Experiments Runner
=================================
CLI tool for running, managing, and submitting AVE reproduction experiments.

Usage:
    python runner.py list                          # List available templates
    python runner.py run --template <name>         # Run an experiment
    python runner.py submit --experiment-id <id>   # Submit results
    python runner.py validate --template <name>    # Validate template
    python runner.py batch --difficulty beginner    # Batch run

Part of the NAIL Institute AVE Database
https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

console = Console()

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
CONFIG_DIR = BASE_DIR / "config"
RESULTS_DIR = BASE_DIR / "results"
SCHEMAS_DIR = BASE_DIR / "schemas"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_yaml(path: Path) -> dict:
    """Load a YAML file safely."""
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_defaults() -> dict:
    """Load default experiment configuration."""
    return load_yaml(CONFIG_DIR / "defaults.yaml")


def load_models() -> dict:
    """Load supported model configurations."""
    return load_yaml(CONFIG_DIR / "models.yaml")


def discover_templates() -> list[dict]:
    """Discover all experiment templates."""
    templates = []
    if not TEMPLATES_DIR.exists():
        return templates

    for category_dir in sorted(TEMPLATES_DIR.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("."):
            continue
        for template_dir in sorted(category_dir.iterdir()):
            if not template_dir.is_dir():
                continue
            manifest_path = template_dir / "experiment.yaml"
            if manifest_path.exists():
                manifest = load_yaml(manifest_path)
                manifest["_path"] = str(template_dir)
                manifest["_template_key"] = f"{category_dir.name}/{template_dir.name}"
                templates.append(manifest)
    return templates


def find_template(name: str) -> dict | None:
    """Find a template by name (category/template format)."""
    for t in discover_templates():
        if t.get("_template_key") == name:
            return t
    return None


def generate_experiment_id() -> str:
    """Generate a unique experiment ID."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    short_uuid = uuid.uuid4().hex[:6]
    return f"EXP-{ts}-{short_uuid}"


def estimate_cost(template: dict, models: list[str], repetitions: int) -> float:
    """Estimate experiment cost in USD."""
    model_configs = load_models().get("models", {})
    total = 0.0
    for model_name in models:
        cfg = model_configs.get(model_name, {})
        # Rough estimate: 2K input + 1K output tokens per trial
        input_cost = cfg.get("cost_per_1k_input", 0.01) * 2 * repetitions
        output_cost = cfg.get("cost_per_1k_output", 0.03) * 1 * repetitions
        total += input_cost + output_cost
    return round(total, 2)


# ---------------------------------------------------------------------------
# Experiment Execution Engine
# ---------------------------------------------------------------------------

class ExperimentRunner:
    """Core experiment execution engine."""

    def __init__(self, template: dict, model: str, repetitions: int,
                 temperature: float, output_dir: Path, dry_run: bool = False):
        self.template = template
        self.model = model
        self.repetitions = repetitions
        self.temperature = temperature
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.experiment_id = generate_experiment_id()
        self.results: list[dict] = []
        self.start_time: float | None = None
        self.end_time: float | None = None

    def validate(self) -> list[str]:
        """Validate experiment configuration. Returns list of issues."""
        issues = []
        model_configs = load_models().get("models", {})

        if self.model not in model_configs:
            issues.append(f"Unknown model: {self.model}")
        else:
            cfg = model_configs[self.model]
            api_key = os.environ.get(cfg.get("api_key_env", ""), "")
            if not api_key and not self.dry_run:
                issues.append(
                    f"Missing API key: set {cfg.get('api_key_env')} environment variable"
                )

        required_tools = self.template.get("requirements", {}).get("tools", [])
        if required_tools and not model_configs.get(self.model, {}).get("supports_tools"):
            issues.append(f"Model {self.model} does not support required tools: {required_tools}")

        safety = self.template.get("safety", {})
        max_cost = safety.get("max_cost", 50.0)
        est = estimate_cost(self.template, [self.model], self.repetitions)
        if est > max_cost:
            issues.append(
                f"Estimated cost ${est} exceeds safety limit ${max_cost}"
            )

        return issues

    def run(self) -> dict:
        """Execute the experiment."""
        self.start_time = time.time()

        console.print(Panel(
            f"[bold cyan]Experiment:[/] {self.template.get('name', 'Unknown')}\n"
            f"[bold]ID:[/] {self.experiment_id}\n"
            f"[bold]Model:[/] {self.model}\n"
            f"[bold]Repetitions:[/] {self.repetitions}\n"
            f"[bold]Temperature:[/] {self.temperature}",
            title="🧪 NAIL Experiment Runner",
            border_style="cyan"
        ))

        if self.dry_run:
            console.print("\n[yellow]DRY RUN — no API calls will be made[/]\n")

        # Validate
        issues = self.validate()
        if issues:
            for issue in issues:
                console.print(f"  [red]✗[/] {issue}")
            if not self.dry_run:
                console.print("\n[red]Experiment aborted due to validation errors.[/]")
                return {"status": "failed", "errors": issues}

        # Execute trials
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task(
                f"Running {self.repetitions} trials...",
                total=self.repetitions
            )

            for trial_num in range(self.repetitions):
                result = self._run_trial(trial_num)
                self.results.append(result)
                progress.update(task, advance=1)

        self.end_time = time.time()
        duration = self.end_time - self.start_time

        # Compile results
        report = self._compile_report(duration)

        # Save results
        self._save_results(report)

        # Display summary
        self._display_summary(report)

        return report

    def _run_trial(self, trial_num: int) -> dict:
        """Execute a single experimental trial."""
        if self.dry_run:
            # Simulate a trial
            import random
            random.seed(self.template.get("parameters", {}).get("seed", 42) + trial_num)
            success = random.random() < 0.45
            return {
                "trial": trial_num + 1,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "model": self.model,
                "attack_successful": success,
                "severity": "high" if success else "none",
                "tokens_used": {"input": random.randint(500, 2000),
                                "output": random.randint(200, 1000)},
                "latency_ms": random.randint(200, 3000),
                "notes": "Simulated trial (dry run)"
            }

        # Real trial execution would go here
        # For now, return placeholder indicating API integration needed
        return {
            "trial": trial_num + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model": self.model,
            "status": "requires_api_integration",
            "notes": "Configure API keys and implement model-specific adapters"
        }

    def _compile_report(self, duration: float) -> dict:
        """Compile trial results into a report."""
        successful = sum(1 for r in self.results if r.get("attack_successful", False))
        total = len(self.results)
        vuln_rate = successful / total if total > 0 else 0

        total_input = sum(r.get("tokens_used", {}).get("input", 0) for r in self.results)
        total_output = sum(r.get("tokens_used", {}).get("output", 0) for r in self.results)

        return {
            "experiment_id": self.experiment_id,
            "template": self.template.get("_template_key", "unknown"),
            "template_name": self.template.get("name", "Unknown"),
            "date": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(duration, 2),
            "dry_run": self.dry_run,
            "configuration": {
                "model": self.model,
                "repetitions": self.repetitions,
                "temperature": self.temperature,
                "seed": self.template.get("parameters", {}).get("seed", 42)
            },
            "environment": {
                "os": sys.platform,
                "python": sys.version.split()[0],
                "runner_version": "1.0.0"
            },
            "results": {
                "total_trials": total,
                "successful_attacks": successful,
                "failed_attacks": total - successful,
                "vulnerability_rate": round(vuln_rate, 4),
                "total_tokens": {"input": total_input, "output": total_output}
            },
            "target_aves": self.template.get("target_aves", []),
            "trials": self.results
        }

    def _save_results(self, report: dict) -> None:
        """Save experiment results to disk."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        out_file = self.output_dir / f"{self.experiment_id}.json"
        with open(out_file, "w") as f:
            json.dump(report, f, indent=2, default=str)
        console.print(f"\n[green]Results saved to:[/] {out_file}")

    def _display_summary(self, report: dict) -> None:
        """Display experiment summary."""
        r = report["results"]
        table = Table(title="Experiment Results", border_style="cyan")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Total Trials", str(r["total_trials"]))
        table.add_row("Successful Attacks", str(r["successful_attacks"]))
        table.add_row("Failed Attacks", str(r["failed_attacks"]))

        rate = r["vulnerability_rate"]
        rate_color = "red" if rate > 0.5 else "yellow" if rate > 0.2 else "green"
        table.add_row("Vulnerability Rate", f"[{rate_color}]{rate:.1%}[/{rate_color}]")

        table.add_row("Duration", f"{report['duration_seconds']:.1f}s")
        table.add_row("Target AVEs", ", ".join(report.get("target_aves", [])))

        console.print(table)

        threshold = self.template.get("criteria", {}).get("reproduction_threshold", 0.7)
        if rate >= threshold:
            console.print(f"\n[red bold]⚠ VULNERABILITY CONFIRMED[/] — rate {rate:.1%} ≥ threshold {threshold:.0%}")
        else:
            console.print(f"\n[green]✓ Below reproduction threshold[/] — rate {rate:.1%} < {threshold:.0%}")


# ---------------------------------------------------------------------------
# CLI Commands
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version="1.0.0", prog_name="NAIL Experiment Runner")
def cli():
    """🧪 NAIL Community Experiments Runner

    Run, manage, and submit AVE vulnerability reproduction experiments.
    """
    pass


@cli.command()
@click.option("--category", "-c", help="Filter by category")
@click.option("--difficulty", "-d", help="Filter by difficulty")
@click.option("--ave", help="Filter by AVE ID")
def list(category: str | None, difficulty: str | None, ave: str | None):
    """List available experiment templates."""
    templates = discover_templates()

    if not templates:
        console.print("[yellow]No experiment templates found.[/]")
        console.print("Templates should be in: experiments/templates/<category>/<name>/")
        console.print("See README.md for template authoring guide.")
        return

    if category:
        templates = [t for t in templates if t.get("category") == category]
    if difficulty:
        templates = [t for t in templates
                     if t.get("requirements", {}).get("difficulty", "").lower() == difficulty.lower()]
    if ave:
        templates = [t for t in templates if ave in t.get("target_aves", [])]

    table = Table(title="Available Experiment Templates", border_style="cyan")
    table.add_column("Template", style="bold")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Target AVEs")
    table.add_column("Version")

    for t in templates:
        table.add_row(
            t.get("_template_key", "?"),
            t.get("name", "?"),
            t.get("category", "?"),
            ", ".join(t.get("target_aves", [])[:3]),
            t.get("version", "?")
        )

    console.print(table)
    console.print(f"\n[dim]{len(templates)} template(s) found[/]")


@cli.command()
@click.option("--template", "-t", required=True, help="Template name (category/name)")
@click.option("--model", "-m", default="gpt-4o", help="Model to test against")
@click.option("--models", help="Comma-separated list of models for cross-model run")
@click.option("--all-models", is_flag=True, help="Run against all supported models")
@click.option("--repetitions", "-r", default=None, type=int, help="Number of trial repetitions")
@click.option("--temperature", default=None, type=float, help="Model temperature")
@click.option("--output", "-o", default=None, help="Output directory")
@click.option("--dry-run", is_flag=True, help="Validate and simulate without API calls")
def run(template: str, model: str, models: str | None, all_models: bool,
        repetitions: int | None, temperature: float | None,
        output: str | None, dry_run: bool):
    """Run an experiment template."""
    tmpl = find_template(template)

    if not tmpl:
        console.print(f"[red]Template not found:[/] {template}")
        console.print("Run 'python runner.py list' to see available templates.")
        sys.exit(1)

    defaults = load_defaults()
    reps = repetitions or tmpl.get("parameters", {}).get("repetitions",
                                                          defaults.get("experiment", {}).get("repetitions", 10))
    temp = temperature or tmpl.get("parameters", {}).get("temperature",
                                                          defaults.get("model", {}).get("temperature", 0.7))
    out_dir = Path(output) if output else RESULTS_DIR / template.replace("/", "_")

    # Determine models to run
    if all_models:
        model_list = list(load_models().get("models", {}).keys())
    elif models:
        model_list = [m.strip() for m in models.split(",")]
    else:
        model_list = [model]

    # Run for each model
    for m in model_list:
        runner = ExperimentRunner(
            template=tmpl,
            model=m,
            repetitions=reps,
            temperature=temp,
            output_dir=out_dir / m if len(model_list) > 1 else out_dir,
            dry_run=dry_run
        )
        runner.run()

        if len(model_list) > 1:
            console.print()  # Spacing between models


@cli.command()
@click.option("--difficulty", "-d", help="Run all templates of this difficulty")
@click.option("--ave", help="Run all templates targeting this AVE")
@click.option("--suite", help="Run a named suite (reproduction, discovery)")
@click.option("--model", "-m", default="gpt-4o", help="Model to test against")
@click.option("--dry-run", is_flag=True, help="Simulate without API calls")
def batch(difficulty: str | None, ave: str | None, suite: str | None,
          model: str, dry_run: bool):
    """Batch-run multiple experiment templates."""
    templates = discover_templates()

    if difficulty:
        templates = [t for t in templates
                     if t.get("requirements", {}).get("difficulty", "").lower() == difficulty.lower()]
    if ave:
        templates = [t for t in templates if ave in t.get("target_aves", [])]
    if suite == "reproduction":
        templates = [t for t in templates if "reproduction" in t.get("tags", [])]
    elif suite == "discovery":
        templates = [t for t in templates if "discovery" in t.get("tags", [])]

    if not templates:
        console.print("[yellow]No matching templates found.[/]")
        return

    console.print(f"[bold]Running {len(templates)} experiment(s)...[/]\n")

    for tmpl in templates:
        key = tmpl.get("_template_key", "unknown")
        console.print(f"[cyan]▸[/] {key}")
        reps = tmpl.get("parameters", {}).get("repetitions", 10)
        runner = ExperimentRunner(
            template=tmpl,
            model=model,
            repetitions=reps,
            temperature=tmpl.get("parameters", {}).get("temperature", 0.7),
            output_dir=RESULTS_DIR / key.replace("/", "_"),
            dry_run=dry_run
        )
        runner.run()
        console.print()


@cli.command()
@click.option("--experiment-id", "-e", required=True, help="Experiment ID")
@click.option("--results", "-r", required=True, help="Path to results directory or file")
@click.option("--author", "-a", required=True, help="Author name")
@click.option("--notes", "-n", default="", help="Additional notes")
def submit(experiment_id: str, results: str, author: str, notes: str):
    """Submit experiment results for community review."""
    results_path = Path(results)

    if not results_path.exists():
        console.print(f"[red]Results not found:[/] {results}")
        sys.exit(1)

    # Load result file(s)
    if results_path.is_file():
        with open(results_path) as f:
            data = json.load(f)
    else:
        # Combine all JSON files in directory
        data = []
        for json_file in sorted(results_path.glob("*.json")):
            with open(json_file) as f:
                data.append(json.load(f))

    submission = {
        "submission_id": f"SUB-{uuid.uuid4().hex[:8]}",
        "experiment_id": experiment_id,
        "author": author,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "notes": notes,
        "data": data,
        "status": "pending_review"
    }

    # Save submission
    submissions_dir = BASE_DIR / "submissions"
    submissions_dir.mkdir(exist_ok=True)
    sub_file = submissions_dir / f"{submission['submission_id']}.json"
    with open(sub_file, "w") as f:
        json.dump(submission, f, indent=2, default=str)

    console.print(Panel(
        f"[bold green]Submission created![/]\n\n"
        f"[bold]Submission ID:[/] {submission['submission_id']}\n"
        f"[bold]Experiment:[/] {experiment_id}\n"
        f"[bold]Author:[/] {author}\n"
        f"[bold]Status:[/] pending_review\n\n"
        f"[dim]To share with the community, submit a PR including:[/]\n"
        f"  {sub_file}",
        title="📤 Result Submission",
        border_style="green"
    ))


@cli.command()
@click.option("--template", "-t", required=True, help="Template name to validate")
def validate(template: str):
    """Validate an experiment template."""
    tmpl = find_template(template)
    if not tmpl:
        console.print(f"[red]Template not found:[/] {template}")
        sys.exit(1)

    issues = []
    required_fields = ["id", "name", "version", "description", "category", "target_aves"]
    for field in required_fields:
        if field not in tmpl:
            issues.append(f"Missing required field: {field}")

    if tmpl.get("target_aves") and not isinstance(tmpl["target_aves"], list):
        issues.append("target_aves must be a list")

    if tmpl.get("parameters"):
        params = tmpl["parameters"]
        if "repetitions" in params and not isinstance(params["repetitions"], int):
            issues.append("parameters.repetitions must be an integer")
        if "temperature" in params:
            temp = params["temperature"]
            if not isinstance(temp, (int, float)) or temp < 0 or temp > 2:
                issues.append("parameters.temperature must be between 0 and 2")

    if issues:
        console.print(f"[red]Validation failed for {template}:[/]")
        for issue in issues:
            console.print(f"  [red]✗[/] {issue}")
        sys.exit(1)
    else:
        console.print(f"[green]✓[/] Template [bold]{template}[/] is valid")
        console.print(f"  Name: {tmpl.get('name')}")
        console.print(f"  Version: {tmpl.get('version')}")
        console.print(f"  Category: {tmpl.get('category')}")
        console.print(f"  Target AVEs: {', '.join(tmpl.get('target_aves', []))}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
