"""Typer CLI (`artex-hunt`) for multi-surface scanning, kill-chain correlation, evaluation, and local Gemma 4 triage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import typer
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.table import Table

from .detectors import correlate_kill_chains, scan_telemetry_file
from .eval_harness import run_evaluation
from .host_triage import run_host_triage
from .sanitizer import sanitize_payload, sanitize_text
from .simulator import generate_synthetic_suite
from .task_analyzer import analyze_task_artifacts
from .watchtower import run_watchtower
from .worker import GemmaWorker, GemmaWorkerError

app = typer.Typer(
    name="artex-hunt",
    help="Multi-surface defensive threat-hunting CLI combining DuckDB pre-filters with local Gemma 4.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def health(
    model: str | None = typer.Option(None, "--model", help="Override Ollama model name."),
    url: str | None = typer.Option(None, "--url", help="Override Ollama base URL."),
) -> None:
    """Check local Ollama reachability, installed models, and GPU VRAM residency."""
    worker = GemmaWorker(base_url=url, model=model)
    try:
        info = worker.health_check()
    except Exception as exc:
        console.print(f"[bold red]Health check failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print_json(data=info)
    if not info["model_installed"]:
        console.print(
            f"[yellow]Warning:[/yellow] Configured model '{info['configured_model']}' is not installed yet."
        )
        raise typer.Exit(code=2)


@app.command()
def scan(
    log_file: Path = typer.Argument(..., exists=True, readable=True, help="Log file (JSONL, ASA/FTD, Citrix, PAN-OS, F5, Zscaler, Nginx)."),
    fmt: str = typer.Option("auto", "--format", "-f", help="Log format (auto, jsonl, cisco_asa_ftd, citrix_netscaler, panos, f5_bigip, web_access)."),
    bucket_seconds: int = typer.Option(120, help="Aggregation bucket size in seconds."),
    sanitize: bool = typer.Option(
        False, "--sanitize", help="Redact secrets/emails, pseudonymize IPs, and defang domains in output."
    ),
    scanner_ip: list[str] | None = typer.Option(
        None, "--scanner-ip", help="Authorized scanner IP or CIDR to suppress generic burst cadence (repeatable)."
    ),
    out: Path | None = typer.Option(None, "--out", help="Write candidate windows JSON to file."),
) -> None:
    """Run Stage 1 deterministic DuckDB + Python behavioral and artifact pre-filters (0 LLM tokens)."""
    candidates = scan_telemetry_file(
        log_file, fmt=fmt, bucket_seconds=bucket_seconds, authorized_scanner_ips=scanner_ip
    )
    if not candidates:
        console.print("[green]No suspicious behavioral or artifact windows detected.[/green]")
        if out:
            out.write_text("[]\n", encoding="utf-8")
            console.print(f"Saved empty candidate list to [bold]{out}[/bold]")
        return

    payload = [c.model_dump(mode="json") for c in candidates]
    if sanitize:
        payload = sanitize_payload(payload)

    table = Table(title=f"Stage 1 Candidate Windows ({len(payload)})")
    table.add_column("Window ID", style="cyan")
    table.add_column("Risk / Tier")
    table.add_column("Surface / Appliance")
    table.add_column("Host / Actor")
    table.add_column("Events (EPM)", justify="right")
    table.add_column("Reasons", style="yellow")
    for item in payload:
        surf = f"{item['surface']} ({item['appliance']})" if item.get("appliance") else str(item["surface"])
        tier = str(item.get("alert_tier", "info"))
        tier_color = "bold red" if tier == "alert" else ("yellow" if tier == "hunt" else "dim")
        cadence = item.get("cadence", {})
        table.add_row(
            rich_escape(str(item.get("window_id", ""))),
            f"[{tier_color}]{item.get('risk_score', 0)} ({rich_escape(tier)})[/{tier_color}]",
            rich_escape(surf),
            f"{rich_escape(str(item.get('source_host', '')))} / {rich_escape(str(item.get('actor', '')))}",
            f"{cadence.get('event_count', 0)} ({cadence.get('events_per_minute', 0)}/m)",
            rich_escape(", ".join(str(r) for r in item.get("reasons", []))),
        )
    console.print(table)

    if out:
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"Saved candidate windows to [bold]{out}[/bold]")


@app.command()
def correlate(
    log_file: Path = typer.Argument(..., exists=True, readable=True, help="Multi-surface telemetry log file."),
    horizon_minutes: int = typer.Option(180, help="Max compressed kill-chain correlation window in minutes."),
    long_horizon_days: int = typer.Option(30, help="Max multi-week shared-IP dormant-gap correlation window in days."),
    sanitize: bool = typer.Option(False, "--sanitize", help="Sanitize/defang storyline output."),
) -> None:
    """Run Stage 1 detection plus compressed (<3h) and long-horizon (<=30d) kill-chain correlation."""
    candidates = scan_telemetry_file(log_file)
    storylines = correlate_kill_chains(
        candidates, horizon_minutes=horizon_minutes, long_horizon_days=long_horizon_days
    )
    payload = {
        "candidate_count": len(candidates),
        "storyline_count": len(storylines),
        "storylines": [s.model_dump(mode="json") for s in storylines],
    }
    if sanitize:
        payload["storylines"] = sanitize_payload(payload["storylines"])
    console.print_json(data=payload)


@app.command("sanitize")
def sanitize_file(
    input_file: Path = typer.Argument(..., exists=True, readable=True, help="File to sanitize/defang."),
    out: Path | None = typer.Option(None, "--out", help="Write sanitized output to file (defaults to stdout)."),
) -> None:
    """Deterministically redact secrets/emails, pseudonymize IPs, and defang URLs/domains."""
    cleaned = sanitize_text(input_file.read_text(encoding="utf-8"))
    if out:
        out.write_text(cleaned, encoding="utf-8")
        console.print(f"Saved sanitized output to [bold]{out}[/bold]")
    else:
        console.print(cleaned, markup=False)


@app.command()
def simulate(
    out_dir: Path = typer.Option(
        Path("data/synthetic"), "--out-dir", "-o", help="Directory to write benign synthetic telemetry fixtures."
    ),
    seed: int = typer.Option(42, help="Deterministic RNG seed."),
) -> None:
    """Generate 100% benign synthetic multi-surface baselines & agentic attack-pattern fixtures."""
    manifest = generate_synthetic_suite(out_dir, seed=seed)
    table = Table(title=f"Generated Synthetic Telemetry Suite ({len(manifest)} datasets)")
    table.add_column("Dataset", style="cyan")
    table.add_column("Format")
    table.add_column("Expected")
    table.add_column("Path")
    for name, meta in manifest.items():
        expected = "[red]ATTACK PATTERN[/red]" if meta["expected_positive"] else "[green]BENIGN BASELINE[/green]"
        table.add_row(name, meta["format"], expected, meta["path"])
    console.print(table)


@app.command("eval")
def evaluate(
    rules_dir: Path = typer.Option(
        Path("rules/sigma"), "--rules-dir", help="Sigma YAML rules directory to lint and validate."
    ),
    with_gemma4: bool = typer.Option(
        False, "--with-gemma4", help="Also run Stage 2 local Gemma 4 triage on detected scenarios."
    ),
    model: str | None = typer.Option(None, "--model", help="Override Ollama model name."),
    out: Path | None = typer.Option(None, "--out", help="Write evaluation report JSON to file."),
) -> None:
    """Run automated Precision/Recall validation harness across synthetic baselines & attack scenarios."""
    report = run_evaluation(rules_dir=rules_dir, with_gemma4=with_gemma4, model=model)
    m = report["metrics"]

    table = Table(
        title=(
            f"ARTEX Detection Evaluation — Precision: {m['precision']:.2%} | "
            f"Recall: {m['recall']:.2%} (TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']})"
        )
    )
    table.add_column("Dataset", style="cyan")
    table.add_column("Outcome")
    table.add_column("Windows", justify="right")
    table.add_column("KillChains", justify="right")
    table.add_column("Reasons / Verdict", style="yellow")
    for s in report["scenarios"]:
        color = "green" if s["outcome"] in {"TP", "TN"} else "red"
        extra = ", ".join(s["observed_reasons"]) or "none"
        if s["gemma4_verdict"]:
            gv = s["gemma4_verdict"]
            extra += f" | Gemma4: {gv['severity']}/{gv['likelihood_agentic']} ({gv['mitre_count']} ATT&CK)"
        table.add_row(
            s["dataset"],
            f"[{color}]{s['outcome']}[/{color}]",
            str(s["candidate_count"]),
            str(s["storyline_count"]),
            extra,
        )
    console.print(table)

    if report["sigma_rules"]:
        st = Table(title=f"Sigma Rule Pack Lint & Synthetic Match ({len(report['sigma_rules'])} rules)")
        st.add_column("Rule File", style="cyan")
        st.add_column("YAML Valid")
        st.add_column("Attack Hits", justify="right")
        st.add_column("Baseline FP Hits", justify="right")
        for r in report["sigma_rules"]:
            st.add_row(
                r["file"],
                "[green]OK[/green]" if r["valid"] else f"[red]{r['errors']}[/red]",
                str(r["synthetic_attack_hits"]),
                f"[green]{r['synthetic_baseline_fp_hits']}[/green]"
                if r["synthetic_baseline_fp_hits"] == 0
                else f"[red]{r['synthetic_baseline_fp_hits']}[/red]",
            )
        console.print(st)

    if out:
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        console.print(f"Saved evaluation report to [bold]{out}[/bold]")


@app.command("sigma-compile")
def sigma_compile(
    rules_dir: Path = typer.Option(
        Path("rules/sigma"), "--rules-dir", help="Directory containing Sigma YAML rules."
    ),
    export_dir: Path | None = typer.Option(
        None, "--export-dir", "-o", help="Optional directory to export compiled SIEM/XDR query packs."
    ),
) -> None:
    """Validate and compile all Sigma rules across Elastic, KQL/MDE/ASIM, CrowdStrike, Splunk, and SentinelOne."""
    try:
        from .sigma_compiler import compile_sigma_directory
    except ImportError as exc:
        console.print(
            "[bold red]pySigma extras not installed.[/bold red] Install with: "
            "`uv pip install '.[sigma]'`"
        )
        raise typer.Exit(code=1) from exc

    report = compile_sigma_directory(rules_dir, export_dir=export_dir)
    issues = report["schema_issues"]
    status_str = "[green]0 issues[/green]" if not issues else f"[red]{len(issues)} issues[/red]"
    console.print(
        f"pySigma Core Schema Check ({report['total_rules']} rules in {report['rules_dir']}): {status_str}"
    )
    for iss in issues:
        console.print(f"  [red]- {iss}[/red]")

    table = Table(title="Multi-Backend Sigma Compilation Matrix")
    table.add_column("Target Platform", style="cyan")
    table.add_column("Pipeline")
    table.add_column("Compiled", justify="right")
    table.add_column("Failed", justify="right")
    table.add_column("Exported Pack")
    for t in report["targets"]:
        ok_style = "green" if t["failed"] == 0 else "red"
        table.add_row(
            t["label"],
            t["pipeline"] or "default",
            f"[{ok_style}]{t['compiled']}/{t['applicable']}[/{ok_style}]",
            f"[{ok_style}]{t['failed']}[/{ok_style}]",
            t["exported_file"] or "-",
        )
    console.print(table)

    if not report["all_ok"]:
        for t in report["targets"]:
            for f in t["failures"]:
                console.print(f"[red]FAIL [{t['key']}] {f['file']}: {f['error']}[/red]")
        raise typer.Exit(code=1)


@app.command("host-triage")
def host_triage(
    root: Path = typer.Option(
        Path("/"), "--root", help="Filesystem root ('/' for live read-only scan, or mounted offline image path)."
    ),
    proc_root: Path | None = typer.Option(
        None, "--proc-root", help="Optional override for /proc directory (for offline triage captures)."
    ),
    scan_path: list[Path] | None = typer.Option(
        None, "--scan-path", "-s", help="Specific directories to scan (repeatable; defaults to /opt,/srv,/var/lib,/tmp)."
    ),
    pg_schema: Path | None = typer.Option(
        None, "--pg-schema", help="Optional read-only PostgreSQL table/schema dump file to check for ARTEX dual-graph tables."
    ),
    sanitize: bool = typer.Option(
        False, "--sanitize", help="Redact secrets/IPs/paths in JSON output before sharing."
    ),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write full triage JSON report to file."),
) -> None:
    """Run strictly read-only forensic checks for ARTEX operator/transit-host artifacts."""
    report = run_host_triage(
        fs_root=root,
        proc_root=proc_root,
        scan_paths=scan_path,
        pg_schema_file=pg_schema,
    )
    verdict_color = {
        "clean": "green",
        "suspicious": "yellow",
        "likely_artex_host": "bold red",
    }.get(report.verdict, "white")

    console.print(
        f"ARTEX Read-Only Host Triage ({report.mode} | {report.hostname}): "
        f"[{verdict_color}]{report.verdict.upper()}[/{verdict_color}] "
        f"({report.finding_count} findings; checks={', '.join(report.checks_run)})"
    )

    if report.findings:
        table = Table(title=f"Host Forensic Findings ({report.finding_count})")
        table.add_column("Severity")
        table.add_column("Check", style="cyan")
        table.add_column("Target / PID")
        table.add_column("Summary")
        table.add_column("Evidence", style="yellow")
        for f in report.findings:
            sc = "bold red" if f.severity == "critical" else ("red" if f.severity == "high" else "yellow")
            table.add_row(f"[{sc}]{f.severity}[/{sc}]", f.check, f.path_or_pid, f.summary, f.evidence)
        console.print(table)
    else:
        console.print("[green]No ARTEX operator-host or relay artifacts detected.[/green]")

    if out:
        payload = report.to_dict()
        if sanitize:
            payload = sanitize_payload(payload)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"Saved host triage report to [bold]{out}[/bold]")


@app.command()
def triage(
    log_file: Path = typer.Argument(..., exists=True, readable=True, help="Telemetry log file."),
    fmt: str = typer.Option("auto", "--format", "-f", help="Log format (auto-detected by default)."),
    max_windows: int = typer.Option(5, help="Maximum flagged windows to send to Gemma 4."),
    model: str | None = typer.Option(None, "--model", help="Override Ollama model name."),
    out: Path | None = typer.Option(None, "--out", help="Write full triage report JSON to file."),
) -> None:
    """Run Stage 1 pre-filter then dispatch flagged windows to local Gemma 4 for structured triage."""
    candidates = scan_telemetry_file(log_file, fmt=fmt)
    if not candidates:
        console.print("[green]No candidate windows flagged by Stage 1; skipping LLM triage.[/green]")
        return

    storylines = correlate_kill_chains(candidates)
    worker = GemmaWorker(model=model)
    selected = candidates[:max_windows]
    verdicts = []
    for window in selected:
        console.print(f"Triaging [cyan]{window.window_id}[/cyan] ({', '.join(window.reasons)})...")
        try:
            verdict = worker.triage_window(window)
        except GemmaWorkerError as exc:
            console.print(f"[bold red]Gemma 4 triage failed:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc
        verdicts.append(verdict.model_dump(mode="json"))

    report = {
        "source_file": str(log_file),
        "total_candidates": len(candidates),
        "storylines": [s.model_dump(mode="json") for s in storylines],
        "triaged_count": len(verdicts),
        "verdicts": verdicts,
    }
    console.print_json(data=report)
    if out:
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        console.print(f"Saved triage report to [bold]{out}[/bold]")


@app.command()
def intel(
    report_file: Path = typer.Argument(..., exists=True, readable=True, help="Local intel report."),
    model: str | None = typer.Option(None, "--model", help="Override Ollama model name."),
    out: Path | None = typer.Option(None, "--out", help="Write structured extraction JSON to file."),
) -> None:
    """Extract structured defensive IOCs, TTPs, and detection ideas from a local report via Gemma 4."""
    text = report_file.read_text(encoding="utf-8")
    worker = GemmaWorker(model=model)
    extraction = worker.extract_intel(text, source_name=report_file.name)
    data = extraction.model_dump(mode="json")
    console.print_json(data=data)
    if out:
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"Saved intel extraction to [bold]{out}[/bold]")


@app.command("analyze-tasks")
def analyze_tasks(
    target_path: Path = typer.Argument(
        ..., exists=True, help="Sanitized TaskID JSONL/log file or directory (from Tier 3 VM / intel export)."
    ),
    with_gemma4: bool = typer.Option(
        False, "--with-gemma4", help="Ask local Gemma 4 to propose detection ideas from retry chains."
    ),
    out: Path | None = typer.Option(None, "--out", help="Write sanitized analysis JSON to file."),
) -> None:
    """Analyze sanitized threat-actor TaskID/staging transcripts for tool usage & failure->retry chains."""
    summary = analyze_task_artifacts(target_path, sanitize=True)
    if with_gemma4 and summary["total_task_events"] > 0:
        worker = GemmaWorker()
        summary["gemma4_detection_notes"] = worker.delegate(
            "Review this sanitized TaskID staging summary and list 3-5 concrete behavioral Sigma/EDR "
            "detection ideas targeting the observed tool chains and failure->retry mutation patterns.",
            context=json.dumps(summary, indent=2),
        )
    console.print_json(data=summary)
    if out:
        out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        console.print(f"Saved TaskID analysis to [bold]{out}[/bold]")


@app.command("draft-rule")
def draft_rule(
    finding_file: Path = typer.Argument(..., exists=True, readable=True, help="Finding JSON file."),
    rule_format: Literal["sigma", "yara", "kql", "zeek"] = typer.Option(
        "sigma", "--format", "-f", help="Target defensive rule format."
    ),
    model: str | None = typer.Option(None, "--model", help="Override Ollama model name."),
    out: Path | None = typer.Option(None, "--out", help="Write drafted rule to file."),
) -> None:
    """Draft a defensive Sigma/YARA/KQL/Zeek rule from a JSON finding via local Gemma 4."""
    finding = json.loads(finding_file.read_text(encoding="utf-8"))
    worker = GemmaWorker(model=model)
    rule_text = worker.draft_rule(finding, rule_format=rule_format)
    console.print(rule_text)
    if out:
        out.write_text(rule_text + "\n", encoding="utf-8")
        console.print(f"Saved drafted rule to [bold]{out}[/bold]")


@app.command("watchtower")
def watchtower_cmd(
    state_dir: Path = typer.Option(
        Path("quarantine/watchtower"), "--state-dir", help="Directory for SQLite dedup state and Markdown digests."
    ),
    rules_dir: Path = typer.Option(
        Path("rules/sigma"), "--rules-dir", help="Sigma rules directory for coverage gap inventory."
    ),
    offline_feed: list[Path] | None = typer.Option(
        None, "--offline-feed", help="Optional local RSS/Atom XML file(s) to run strictly offline."
    ),
    with_gemma4: bool = typer.Option(
        False, "--with-gemma4", help="Wake local Ollama LLM worker for gap analysis ONLY when new relevant intel arrives."
    ),
    model: str | None = typer.Option(None, "--model", help="Override Ollama model name."),
) -> None:
    """Poll allowlisted public defensive feeds, deduplicate via SQLite, and emit a defanged intel digest."""
    report = run_watchtower(
        state_dir=state_dir,
        rules_dir=rules_dir,
        offline_feed_files=offline_feed,
        with_gemma4=with_gemma4,
        model=model,
    )
    console.print_json(data=report)


if __name__ == "__main__":
    app()
