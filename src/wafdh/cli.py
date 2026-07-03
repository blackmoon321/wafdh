from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Final

import anyio
import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.text import Text

from wafdh.agents import MainAgent, ScanProgressCallback
from wafdh.config import (
    CliScanOptions,
    build_config,
    count_submitted_targets,
    expand_targets,
    read_target_file,
    select_worker_count,
)
from wafdh.models import LlmProvider, ScanReport, Target, TargetReport
from wafdh.reporting import (
    ReportArtifacts,
    append_partial_target,
    create_report_artifacts,
    create_resume_report_artifacts,
    emit_incomplete_report_notice,
    emit_report,
    load_checkpoint_reports,
)
from wafdh.signatures import load_rules

ASCII_BANNER: Final = (
    "__        __    _ _____ ____  _   _\n"
    "\\ \\      / /_ _| |  ___|  _ \\| | | |\n"
    " \\ \\ /\\ / / _` | | |_  | | | | |_| |\n"
    "  \\ V  V / (_| | |  _| | |_| |  _  |\n"
    "   \\_/\\_/ \\__,_|_|_|   |____/|_| |_|\n"
    "        W A F   D E T E C T   H A E"
)

app = typer.Typer(no_args_is_help=True, add_completion=False)


@dataclass(frozen=True, slots=True)
class CliRun:
    targets: tuple[Target, ...]
    options: CliScanOptions
    artifacts: ReportArtifacts
    completed_reports: tuple[TargetReport, ...]


@app.callback(invoke_without_command=True)
def main(  # noqa: PLR0913
    ctx: typer.Context,
    url: Annotated[
        str | None, typer.Option("--url", "-u", help="Single target URL or hostname")
    ] = None,
    list_file: Annotated[
        Path | None, typer.Option("--list", "-l", help="File containing target URLs or hostnames")
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write summary CSV")] = None,
    resume: Annotated[
        Path | None,
        typer.Option(
            "--resume",
            help="Resume from a data/*.partial.jsonl checkpoint; use with the same -u/-l input.",
        ),
    ] = None,
    llm_provider: Annotated[
        LlmProvider,
        typer.Option(
            "--llm-provider",
            help="LLM engine for final WAF classification: codex or off.",
        ),
    ] = LlmProvider.CODEX,
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    raw_targets = (url,) if url is not None else ()
    if list_file is not None:
        raw_targets = (*raw_targets, *read_target_file(list_file))
    parsed_targets = expand_targets(raw_targets)
    if len(parsed_targets) == 0:
        _ = Console(stderr=True).print("No valid http/https targets were provided.")
        raise typer.Exit(code=2)
    worker_count = select_worker_count(count_submitted_targets(raw_targets), llm_provider)
    options = CliScanOptions(
        worker_count=worker_count,
        timeout_seconds=7.0,
        max_pages=4,
        max_payloads_per_target=12,
        llm_provider=llm_provider,
    )
    artifacts = (
        create_resume_report_artifacts(resume)
        if resume is not None
        else create_report_artifacts(parsed_targets)
    )
    try:
        completed_reports = load_checkpoint_reports(resume) if resume is not None else ()
        report = _run_scan_with_progress(
            CliRun(
                targets=parsed_targets,
                options=options,
                artifacts=artifacts,
                completed_reports=completed_reports,
            )
        )
        emit_report(report, output, artifacts)
    except Exception as exc:
        emit_incomplete_report_notice(artifacts, exc)
        raise typer.Exit(code=1) from exc


@app.command("list-rules")
def list_rules() -> None:
    table_console = Console()
    for rule in load_rules():
        _ = table_console.print(f"{rule.name} ({rule.manufacturer}) [{rule.confidence}]")


async def _scan_async(
    targets: tuple[Target, ...],
    options: CliScanOptions,
    progress_callback: ScanProgressCallback | None = None,
) -> ScanReport:
    return await MainAgent(build_config(options)).scan(targets, progress_callback)


def _run_scan_with_progress(
    run: CliRun,
) -> ScanReport:
    console = Console()
    _ = console.print(Text(ASCII_BANNER, style="bold cyan"))
    _ = console.print(Text("by blackmoon", style="bold white"))
    _ = console.print()
    completed_by_target = _reports_by_target(run.completed_reports)
    remaining_targets = tuple(
        target for target in run.targets if str(target.url) not in completed_by_target
    )
    completed_count = len(run.targets) - len(remaining_targets)
    scanned_reports: tuple[TargetReport, ...] = ()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task(
            "Scanning targets",
            total=len(run.targets),
            completed=completed_count,
        )

        def advance(report: TargetReport) -> None:
            append_partial_target(run.artifacts, report)
            progress.advance(task_id)

        if len(remaining_targets) > 0:
            scanned_reports = anyio.run(
                _scan_async, remaining_targets, run.options, advance
            ).targets
    return _merge_reports(run, scanned_reports)


def _reports_by_target(reports: tuple[TargetReport, ...]) -> dict[str, TargetReport]:
    reports_by_target: dict[str, TargetReport] = {}
    for report in reports:
        reports_by_target[report.target] = report
    return reports_by_target


def _merge_reports(run: CliRun, scanned_reports: tuple[TargetReport, ...]) -> ScanReport:
    reports_by_target = _reports_by_target(run.completed_reports)
    reports_by_target.update(_reports_by_target(scanned_reports))
    ordered_reports = tuple(
        reports_by_target[str(target.url)]
        for target in run.targets
        if str(target.url) in reports_by_target
    )
    return ScanReport(
        generated_at=datetime.now(tz=UTC).isoformat(),
        worker_count=run.options.worker_count,
        target_count=len(run.targets),
        targets=ordered_reports,
    )
