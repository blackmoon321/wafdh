from __future__ import annotations

from csv import writer
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from re import sub
from typing import Final

from rich.console import Console
from rich.table import Table

from wafdh.models import Detection, ScanReport, Target, TargetReport, WafStatus
from wafdh.verdicts import is_generic_detection, primary_detection

DEFAULT_DATA_DIR = Path("data")
CSV_COLUMNS: Final[tuple[str, ...]] = (
    "target",
    "status",
    "waf",
    "evidence",
    "llm",
    "final_url",
    "crawled",
)


@dataclass(frozen=True, slots=True)
class ReportArtifacts:
    json_path: Path
    checkpoint_path: Path


def create_report_artifacts(targets: tuple[Target, ...]) -> ReportArtifacts:
    json_path = _default_report_path_for_targets(targets)
    return ReportArtifacts(
        json_path=json_path,
        checkpoint_path=json_path.with_suffix(".partial.jsonl"),
    )


def create_resume_report_artifacts(checkpoint_path: Path) -> ReportArtifacts:
    return ReportArtifacts(
        json_path=_final_json_path_for_checkpoint(checkpoint_path),
        checkpoint_path=checkpoint_path,
    )


def load_checkpoint_reports(checkpoint_path: Path) -> tuple[TargetReport, ...]:
    reports: list[TargetReport] = []
    for line in checkpoint_path.read_text(encoding="utf-8").splitlines():
        if line.strip() == "":
            continue
        reports.append(TargetReport.model_validate_json(line))
    return tuple(reports)


def append_partial_target(artifacts: ReportArtifacts, target: TargetReport) -> None:
    artifacts.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    with artifacts.checkpoint_path.open("a", encoding="utf-8") as checkpoint_file:
        _ = checkpoint_file.write(target.model_dump_json())
        _ = checkpoint_file.write("\n")


def emit_report(
    report: ScanReport,
    csv_output: Path | None,
    artifacts: ReportArtifacts | None = None,
) -> None:
    json_path = artifacts.json_path if artifacts is not None else _default_report_path(report)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    _write_text_atomic(json_path, report.model_dump_json(indent=2))
    if csv_output is not None:
        _write_summary_csv(report, csv_output)
    if artifacts is not None:
        artifacts.checkpoint_path.unlink(missing_ok=True)
    console = Console()
    _ = console.print(_summary_table(report))
    _ = console.print(f"Detailed JSON: {json_path}")
    if csv_output is not None:
        _ = console.print(f"Summary CSV: {csv_output}")


def emit_incomplete_report_notice(artifacts: ReportArtifacts, error: Exception) -> None:
    console = Console(stderr=True)
    _ = console.print(f"Run stopped before output was finalized: {_error_summary(error)}")
    if artifacts.checkpoint_path.exists():
        _ = console.print(f"Completed target checkpoint JSONL: {artifacts.checkpoint_path}")
        return
    _ = console.print("No completed target checkpoint was written.")


def _error_summary(error: Exception) -> str:
    summaries = tuple(summary for summary in _leaf_error_summaries(error) if summary.strip())
    if len(summaries) == 1:
        return summaries[0]
    if len(summaries) > 1:
        return "; ".join(summaries)
    return f"{type(error).__name__}: {error}"


def _leaf_error_summaries(error: BaseException) -> tuple[str, ...]:
    match error:
        case BaseExceptionGroup(exceptions=exceptions):
            summaries: list[str] = []
            for nested in exceptions:
                summaries.extend(_leaf_error_summaries(nested))
            return tuple(summaries)
        case _:
            message = str(error)
            if message == "":
                return ()
            return (f"{type(error).__name__}: {message}",)


def _summary_table(report: ScanReport) -> Table:
    table = Table(title="WAF detection summary")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("WAF")
    table.add_column("Evidence")
    table.add_column("LLM")
    for target in report.targets:
        detections = identified_waf(target)
        reasons = identification_reason(target)
        table.add_row(
            str(target.target), target.waf_status, detections, reasons, summary_llm_status(target)
        )
    return table


def summary_waf_names(target: TargetReport) -> str:
    verdict = target.final_verdict
    if verdict is not None and verdict.detected and verdict.waf_name is not None:
        return verdict.waf_name
    specific = tuple(
        detection for detection in target.detections if not is_generic_detection(detection)
    )
    if len(specific) > 0:
        return _unique_detection_names(specific)
    return _unique_detection_names(target.detections)


def summary_evidence(target: TargetReport) -> str:
    return identification_reason(target)


def identified_waf(target: TargetReport) -> str:
    return summary_waf_names(target)


def identification_reason(target: TargetReport) -> str:
    if len(target.errors) > 0:
        return "; ".join(target.errors)
    verdict = target.final_verdict
    if verdict is not None:
        if verdict.detected and verdict.waf_name is not None:
            return f"{verdict.waf_name}: {verdict.rationale}"
        return verdict.rationale
    primary = primary_detection(target.detections)
    if primary is not None:
        return f"{primary.name}: {primary.reason}"
    if target.waf_status == WafStatus.NOT_DETECTED:
        return "No WAF signature or block response was observed."
    return "Insufficient probe evidence."


def summary_llm_status(target: TargetReport) -> str:
    verdict = target.llm_verdict
    if verdict is None:
        return "off"
    if verdict.rationale.startswith("Codex SDK failed:"):
        return f"{verdict.model} / error"
    if verdict.enabled:
        if verdict.reasoning_effort is None:
            return f"{verdict.model} / confidence {verdict.confidence}"
        return f"{verdict.model} / {verdict.reasoning_effort} / confidence {verdict.confidence}"
    return "skipped"


def _unique_detection_names(detections: tuple[Detection, ...]) -> str:
    seen: set[str] = set()
    names: list[str] = []
    for detection in detections:
        if detection.name in seen:
            continue
        seen.add(detection.name)
        names.append(detection.name)
    return ", ".join(names) or "-"


def _write_summary_csv(report: ScanReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8-sig", newline="") as output_file:
        csv_writer = writer(output_file)
        csv_writer.writerow(CSV_COLUMNS)
        for target in report.targets:
            csv_writer.writerow(
                (
                    target.target,
                    target.waf_status,
                    identified_waf(target),
                    identification_reason(target),
                    summary_llm_status(target),
                    target.final_url or "",
                    str(target.crawled).lower(),
                )
            )


def _write_text_atomic(path: Path, text: str) -> None:
    temp_path = path.with_name(f".{path.name}.tmp")
    _ = temp_path.write_text(text, encoding="utf-8")
    _ = temp_path.replace(path)


def _default_report_path_for_targets(targets: tuple[Target, ...]) -> Path:
    if len(targets) == 0:
        return _report_path("scan")
    return _report_path(_target_label(str(targets[0].url)))


def _default_report_path(report: ScanReport) -> Path:
    if len(report.targets) == 0:
        return _report_path("scan")
    return _report_path(_target_label(report.targets[0].target))


def _report_path(target_label: str) -> Path:
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_DATA_DIR / f"wafdh-{timestamp}-{target_label}.json"


def _final_json_path_for_checkpoint(checkpoint_path: Path) -> Path:
    name = checkpoint_path.name
    if name.endswith(".partial.jsonl"):
        return checkpoint_path.with_name(f"{name.removesuffix('.partial.jsonl')}.json")
    return checkpoint_path.with_suffix(".json")


def _target_label(value: str) -> str:
    return sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "scan"
